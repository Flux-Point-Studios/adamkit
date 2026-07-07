import Foundation

@testable import AdamKit

/// Scriptable HTTP transport: routes are matched by method + path (query
/// ignored) in registration order; the first match is consumed unless marked
/// `sticky`. Records every request for assertions.
actor StubHTTPTransport: HTTPTransport {
    struct Route {
        let method: String
        let path: String
        let response: HTTPResponse
        let sticky: Bool
    }

    struct RecordedRequest {
        let method: String
        let path: String
        let headers: [String: String]
        let body: Data?

        func bodyJSON() -> [String: JSONValue]? {
            guard let body,
                let value = try? JSONDecoder().decode(JSONValue.self, from: body),
                case let .object(fields) = value
            else { return nil }
            return fields
        }
    }

    private var routes: [Route] = []
    private(set) var recorded: [RecordedRequest] = []

    func stub(_ method: String, _ path: String, status: Int, json: String, sticky: Bool = false) {
        routes.append(
            Route(
                method: method,
                path: path,
                response: HTTPResponse(statusCode: status, body: Data(json.utf8)),
                sticky: sticky
            ))
    }

    /// Serve a captured endpoint fixture (its recorded response, verbatim).
    func stub(fixture: EndpointFixture, sticky: Bool = false) throws {
        let path = fixture.request.url.split(separator: "?")[0]
        let body = try JSONEncoder().encode(fixture.response.body)
        routes.append(
            Route(
                method: fixture.request.method,
                path: String(path),
                response: HTTPResponse(statusCode: fixture.response.statusCode, body: body),
                sticky: sticky
            ))
    }

    func requests() -> [RecordedRequest] { recorded }

    func send(_ request: HTTPRequest, baseURL: URL) async throws -> HTTPResponse {
        recorded.append(
            RecordedRequest(
                method: request.method,
                path: request.path,
                headers: request.headers,
                body: request.body
            ))
        guard
            let index = routes.firstIndex(where: {
                $0.method == request.method && $0.path == request.path
            })
        else {
            throw AdamError.transport("no stub for \(request.method) \(request.path)")
        }
        let route = routes[index]
        if !route.sticky { routes.remove(at: index) }
        return route.response
    }
}

/// Host signer double: returns a preconfigured witness and records calls so
/// tests can prove tampered requests never reach it.
actor FakeSigner: AdamHostSigner {
    var authSignature = AuthSignature(
        signatureHex: String(repeating: "0", count: 128),
        publicKeyHex: String(repeating: "0", count: 64)
    )
    var witness: TransactionWitness = .vkey(
        vkeyHex: String(repeating: "a", count: 64),
        signatureHex: String(repeating: "b", count: 128)
    )

    private(set) var signedChallenges: [AuthChallenge] = []
    private(set) var witnessedCborHexes: [String] = []
    private(set) var witnessedBodyHashes: [String] = []

    func setWitness(_ witness: TransactionWitness) {
        self.witness = witness
    }

    func signAuthChallenge(_ challenge: AuthChallenge, walletAddress: String) async throws -> AuthSignature {
        signedChallenges.append(challenge)
        return authSignature
    }

    func witnessTransaction(
        unsignedCborHex: String,
        bodyHashHex: String,
        context: SigningContext
    ) async throws -> TransactionWitness {
        witnessedCborHexes.append(unsignedCborHex)
        witnessedBodyHashes.append(bodyHashHex)
        return witness
    }

    func challengeCount() -> Int { signedChallenges.count }
    func witnessedCount() -> Int { witnessedCborHexes.count }
}

/// Scripted WebSocket transport. Each connect attempt consumes one script
/// entry: either a failure or a FakeWebSocketConnection.
actor FakeWebSocketTransport: WebSocketTransport {
    enum Attempt {
        case fail(String)
        case connection(FakeWebSocketConnection)
    }

    private var script: [Attempt] = []
    private(set) var connectCount = 0
    private(set) var lastURL: URL?
    private(set) var lastHeaders: [String: String] = [:]

    func plan(_ attempts: [Attempt]) {
        script = attempts
    }

    func connect(url: URL, headers: [String: String]) async throws -> any WebSocketConnection {
        connectCount += 1
        lastURL = url
        lastHeaders = headers
        guard !script.isEmpty else {
            throw AdamError.transport("no scripted connection left")
        }
        switch script.removeFirst() {
        case .fail(let reason):
            throw AdamError.transport(reason)
        case .connection(let connection):
            return connection
        }
    }

    func attempts() -> Int { connectCount }
    func headers() -> [String: String] { lastHeaders }
    func url() -> URL? { lastURL }
}

/// One fake socket: the test yields incoming frames and reads what the SDK
/// sent. Closing finishes the incoming stream (a "server drop").
final class FakeWebSocketConnection: WebSocketConnection, @unchecked Sendable {
    let incoming: AsyncThrowingStream<String, Error>
    private let incomingContinuation: AsyncThrowingStream<String, Error>.Continuation
    private let sentStream: AsyncStream<String>
    private let sentContinuation: AsyncStream<String>.Continuation
    private var sentIterator: AsyncStream<String>.Iterator

    init() {
        (incoming, incomingContinuation) = AsyncThrowingStream.makeStream(of: String.self)
        (sentStream, sentContinuation) = AsyncStream.makeStream(of: String.self)
        sentIterator = sentStream.makeAsyncIterator()
    }

    func push(_ frame: String) {
        incomingContinuation.yield(frame)
    }

    func drop() {
        incomingContinuation.finish(throwing: AdamError.transport("dropped"))
    }

    func finish() {
        incomingContinuation.finish()
    }

    /// Next frame the SDK sent (awaits until one arrives).
    func nextSent() async -> String? {
        await sentIterator.next()
    }

    func send(_ text: String) async throws {
        sentContinuation.yield(text)
    }

    func close() async {
        incomingContinuation.finish()
    }
}
