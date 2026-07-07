import Foundation
#if canImport(FoundationNetworking)
    // corelibs-foundation never annotated URLSession/URLSessionWebSocketTask
    // as Sendable; on Darwin they are.
    @preconcurrency import FoundationNetworking
#endif

public struct HTTPRequest: Sendable {
    public let method: String
    public let path: String
    public let query: [(name: String, value: String)]
    public let headers: [String: String]
    public let body: Data?

    public init(
        method: String,
        path: String,
        query: [(name: String, value: String)] = [],
        headers: [String: String] = [:],
        body: Data? = nil
    ) {
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponse: Sendable {
    public let statusCode: Int
    public let body: Data

    public init(statusCode: Int, body: Data) {
        self.statusCode = statusCode
        self.body = body
    }
}

/// The seam tests stub and production routes through URLSession.
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest, baseURL: URL) async throws -> HTTPResponse
}

public struct URLSessionHTTPTransport: HTTPTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func send(_ request: HTTPRequest, baseURL: URL) async throws -> HTTPResponse {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw AdamError.transport("invalid base URL \(baseURL)")
        }
        components.path += request.path
        if !request.query.isEmpty {
            components.queryItems = request.query.map { URLQueryItem(name: $0.name, value: $0.value) }
        }
        guard let url = components.url else {
            throw AdamError.transport("could not build URL for \(request.path)")
        }

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }

        let (data, response): (Data, URLResponse) = try await withCheckedThrowingContinuation { continuation in
            session.dataTask(with: urlRequest) { data, response, error in
                if let error {
                    continuation.resume(throwing: AdamError.transport(error.localizedDescription))
                } else if let data, let response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(throwing: AdamError.transport("empty response"))
                }
            }.resume()
        }

        guard let http = response as? HTTPURLResponse else {
            throw AdamError.transport("non-HTTP response")
        }
        return HTTPResponse(statusCode: http.statusCode, body: data)
    }
}

// MARK: - WebSocket

public protocol WebSocketConnection: Sendable {
    /// Incoming text frames; finishes (or throws) when the socket closes.
    var incoming: AsyncThrowingStream<String, Error> { get }
    func send(_ text: String) async throws
    func close() async
}

public protocol WebSocketTransport: Sendable {
    func connect(url: URL, headers: [String: String]) async throws -> any WebSocketConnection
}

public struct URLSessionWebSocketTransport: WebSocketTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func connect(url: URL, headers: [String: String]) async throws -> any WebSocketConnection {
        var request = URLRequest(url: url)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        let task = session.webSocketTask(with: request)
        task.resume()
        return URLSessionWebSocketConnection(task: task)
    }
}

struct URLSessionWebSocketConnection: WebSocketConnection {
    let task: URLSessionWebSocketTask

    var incoming: AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let receiveTask = Task {
                while !Task.isCancelled {
                    do {
                        let message = try await task.receive()
                        switch message {
                        case .string(let text):
                            continuation.yield(text)
                        case .data(let data):
                            if let text = String(data: data, encoding: .utf8) {
                                continuation.yield(text)
                            }
                        @unknown default:
                            break
                        }
                    } catch {
                        continuation.finish(throwing: error)
                        return
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in receiveTask.cancel() }
        }
    }

    func send(_ text: String) async throws {
        try await task.send(.string(text))
    }

    func close() async {
        task.cancel(with: .normalClosure, reason: nil)
    }
}
