import Foundation

struct DataEnvelope<T: Decodable>: Decodable {
    let data: T
}

struct APIErrorBody: Decodable {
    let code: String
    let message: String
}

struct APIErrorEnvelope: Decodable {
    let error: APIErrorBody
}

/// Typed access to the gateway's `/api/v1` surface: envelope unwrapping,
/// error mapping, and the `x-adam-network` header on every call.
public struct AdamClient: Sendable {
    let config: AdamConfig
    let transport: any HTTPTransport

    public init(config: AdamConfig, transport: any HTTPTransport = URLSessionHTTPTransport()) {
        self.config = config
        self.transport = transport
    }

    func get<T: Decodable>(
        _ path: String,
        query: [(name: String, value: String)] = [],
        accessToken: String? = nil
    ) async throws -> T {
        try await send(method: "GET", path: path, query: query, body: nil as Never?, accessToken: accessToken)
    }

    func post<T: Decodable>(
        _ path: String,
        body: (some Encodable & Sendable)?,
        accessToken: String? = nil
    ) async throws -> T {
        try await send(method: "POST", path: path, query: [], body: body, accessToken: accessToken)
    }

    private func send<T: Decodable>(
        method: String,
        path: String,
        query: [(name: String, value: String)],
        body: (some Encodable & Sendable)?,
        accessToken: String?
    ) async throws -> T {
        var headers = [
            "accept": "application/json",
            "x-adam-network": config.network.rawValue,
        ]
        if let accessToken {
            headers["authorization"] = "Bearer \(accessToken)"
        }
        var encodedBody: Data?
        if let body {
            headers["content-type"] = "application/json"
            encodedBody = try JSONEncoder().encode(body)
        }

        let response = try await transport.send(
            HTTPRequest(method: method, path: path, query: query, headers: headers, body: encodedBody),
            baseURL: config.baseURL,
        )

        let decoder = JSONDecoder()
        guard (200..<300).contains(response.statusCode) else {
            if let envelope = try? decoder.decode(APIErrorEnvelope.self, from: response.body) {
                throw AdamError.api(
                    code: envelope.error.code,
                    message: envelope.error.message,
                    statusCode: response.statusCode,
                )
            }
            throw AdamError.contract("HTTP \(response.statusCode) without error envelope on \(path)")
        }
        do {
            return try decoder.decode(DataEnvelope<T>.self, from: response.body).data
        } catch {
            throw AdamError.contract("undecodable response on \(path): \(error)")
        }
    }
}

extension AdamError {
    var isAuthExpiry: Bool {
        if case .api(_, _, let statusCode) = self { return statusCode == 401 }
        return false
    }
}
