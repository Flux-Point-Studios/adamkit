import Foundation

/// Everything the `/ws/v1` socket can tell the app. WS delivery is
/// best-effort by contract: `connected` and `reconnected` are the cues to
/// reconcile pending work over REST.
public enum RealtimeEvent: Sendable {
    case connected(connectionId: String, tier: String)
    case subscribed(channel: String)
    case unsubscribed(channel: String?)
    case signRequired(WsSignRequired)
    case approvalRequired(WsApprovalRequired)
    case serverError(code: String, message: String)
    case reconnecting(attempt: Int)
    case disconnected
    case unhandled(type: String)
}

private struct DownFrame: Decodable {
    let type: String?
    let id: String?
    let channel: String?
    let event: String?
    let connectionId: String?
    let tier: String?
    let data: JSONValue?
}

private struct UpFrame: Encodable {
    let type: String
    let id: String
    var channel: String?
    var data: [String: String]?
}

/// Owns the WebSocket: connect with both credentials (Authorization header
/// for the gateway's global JWT hook, `?token=` for the WS handler),
/// decode frames, resubscribe and back off across drops.
public actor AdamRealtime {
    private let config: AdamConfig
    private let session: AdamSession
    private let transport: any WebSocketTransport
    private let sleep: @Sendable (Duration) async throws -> Void

    private var desiredChannels: Set<String> = ["notifications"]
    private var connection: (any WebSocketConnection)?
    private var runner: Task<Void, Never>?
    private var nextMessageId = 0
    private var continuation: AsyncStream<RealtimeEvent>.Continuation?

    private static let maxBackoff = Duration.seconds(30)

    public init(
        config: AdamConfig,
        session: AdamSession,
        transport: any WebSocketTransport = URLSessionWebSocketTransport(),
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    ) {
        self.config = config
        self.session = session
        self.transport = transport
        self.sleep = sleep
    }

    /// Start (or restart) the socket. Events arrive on the returned stream;
    /// a fresh call replaces any previous stream.
    public func start() -> AsyncStream<RealtimeEvent> {
        runner?.cancel()
        let (stream, continuation) = AsyncStream.makeStream(of: RealtimeEvent.self)
        self.continuation = continuation
        runner = Task { await run() }
        return stream
    }

    public func stop() async {
        runner?.cancel()
        runner = nil
        await connection?.close()
        connection = nil
        continuation?.finish()
        continuation = nil
    }

    public func subscribe(to channel: String) async {
        desiredChannels.insert(channel)
        try? await sendFrame(type: "subscribe", channel: channel)
    }

    public func unsubscribe(from channel: String) async {
        desiredChannels.remove(channel)
        try? await sendFrame(type: "unsubscribe", channel: channel)
    }

    private func sendFrame(type: String, channel: String?) async throws {
        guard let connection else { throw AdamError.realtimeDisconnected }
        nextMessageId += 1
        let frame = UpFrame(type: type, id: "msg-\(nextMessageId)", channel: channel)
        let encoded = try JSONEncoder().encode(frame)
        try await connection.send(String(decoding: encoded, as: UTF8.self))
    }

    private func run() async {
        var attempt = 0
        while !Task.isCancelled {
            if attempt > 0 {
                continuation?.yield(.reconnecting(attempt: attempt))
                let backoff = min(Duration.seconds(1) * (1 << min(attempt - 1, 5)), Self.maxBackoff)
                guard (try? await sleep(backoff)) != nil else { break }
            }
            attempt += 1
            do {
                let token = try await session.validAccessToken()
                var components = URLComponents(url: config.wsURL, resolvingAgainstBaseURL: false)!
                components.path += "/ws/v1"
                components.queryItems = [URLQueryItem(name: "token", value: token)]
                let connection = try await transport.connect(
                    url: components.url!,
                    headers: ["authorization": "Bearer \(token)"],
                )
                self.connection = connection
                for channel in desiredChannels {
                    try await sendFrame(type: "subscribe", channel: channel)
                }
                for try await text in connection.incoming {
                    if Task.isCancelled { break }
                    if let event = Self.decode(text) {
                        continuation?.yield(event)
                        if case .connected = event { attempt = 0 }
                    }
                }
            } catch let error as AdamError where error == .notAuthenticated {
                break
            } catch {
                // fall through to backoff
            }
            connection = nil
            continuation?.yield(.disconnected)
        }
        continuation?.finish()
    }

    static func decode(_ text: String) -> RealtimeEvent? {
        guard let data = text.data(using: .utf8),
            let frame = try? JSONDecoder().decode(DownFrame.self, from: data)
        else {
            return .unhandled(type: "undecodable")
        }

        // Channel pushes carry `event`, control frames carry `type`.
        if let event = frame.event {
            switch event {
            case "sign_required":
                if let payload = decodePayload(WsSignRequired.self, frame.data) {
                    return .signRequired(payload)
                }
                return .unhandled(type: "sign_required")
            case "approval_required":
                if let payload = decodePayload(WsApprovalRequired.self, frame.data) {
                    return .approvalRequired(payload)
                }
                return .unhandled(type: "approval_required")
            default:
                return .unhandled(type: event)
            }
        }

        switch frame.type {
        case "connected":
            return .connected(connectionId: frame.connectionId ?? "", tier: frame.tier ?? "")
        case "subscribed":
            return .subscribed(channel: frame.channel ?? "")
        case "unsubscribed":
            return .unsubscribed(channel: frame.channel)
        case "heartbeat":
            return nil
        case "error":
            guard case let .object(fields) = frame.data,
                case let .string(code)? = fields["code"],
                case let .string(message)? = fields["message"]
            else {
                return .serverError(code: "UNKNOWN", message: "undecodable error frame")
            }
            return .serverError(code: code, message: message)
        case let type?:
            return .unhandled(type: type)
        case nil:
            return .unhandled(type: "missing-type")
        }
    }

    private static func decodePayload<T: Decodable>(_ type: T.Type, _ data: JSONValue?) -> T? {
        guard let data, let encoded = try? JSONEncoder().encode(data) else { return nil }
        return try? JSONDecoder().decode(type, from: encoded)
    }
}
