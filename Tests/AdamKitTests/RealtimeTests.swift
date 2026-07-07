import Foundation
import Testing

@testable import AdamKit

private let testConfig = AdamConfig(
    baseURL: URL(string: "https://gateway.test")!,
    network: .preprod
)

private func liveSession() async throws -> AdamSession {
    let store = InMemoryTokenStore()
    try await store.save(
        StoredTokens(
            accessToken: "live-token",
            refreshToken: "refresh",
            expiresAt: Date().addingTimeInterval(3600),
            walletAddress: "addr_test1x",
            deviceId: "dev"
        ))
    return AdamSession(
        client: AdamClient(config: testConfig, transport: StubHTTPTransport()),
        signer: FakeSigner(),
        tokenStore: store
    )
}

/// The frames the live gateway actually sent, replayed from the captured
/// session — the decoder must understand every one of them.
@Suite struct WsFixtureDecodingTests {
    struct WsSessionFixture: Decodable {
        struct Entry: Decodable {
            let direction: String
            let frame: JSONValue
        }
        let frames: [Entry]
        let missingQueryToken: Rejection
        struct Rejection: Decodable {
            let code: Int
        }
    }

    @Test func decodesEveryCapturedDownFrame() throws {
        let url = ContractFiles.root.appendingPathComponent("fixtures/current/ws-session.json")
        let fixture = try JSONDecoder().decode(WsSessionFixture.self, from: Data(contentsOf: url))
        #expect(fixture.missingQueryToken.code == 4401)

        var seen: [String] = []
        for entry in fixture.frames where entry.direction == "down" {
            let text = String(decoding: try JSONEncoder().encode(entry.frame), as: UTF8.self)
            let event = AdamRealtime.decode(text)
            let decoded = try #require(event, "captured frame must decode")
            switch decoded {
            case .connected(_, let tier):
                #expect(tier == "premium")
                seen.append("connected")
            case .subscribed(let channel):
                seen.append("subscribed:\(channel)")
            case .unsubscribed(let channel):
                seen.append("unsubscribed:\(channel ?? "")")
            case .serverError(let code, _):
                seen.append("error:\(code)")
            default:
                seen.append("other")
            }
        }
        #expect(
            seen == [
                "connected",
                "subscribed:notifications",
                "subscribed:execution:bot-fixture",
                "unsubscribed:execution:bot-fixture",
                "error:UNKNOWN_MESSAGE_TYPE",
            ])
    }

    @Test func decodesSignRequiredPush() throws {
        let text = """
            {"channel":"notifications","event":"sign_required","data":{"requestId":"req-9",\
            "unsignedCborHex":"84a0a0f5f6","bodyHashHex":"ab","stepId":"s","action":"swap",\
            "protocol":"saturnswap","description":"d","rationale":"r","estimatedValueAda":5,\
            "estimatedFeeAda":0.2,"createdAt":1783400000000},"timestamp":"2026-07-07T00:00:00Z"}
            """
        guard case let .signRequired(push)? = AdamRealtime.decode(text) else {
            Issue.record("expected signRequired")
            return
        }
        #expect(push.requestId == "req-9")
        #expect(push.tradeProtocol == "saturnswap")
        #expect(push.createdAt == 1_783_400_000_000)
    }

    /// The captured pushes come from the real AgentBridge, so a gateway field
    /// rename fails the drift test AND this decode — the funds-critical payload
    /// shape is no longer pinned only by hand-written literals.
    @Test func decodesGatewayCapturedPushes() throws {
        struct PushFixture: Decodable {
            struct Entry: Decodable {
                let event: String
                let payload: JSONValue
            }
            let pushes: [Entry]
        }
        let url = ContractFiles.root.appendingPathComponent("fixtures/current/ws-pushes.json")
        let fixture = try JSONDecoder().decode(PushFixture.self, from: Data(contentsOf: url))

        for entry in fixture.pushes {
            let text = String(decoding: try JSONEncoder().encode(entry.payload), as: UTF8.self)
            let decoded = try #require(AdamRealtime.decode(text), "\(entry.event) must decode")
            switch entry.event {
            case "sign_required":
                guard case let .signRequired(push) = decoded else {
                    Issue.record("expected signRequired, got \(decoded)")
                    continue
                }
                #expect(!push.requestId.isEmpty)
                #expect(!push.unsignedCborHex.isEmpty)
                #expect(!push.bodyHashHex.isEmpty)
                #expect(push.tradeProtocol == "saturnswap")
            case "approval_required":
                guard case let .approvalRequired(push) = decoded else {
                    Issue.record("expected approvalRequired, got \(decoded)")
                    continue
                }
                #expect(!push.approval.planId.isEmpty)
                #expect(push.approval.status == "pending")
            default:
                Issue.record("unexpected push event \(entry.event)")
            }
        }
    }

    @Test func decodesApprovalRequiredPush() throws {
        let text = """
            {"channel":"notifications","event":"approval_required","data":{"id":"approval-p1",\
            "type":"approval","title":"Approval Needed","message":"m","timestamp":1783400000000,\
            "read":false,"approval":{"planId":"p1","rationale":"r","action":"swap",\
            "protocol":"saturnswap","estimatedValueAda":5,"estimatedFeeAda":0.2,\
            "status":"pending"}},"timestamp":"2026-07-07T00:00:00Z"}
            """
        guard case let .approvalRequired(push)? = AdamRealtime.decode(text) else {
            Issue.record("expected approvalRequired")
            return
        }
        #expect(push.approval.planId == "p1")
        #expect(push.approval.status == "pending")
    }

    @Test func heartbeatIsElided() {
        let text = #"{"type":"heartbeat","data":{"serverTime":"t","latency":null}}"#
        #expect(AdamRealtime.decode(text) == nil)
    }

    @Test func unknownFramesSurfaceAsUnhandled() {
        guard case .unhandled(let type)? = AdamRealtime.decode(#"{"type":"future-thing"}"#) else {
            Issue.record("expected unhandled")
            return
        }
        #expect(type == "future-thing")
    }
}

@Suite struct RealtimeActorTests {
    @Test func connectsWithBothCredentialsAndResubscribes() async throws {
        let transport = FakeWebSocketTransport()
        let connection = FakeWebSocketConnection()
        await transport.plan([.connection(connection)])

        let realtime = AdamRealtime(
            config: testConfig,
            session: try await liveSession(),
            transport: transport,
            sleep: { _ in }
        )
        _ = await realtime.start()

        // The SDK subscribes its default channel on connect.
        let first = await connection.nextSent()
        let frame = try JSONDecoder().decode(
            [String: JSONValue].self, from: Data((first ?? "{}").utf8))
        #expect(frame["type"] == .string("subscribe"))
        #expect(frame["channel"] == .string("notifications"))

        // Both credentials were presented.
        let url = try #require(await transport.url())
        #expect(url.absoluteString.contains("/ws/v1?token=live-token"))
        let headers = await transport.headers()
        #expect(headers["authorization"] == "Bearer live-token")

        await realtime.stop()
    }

    @Test func dropReconnectsWithBackoffAndEmitsLifecycleEvents() async throws {
        let transport = FakeWebSocketTransport()
        let first = FakeWebSocketConnection()
        let second = FakeWebSocketConnection()
        await transport.plan([.connection(first), .fail("boom"), .connection(second)])

        let slept = SleepRecorder()
        let realtime = AdamRealtime(
            config: testConfig,
            session: try await liveSession(),
            transport: transport,
            sleep: { await slept.record($0) }
        )
        let events = await realtime.start()

        _ = await first.nextSent()  // subscribe on first connection
        first.push(
            #"{"type":"connected","connectionId":"c1","userId":"u","tier":"premium","maxSubscriptions":50,"serverTime":"t"}"#
        )
        first.drop()

        // Complete the second connection's handshake whenever it comes up.
        let handshake = Task {
            _ = await second.nextSent()
            second.push(
                #"{"type":"connected","connectionId":"c2","userId":"u","tier":"premium","maxSubscriptions":50,"serverTime":"t"}"#
            )
        }

        var lifecycle: [String] = []
        for await event in events {
            switch event {
            case .connected: lifecycle.append("connected")
            case .disconnected: lifecycle.append("disconnected")
            case .reconnecting(let attempt): lifecycle.append("reconnecting-\(attempt)")
            default: continue
            }
            if lifecycle.filter({ $0 == "connected" }).count == 2 {
                break
            }
        }
        handshake.cancel()

        #expect(lifecycle.contains("connected"))
        #expect(lifecycle.contains("disconnected"))
        #expect(lifecycle.contains { $0.hasPrefix("reconnecting") })
        #expect(await transport.attempts() >= 2)
        #expect(await slept.count() >= 1)

        await realtime.stop()
    }
}

actor SleepRecorder {
    private var durations: [Duration] = []

    func record(_ duration: Duration) {
        durations.append(duration)
    }

    func count() -> Int { durations.count }
}
