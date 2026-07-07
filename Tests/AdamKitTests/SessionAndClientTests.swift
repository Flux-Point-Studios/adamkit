import Foundation
import Testing

@testable import AdamKit

private let testConfig = AdamConfig(
    baseURL: URL(string: "https://gateway.test")!,
    network: .preprod
)

private func makeSession(
    _ transport: StubHTTPTransport,
    signer: FakeSigner = FakeSigner(),
    store: InMemoryTokenStore = InMemoryTokenStore()
) -> AdamSession {
    AdamSession(
        client: AdamClient(config: testConfig, transport: transport),
        signer: signer,
        tokenStore: store
    )
}

@Suite struct SessionTests {
    @Test func loginFollowsTheCapturedChallengeResponseFlow() async throws {
        let transport = StubHTTPTransport()
        try await transport.stub(fixture: ContractFiles.fixture("auth-nonce"))
        try await transport.stub(fixture: ContractFiles.fixture("auth-login"))
        let signer = FakeSigner()
        let store = InMemoryTokenStore()
        let session = makeSession(transport, signer: signer, store: store)

        let fixture = try ContractFiles.fixture("auth-login")
        guard case let .object(body) = fixture.response.body,
            case let .object(data)? = body["data"],
            case let .object(fixtureUser)? = data["user"],
            case let .string(wallet)? = fixtureUser["walletAddress"]
        else {
            Issue.record("login fixture shape changed")
            return
        }

        let user = try await session.login(walletAddress: wallet, deviceId: "test-device")
        #expect(user.walletAddress == wallet)
        #expect(user.scopes.contains("bot:manage"))

        // The host signs exactly the text the server issued — here the
        // fixture's normalization sentinel, passed through verbatim.
        let challenges = await signer.signedChallenges
        #expect(challenges.count == 1)
        #expect(challenges[0].message == "<volatile>")

        // Tokens persisted for subsequent calls.
        let stored = try await store.load()
        #expect(stored?.accessToken == "<volatile>")
        #expect(stored?.walletAddress == wallet)

        // The login request carried the CIP-30 fields the contract requires.
        let loginRequest = try #require(await transport.requests().last)
        let json = try #require(loginRequest.bodyJSON())
        #expect(json["walletAddress"] == .string(wallet))
        #expect(json["chain"] == .string("cardano"))
        #expect(json["deviceId"] == .string("test-device"))
        #expect(loginRequest.headers["x-adam-network"] == "preprod")
    }

    @Test func validAccessTokenRefreshesWhenExpiring() async throws {
        let transport = StubHTTPTransport()
        await transport.stub(
            "POST", "/api/v1/auth/refresh", status: 200,
            json: #"{"data":{"accessToken":"fresh","refreshToken":"rotated","expiresIn":3600}}"#
        )
        let store = InMemoryTokenStore()
        try await store.save(
            StoredTokens(
                accessToken: "stale",
                refreshToken: "old-refresh",
                expiresAt: Date(),
                walletAddress: "addr_test1x",
                deviceId: "dev"
            ))
        let session = makeSession(transport, store: store)

        let token = try await session.validAccessToken()
        #expect(token == "fresh")
        let stored = try await store.load()
        #expect(stored?.refreshToken == "rotated")

        // Fresh token now short-circuits: no further HTTP.
        let again = try await session.validAccessToken()
        #expect(again == "fresh")
        #expect(await transport.requests().count == 1)
    }

    @Test func rejectedRefreshClearsTokens() async throws {
        let transport = StubHTTPTransport()
        await transport.stub(
            "POST", "/api/v1/auth/refresh", status: 401,
            json: #"{"error":{"code":"REFRESH_INVALID","message":"expired","requestId":"r"}}"#
        )
        let store = InMemoryTokenStore()
        try await store.save(
            StoredTokens(
                accessToken: "stale",
                refreshToken: "dead",
                expiresAt: Date(),
                walletAddress: "addr_test1x",
                deviceId: "dev"
            ))
        let session = makeSession(transport, store: store)

        await #expect(throws: AdamError.notAuthenticated) {
            _ = try await session.validAccessToken()
        }
        #expect(try await store.load() == nil)
    }

    @Test func noTokensMeansNotAuthenticated() async throws {
        let session = makeSession(StubHTTPTransport())
        await #expect(throws: AdamError.notAuthenticated) {
            _ = try await session.validAccessToken()
        }
    }
}

@Suite struct AuthorizedClientTests {
    private func authorizedPair(
        _ transport: StubHTTPTransport
    ) async throws -> AuthorizedClient {
        let store = InMemoryTokenStore()
        try await store.save(
            StoredTokens(
                accessToken: "live-token",
                refreshToken: "refresh",
                expiresAt: Date().addingTimeInterval(3600),
                walletAddress: "addr_test1x",
                deviceId: "dev"
            ))
        let client = AdamClient(config: testConfig, transport: transport)
        return AuthorizedClient(
            client: client,
            session: AdamSession(client: client, signer: FakeSigner(), tokenStore: store)
        )
    }

    @Test func retriesExactlyOnceAfter401() async throws {
        let transport = StubHTTPTransport()
        await transport.stub(
            "GET", "/api/v1/bot/status", status: 401,
            json: #"{"error":{"code":"AUTH_REQUIRED","message":"expired","requestId":"r"}}"#
        )
        await transport.stub(
            "POST", "/api/v1/auth/refresh", status: 200,
            json: #"{"data":{"accessToken":"fresh","refreshToken":"rotated","expiresIn":3600}}"#
        )
        await transport.stub(
            "GET", "/api/v1/bot/status", status: 200,
            json: #"{"data":{"status":"disarmed","runtimeConnected":false}}"#
        )
        let api = try await authorizedPair(transport)

        let status: BotStatus = try await api.get("/api/v1/bot/status")
        #expect(status.status == "disarmed")

        let requests = await transport.requests()
        #expect(requests.count == 3)
        #expect(requests[2].headers["authorization"] == "Bearer fresh")
    }

    @Test func decodesEveryCapturedReadFixture() async throws {
        let transport = StubHTTPTransport()
        for name in [
            "strategies", "bot-status", "agent-approvals-empty",
            "agent-signatures-empty", "agent-activity-empty",
        ] {
            try await transport.stub(fixture: ContractFiles.fixture(name), sticky: true)
        }
        let api = try await authorizedPair(transport)
        let bot = BotAPI(api: api)

        let strategies = try await bot.strategies()
        #expect(strategies.count >= 3)
        let conservative = try #require(strategies.first { $0.id == "conservative" })
        #expect(conservative.release.paper)
        #expect(conservative.constraints.maxPositions != nil)

        let status = try await bot.status()
        #expect(status.status == "armed" || status.status == "disarmed")

        #expect(try await bot.activity().isEmpty)
        #expect(try await ApprovalCoordinator(api: api).pending().isEmpty)
    }

    @Test func armAndDisarmMatchCapturedFixtures() async throws {
        let transport = StubHTTPTransport()
        try await transport.stub(fixture: ContractFiles.fixture("bot-arm"))
        try await transport.stub(fixture: ContractFiles.fixture("bot-disarm"))
        let api = try await authorizedPair(transport)
        let bot = BotAPI(api: api)

        let armed = try await bot.arm()
        #expect(armed.status == "armed")
        let disarmed = try await bot.disarm()
        #expect(disarmed.status == "disarmed")
        #expect(disarmed.runtimeConnected == false)
    }

    @Test func gatewayErrorEnvelopeBecomesTypedError() async throws {
        let transport = StubHTTPTransport()
        try await transport.stub(fixture: ContractFiles.fixture("agent-signature-post-unknown"))
        let api = try await authorizedPair(transport)

        struct AnyBody: Encodable {
            let approved = true
            let vkeyHex = "00"
            let signatureHex = "00"
        }
        do {
            let _: DecisionStatus = try await api.post(
                "/api/v1/agent/signatures/req-fixture-missing", body: AnyBody())
            Issue.record("expected error")
        } catch let AdamError.api(code, _, statusCode) {
            #expect(code == "RUNTIME_UNAVAILABLE")
            #expect(statusCode == 503)
        }
    }
}
