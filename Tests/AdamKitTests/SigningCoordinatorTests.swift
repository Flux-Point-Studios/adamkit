import Foundation
import Testing

@testable import AdamKit

private let testConfig = AdamConfig(
    baseURL: URL(string: "https://gateway.test")!,
    network: .preprod
)

private func makeAPI(_ transport: StubHTTPTransport) async throws -> AuthorizedClient {
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

/// A sign request whose CBOR and hash come from the cross-language vectors,
/// so "valid" means "valid the way the runtime computes it".
private func vectorSignRequest(
    requestId: String = "req-1",
    tamperHash: Bool = false,
    tamperCbor: Bool = false
) throws -> SignRequest {
    let vectors = try ContractFiles.vector("tx-body.json", as: TxBodyVectors.self)
    let tx = vectors.cases[0]
    var bodyHash = tx.bodyHashHex
    if tamperHash {
        bodyHash = String(bodyHash.dropLast(2)) + (bodyHash.hasSuffix("00") ? "01" : "00")
    }
    var cbor = tx.txHex
    if tamperCbor {
        // Flip a hex digit inside the body span: the claimed hash no longer
        // matches what the bytes commit to.
        let outerHeader = 2  // '84'
        let flipIndex = cbor.index(cbor.startIndex, offsetBy: outerHeader + 6)
        let original = cbor[flipIndex]
        let replacement: Character = original == "0" ? "1" : "0"
        cbor.replaceSubrange(flipIndex...flipIndex, with: String(replacement))
    }
    return SignRequest(
        requestId: requestId,
        unsignedCborHex: cbor,
        bodyHashHex: bodyHash,
        stepId: "step-1",
        action: "swap",
        tradeProtocol: "saturnswap",
        description: "Sell 50 ADA for SNEK",
        rationale: "vector-backed test request",
        estimatedValueAda: 50,
        estimatedFeeAda: 0.2,
        createdAt: "2026-07-07T00:00:00.000Z"
    )
}

private func signaturesListJSON(_ requests: [SignRequest]) throws -> String {
    struct Envelope: Encodable {
        struct List: Encodable {
            let runtimeConnected: Bool
            let signatures: [SignRequest]
        }
        let data: List
    }
    let data = try JSONEncoder().encode(
        Envelope(data: .init(runtimeConnected: true, signatures: requests)))
    return String(decoding: data, as: UTF8.self)
}

@Suite struct SigningCoordinatorTests {
    @Test func verifiedRequestCanBeApprovedWithAWitnessSet() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([request])
        )
        await transport.stub(
            "POST", "/api/v1/agent/signatures/req-1", status: 200,
            json: #"{"data":{"requestId":"req-1","status":"approved"}}"#
        )

        let witnessVectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        let single = try #require(witnessVectors.cases.first { $0.expected.count == 1 })
        let signer = FakeSigner()
        await signer.setWitness(.witnessSet(cborHex: single.witnessSetHex))

        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)
        let verified = try await coordinator.reconcile()
        #expect(verified.map(\.requestId) == ["req-1"])
        #expect(await coordinator.pending.count == 1)

        let state = try await coordinator.approve("req-1")
        #expect(state == .submitted(status: "approved"))

        // The wire form is the single vkey witness extracted from the set.
        let submit = try #require(await transport.requests().last)
        let json = try #require(submit.bodyJSON())
        #expect(json["approved"] == .bool(true))
        #expect(json["vkeyHex"] == .string(single.expected[0].vkeyHex))
        #expect(json["signatureHex"] == .string(single.expected[0].signatureHex))
    }

    @Test func tamperedHashNeverReachesTheSigner() async throws {
        let transport = StubHTTPTransport()
        let tampered = try vectorSignRequest(tamperHash: true)
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([tampered])
        )
        let signer = FakeSigner()
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)

        let verified = try await coordinator.reconcile()
        #expect(verified.isEmpty)
        #expect(await coordinator.pending.isEmpty)
        guard case .invalid = await coordinator.state(of: "req-1") else {
            Issue.record("tampered request must be invalid")
            return
        }

        await #expect(throws: AdamError.self) {
            _ = try await coordinator.approve("req-1")
        }
        #expect(await signer.witnessedCount() == 0)
    }

    @Test func tamperedBodyBytesNeverReachTheSigner() async throws {
        let transport = StubHTTPTransport()
        let tampered = try vectorSignRequest(tamperCbor: true)
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([tampered])
        )
        let signer = FakeSigner()
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)

        _ = try await coordinator.reconcile()
        #expect(await coordinator.pending.isEmpty)
        #expect(await signer.witnessedCount() == 0)
    }

    @Test func garbageCborIsInvalidNotFatal() async throws {
        let transport = StubHTTPTransport()
        var request = try vectorSignRequest()
        request = SignRequest(
            requestId: request.requestId,
            unsignedCborHex: "zz-not-hex",
            bodyHashHex: request.bodyHashHex,
            stepId: request.stepId,
            action: request.action,
            tradeProtocol: request.tradeProtocol,
            description: request.description,
            rationale: request.rationale,
            estimatedValueAda: request.estimatedValueAda,
            estimatedFeeAda: request.estimatedFeeAda,
            createdAt: request.createdAt
        )
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([request])
        )
        let coordinator = SigningCoordinator(
            api: try await makeAPI(transport), signer: FakeSigner())
        _ = try await coordinator.reconcile()
        guard case .invalid = await coordinator.state(of: "req-1") else {
            Issue.record("garbage CBOR must be invalid")
            return
        }
    }

    @Test func ambiguousWitnessSetIsRefused() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([request])
        )
        let witnessVectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        let double = try #require(witnessVectors.cases.first { $0.expected.count == 2 })
        let signer = FakeSigner()
        await signer.setWitness(.witnessSet(cborHex: double.witnessSetHex))
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)
        _ = try await coordinator.reconcile()

        await #expect(throws: AdamError.witnessCount(2)) {
            _ = try await coordinator.approve("req-1")
        }
        // Nothing was submitted to the gateway.
        let posts = await transport.requests().filter { $0.method == "POST" }
        #expect(posts.isEmpty)
    }

    @Test func declineSubmitsWithoutSigning() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([request])
        )
        await transport.stub(
            "POST", "/api/v1/agent/signatures/req-1", status: 200,
            json: #"{"data":{"requestId":"req-1","status":"declined"}}"#
        )
        let signer = FakeSigner()
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)
        _ = try await coordinator.reconcile()

        let state = try await coordinator.decline("req-1")
        #expect(state == .declined)
        #expect(await signer.witnessedCount() == 0)
        let json = try #require(await transport.requests().last?.bodyJSON())
        #expect(json["approved"] == .bool(false))
    }

    @Test func realtimePushVerifiesLikeRest() async throws {
        let coordinator = SigningCoordinator(
            api: try await makeAPI(StubHTTPTransport()), signer: FakeSigner())
        let request = try vectorSignRequest()

        let push = WsSignRequired(
            requestId: request.requestId,
            unsignedCborHex: request.unsignedCborHex,
            bodyHashHex: request.bodyHashHex,
            stepId: request.stepId,
            action: request.action,
            tradeProtocol: request.tradeProtocol,
            description: request.description,
            rationale: request.rationale,
            estimatedValueAda: request.estimatedValueAda,
            estimatedFeeAda: request.estimatedFeeAda,
            createdAt: 1_783_400_000_000
        )
        let surfaced = await coordinator.handle(.signRequired(push))
        #expect(surfaced?.requestId == request.requestId)
        // A duplicate push is not surfaced twice.
        #expect(await coordinator.handle(.signRequired(push)) == nil)

        // Tampered push: swallowed, never pending.
        let tampered = WsSignRequired(
            requestId: "req-2",
            unsignedCborHex: push.unsignedCborHex,
            bodyHashHex: String(push.bodyHashHex.dropLast(2)) + "ff",
            stepId: push.stepId,
            action: push.action,
            tradeProtocol: push.tradeProtocol,
            description: push.description,
            rationale: push.rationale,
            estimatedValueAda: push.estimatedValueAda,
            estimatedFeeAda: push.estimatedFeeAda,
            createdAt: 1_783_400_000_000
        )
        #expect(await coordinator.handle(.signRequired(tampered)) == nil)
        #expect(await coordinator.pending.map(\.requestId) == [request.requestId])
    }

    @Test func reconcileDropsRequestsTheServerResolved() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([request])
        )
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200,
            json: try signaturesListJSON([])
        )
        let coordinator = SigningCoordinator(
            api: try await makeAPI(transport), signer: FakeSigner())
        _ = try await coordinator.reconcile()
        #expect(await coordinator.pending.count == 1)
        _ = try await coordinator.reconcile()
        #expect(await coordinator.pending.isEmpty)
    }

    @Test func sameRequestIdWithDifferentBytesNeverOverwritesVerifiedBytes() async throws {
        // A second sign_required reusing a verified requestId but carrying
        // different (self-consistent) CBOR must not replace the reviewed bytes.
        let vectors = try ContractFiles.vector("tx-body.json", as: TxBodyVectors.self)
        let original = try vectorSignRequest()
        let swapped = SignRequest(
            requestId: original.requestId,
            unsignedCborHex: vectors.cases[1].txHex,
            bodyHashHex: vectors.cases[1].bodyHashHex,
            stepId: "s", action: "swap", tradeProtocol: "saturnswap",
            description: "attacker", rationale: "swap", estimatedValueAda: 1,
            estimatedFeeAda: 0.1, createdAt: "2026-07-07T00:00:00.000Z"
        )
        #expect(original.unsignedCborHex != swapped.unsignedCborHex)

        let transport = StubHTTPTransport()
        await transport.stub(
            "POST", "/api/v1/agent/signatures/req-1", status: 200,
            json: #"{"data":{"requestId":"req-1","status":"approved"}}"#)
        let signer = FakeSigner()
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)

        #expect(await coordinator.handle(swappedPush(original)) != nil)
        // The swap arrives after the user reviewed the first request.
        #expect(await coordinator.handle(swappedPush(swapped)) == nil)

        try await coordinator.approve("req-1")
        // The host witnessed the ORIGINAL bytes, not the swapped ones.
        #expect(await signer.witnessedCborHexes == [original.unsignedCborHex])
    }

    @Test func concurrentApproveWitnessesOnlyOnce() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200, json: try signaturesListJSON([request]))
        await transport.stub(
            "POST", "/api/v1/agent/signatures/req-1", status: 200,
            json: #"{"data":{"requestId":"req-1","status":"approved"}}"#)
        // A signer that suspends so both approve() calls overlap before either
        // resolves — the .signing guard must still admit exactly one.
        let signer = GatedSigner()
        let coordinator = SigningCoordinator(api: try await makeAPI(transport), signer: signer)
        _ = try await coordinator.reconcile()

        async let first = try? await coordinator.approve("req-1")
        async let second = try? await coordinator.approve("req-1")
        await signer.release()
        _ = await (first, second)

        #expect(await signer.witnessCount() == 1)
        // Exactly one submit POST reached the gateway.
        #expect(await transport.requests().filter { $0.method == "POST" }.count == 1)
    }

    @Test func reconcileEvictsResolvedRequestsRegardlessOfState() async throws {
        let transport = StubHTTPTransport()
        let request = try vectorSignRequest()
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200, json: try signaturesListJSON([request]))
        await transport.stub(
            "POST", "/api/v1/agent/signatures/req-1", status: 200,
            json: #"{"data":{"requestId":"req-1","status":"declined"}}"#)
        await transport.stub(
            "GET", "/api/v1/agent/signatures", status: 200, json: try signaturesListJSON([]))
        let coordinator = SigningCoordinator(
            api: try await makeAPI(transport), signer: FakeSigner())
        _ = try await coordinator.reconcile()
        _ = try await coordinator.decline("req-1")
        #expect(await coordinator.state(of: "req-1") == .declined)
        _ = try await coordinator.reconcile()
        // The declined (non-verified) entry is gone, not accumulated forever.
        #expect(await coordinator.state(of: "req-1") == nil)
    }
}

/// A signer whose witness call blocks until released — lets a test overlap two
/// concurrent approve() calls before either resolves.
actor GatedSigner: AdamHostSigner {
    private var gate: CheckedContinuation<Void, Never>?
    private var entryWaiter: CheckedContinuation<Void, Never>?
    private var entered = false
    private var witnessed = 0

    func signAuthChallenge(_ challenge: AuthChallenge, walletAddress: String) async throws -> AuthSignature {
        AuthSignature(signatureHex: "00", publicKeyHex: "00")
    }

    func witnessTransaction(
        unsignedCborHex: String, bodyHashHex: String, context: SigningContext
    ) async throws -> TransactionWitness {
        witnessed += 1
        entered = true
        entryWaiter?.resume()
        entryWaiter = nil
        await withCheckedContinuation { gate = $0 }
        return .vkey(vkeyHex: String(repeating: "a", count: 64), signatureHex: String(repeating: "b", count: 128))
    }

    /// Wait until a witness call has parked, then let it proceed.
    func release() async {
        if !entered {
            await withCheckedContinuation { entryWaiter = $0 }
        }
        gate?.resume()
        gate = nil
    }

    func witnessCount() -> Int { witnessed }
}

private func swappedPush(_ r: SignRequest) -> RealtimeEvent {
    .signRequired(
        WsSignRequired(
            requestId: r.requestId, unsignedCborHex: r.unsignedCborHex, bodyHashHex: r.bodyHashHex,
            stepId: r.stepId, action: r.action, tradeProtocol: r.tradeProtocol,
            description: r.description, rationale: r.rationale, estimatedValueAda: r.estimatedValueAda,
            estimatedFeeAda: r.estimatedFeeAda, createdAt: 1_783_400_000_000))
}
