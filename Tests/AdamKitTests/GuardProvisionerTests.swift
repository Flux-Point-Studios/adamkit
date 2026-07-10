import Foundation
import Testing

@testable import AdamKit

private let testConfig = AdamConfig(
    baseURL: URL(string: "https://gateway.test")!,
    network: .preprod
)

/// The owner login address whose payment key-hash equals the guard datum
/// vector's `owner` field, so `requestDeployment`'s owner-attestation passes.
private let ownerAddressBech32 =
    "addr_test1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5zsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6au4c9"

/// The agent gas address the deploy funds: a preprod enterprise address
/// (`0x60 || keyhash28`) whose payment key-hash equals the guard datum vector's
/// `agent` field (`00…0b0b`), so `requestDeployment`'s agent-binding passes.
private let agentGasAddrBech32 = "addr_test1vqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkzcaxme2u"

private func makeAPI(
    _ transport: StubHTTPTransport,
    walletAddress: String = ownerAddressBech32
) async throws -> AuthorizedClient {
    let store = InMemoryTokenStore()
    try await store.save(
        StoredTokens(
            accessToken: "live-token",
            refreshToken: "refresh",
            expiresAt: Date().addingTimeInterval(3600),
            walletAddress: walletAddress,
            deviceId: "dev"
        ))
    let client = AdamClient(config: testConfig, transport: transport)
    return AuthorizedClient(
        client: client,
        session: AdamSession(client: client, signer: FakeSigner(), tokenStore: store)
    )
}

/// A deploy tx that pays the bundled PREPROD guard address with a FRESH-DEPLOY
/// inline datum (empty spends) on the output that carries the STT (value key 1 =
/// `[coin, {sttPolicy: {sttName: 1}}]`) — the shape `requestDeployment` attests.
/// Consent matches it. Datum length prefix is `58ae` (174 bytes).
private let guardDeployTxHex =
    "84a300800182a300581d70ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc601"
    + "821a02faf080a1581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
    + "a15820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01"
    + "028201d81858ae"
    + "d8799f581c00000000000000000000000000000000000000000000000000000a0a"
    + "581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
    + "581c00000000000000000000000000000000000000000000000000000b0b"
    + "1a01312d001a02faf0801a05265c00"
    + "9fd8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1901f41903e8ffff"
    + "80"  // spends = [] (fresh deploy: no prior spend records)
    + "1a004c4b400a1b000001d1a94a2000d87980ff"
    + "a20058390000000000000000000000000000000000000000000000000000000a0a00000000000000000000000000000000000000000000000000000000011a00895440021a0002bf20a0f5f6"

/// The inline datum bytes carried by `guardDeployTxHex`.
private func guardDatumVectorBytes() throws -> Data {
    try Data(
        hexString:
            "d8799f581c00000000000000000000000000000000000000000000000000000a0a"
            + "581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
            + "581c00000000000000000000000000000000000000000000000000000b0b"
            + "1a01312d001a02faf0801a05265c00"
            + "9fd8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1901f41903e8ffff"
            + "9fd8799f40401b000000e8d4a5fa601a00989680ff"
            + "d8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1b000000e8d4a5fa6019012cffff"
            + "1a004c4b400a1b000001d1a94a2000d87980ff")
}

private func guardConsent() throws -> TokenCapConsent {
    TokenCapConsent(
        tokens: [
            .init(
                policy: try Data(hexString: "00000000000000000000000000000000000000000000000000001111"),
                name: try Data(hexString: "544b4e"),
                perTx: 500, daily: 1000)
        ],
        adaPerTx: 20_000_000, adaDaily: 50_000_000,
        windowLen: 86_400_000, minPrincipal: 5_000_000, maxSpends: 10, expiry: 2_000_000_000_000)
}

@Suite struct GuardProvisionerTests {
    private func deployment(botId: String = "bot-1") throws -> GuardDeployment {
        GuardDeployment(
            provision: GuardProvision(
                unsignedCbor: "84a0a0f5f6", guardAddr: "addr_test1guard",
                deployTx: String(repeating: "d", count: 64), botId: botId,
                agentGasAddr: agentGasAddrBech32
            ),
            bodyHashHex: "ab",
            attestedDatum: try GuardDatum.decode(from: try guardDatumVectorBytes())
        )
    }

    /// Provision responses carry the real guard deploy CBOR (pays the bundled
    /// guard address with the inline datum vector), so both the SDK-computed
    /// body hash AND the owner-consent attestation are meaningful end to end.
    private func provisionJSON() throws -> (json: String, txHex: String, bodyHashHex: String) {
        let txHex = guardDeployTxHex
        let bodyHashHex = try CardanoTx.bodyHash(try Data(hexString: txHex)).hexString
        let json = """
            {"data":{"unsignedCbor":"\(txHex)","guardAddr":"addr_test1guard",\
            "agentGasAddr":"\(agentGasAddrBech32)",\
            "deployTx":"\(String(repeating: "d", count: 64))","botId":"bot-1"}}
            """
        return (json, txHex, bodyHashHex)
    }

    @Test func deploymentComputesTheBodyHashFromTheServerCbor() async throws {
        let transport = StubHTTPTransport()
        let (json, txHex, bodyHashHex) = try provisionJSON()
        await transport.stub("POST", "/api/v1/guard/provision", status: 200, json: json)

        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        let deployment = try await provisioner.requestDeployment(
            principalAda: 50, consent: try guardConsent())
        #expect(deployment.provision.unsignedCbor == txHex)
        #expect(deployment.bodyHashHex == bodyHashHex)
        #expect(deployment.provision.guardAddr == "addr_test1guard")
        #expect(deployment.provision.agentGasAddr == agentGasAddrBech32)
        // The attested datum carries the on-chain caps, not server claims.
        #expect(deployment.attestedDatum.perTxCap == 20_000_000)
        #expect(deployment.consentSummary.tokenCaps.first?.perTx == 500)
    }

    @Test func requestDeploymentRejectsAGuardThatDoesNotMatchConsent() async throws {
        let transport = StubHTTPTransport()
        let (json, _, _) = try provisionJSON()
        await transport.stub("POST", "/api/v1/guard/provision", status: 200, json: json)

        let mismatched = TokenCapConsent(
            tokens: [], adaPerTx: 1, adaDaily: 1,
            windowLen: 1, minPrincipal: 1, maxSpends: 1, expiry: 1)
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        await #expect(throws: AdamError.self) {
            _ = try await provisioner.requestDeployment(principalAda: 50, consent: mismatched)
        }
    }

    @Test func signAndSubmitSendsTheDowngradedOwnerWitness() async throws {
        let transport = StubHTTPTransport()
        let (json, _, bodyHashHex) = try provisionJSON()
        await transport.stub("POST", "/api/v1/guard/provision", status: 200, json: json)
        await transport.stub(
            "POST", "/api/v1/guard/provision/submit", status: 200,
            json: #"{"data":{"deployTx":"feedbead"}}"#
        )

        let witnessVectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        let single = try #require(witnessVectors.cases.first { $0.expected.count == 1 })
        let signer = FakeSigner()
        await signer.setWitness(.witnessSet(cborHex: single.witnessSetHex))

        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: signer, sleep: { _ in })
        let deployment = try await provisioner.requestDeployment(
            principalAda: 50, consent: try guardConsent())
        let deployTx = try await provisioner.signAndSubmit(deployment)
        #expect(deployTx == "feedbead")

        // The host saw the exact CBOR and the SDK-computed hash.
        #expect(await signer.witnessedCborHexes == [deployment.provision.unsignedCbor])
        #expect(await signer.witnessedBodyHashes == [bodyHashHex])

        let submit = try #require(await transport.requests().last)
        let body = try #require(submit.bodyJSON())
        #expect(body["vkeyHex"] == .string(single.expected[0].vkeyHex))
        #expect(body["signatureHex"] == .string(single.expected[0].signatureHex))
        #expect(body["botId"] == .string("bot-1"))
    }

    @Test func confirmRetriesWhileGuardNotReady() async throws {
        let transport = StubHTTPTransport()
        let notReady = #"{"error":{"code":"GUARD_NOT_READY","message":"stt not found","requestId":"r"}}"#
        await transport.stub("POST", "/api/v1/guard/provision/confirm", status: 409, json: notReady)
        await transport.stub("POST", "/api/v1/guard/provision/confirm", status: 409, json: notReady)
        await transport.stub(
            "POST", "/api/v1/guard/provision/confirm", status: 200,
            json: #"{"data":{"active":true,"guardAddr":"addr_test1guard"}}"#
        )

        let slept = SleepRecorder()
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(),
            sleep: { await slept.record($0) })
        let confirmation = try await provisioner.confirm(try deployment(), attempts: 5)
        #expect(confirmation.active)
        #expect(await slept.count() == 2)
    }

    @Test func confirmGivesUpAfterAttempts() async throws {
        let transport = StubHTTPTransport()
        let notReady = #"{"error":{"code":"GUARD_NOT_READY","message":"unfunded","requestId":"r"}}"#
        for _ in 0..<3 {
            await transport.stub("POST", "/api/v1/guard/provision/confirm", status: 409, json: notReady)
        }
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })

        await #expect(throws: AdamError.self) {
            _ = try await provisioner.confirm(try deployment(), attempts: 3)
        }
        #expect(await transport.requests().count == 3)
    }

    @Test func provisionSurfacesTheCapturedNoDbError() async throws {
        let transport = StubHTTPTransport()
        try await transport.stub(fixture: ContractFiles.fixture("guard-provision-no-db"))
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        do {
            _ = try await provisioner.requestDeployment(principalAda: 100, consent: try guardConsent())
            Issue.record("expected DB_UNAVAILABLE")
        } catch let AdamError.api(code, _, statusCode) {
            #expect(code == "DB_UNAVAILABLE")
            #expect(statusCode == 503)
        }
    }

    @Test func statusDecodesTheGuardState() async throws {
        let transport = StubHTTPTransport()
        await transport.stub(
            "GET", "/api/v1/guard/status", status: 200,
            json: #"{"data":{"status":"active","guardAddr":"addr_test1guard","autonomousGuardMode":true,"sweepPending":false,"caps":{"perTxCapAda":20,"dailyCapAda":30,"minPrincipalAda":5,"maxSpends":10},"expiry":4000000000000,"botId":"bot-1"}}"#)
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        let status = try await provisioner.status()
        #expect(status.status == "active")
        #expect(status.guardAddr == "addr_test1guard")
        #expect(status.caps?.perTxCapAda == 20)
        #expect(status.caps?.maxSpends == 10)
    }

    @Test func sweepWitnessesTheServerCborAndSubmits() async throws {
        let vectors = try ContractFiles.vector("tx-body.json", as: TxBodyVectors.self)
        let tx = vectors.cases[0]
        let transport = StubHTTPTransport()
        await transport.stub(
            "POST", "/api/v1/guard/sweep", status: 200,
            json: """
                {"data":{"unsignedCbor":"\(tx.txHex)","guardAddr":"addr_test1guard","botId":"bot-1"}}
                """)
        await transport.stub(
            "POST", "/api/v1/guard/sweep/submit", status: 200,
            json: #"{"data":{"sweepTx":"sweep_tx_hash"}}"#)

        let witnessVectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        let single = try #require(witnessVectors.cases.first { $0.expected.count == 1 })
        let signer = FakeSigner()
        await signer.setWitness(.witnessSet(cborHex: single.witnessSetHex))

        let provisioner = GuardProvisioner(api: try await makeAPI(transport), signer: signer, sleep: { _ in })
        let sweep = try await provisioner.requestSweep()
        #expect(sweep.bodyHashHex == tx.bodyHashHex)
        #expect(sweep.guardAddr == "addr_test1guard")

        let sweepTx = try await provisioner.signAndSubmitSweep(sweep)
        #expect(sweepTx == "sweep_tx_hash")
        #expect(await signer.witnessedBodyHashes == [tx.bodyHashHex])
        let submit = try #require(await transport.requests().last?.bodyJSON())
        #expect(submit["vkeyHex"] == .string(single.expected[0].vkeyHex))
        #expect(submit["botId"] == .string("bot-1"))
    }

    @Test func confirmSurfacesFinalErrorsImmediately() async throws {
        let transport = StubHTTPTransport()
        await transport.stub(
            "POST", "/api/v1/guard/provision/confirm", status: 400,
            json: #"{"error":{"code":"NO_PENDING_GUARD","message":"provision first","requestId":"r"}}"#
        )
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })

        do {
            _ = try await provisioner.confirm(try deployment(), attempts: 5)
            Issue.record("expected NO_PENDING_GUARD to be final")
        } catch let AdamError.api(code, _, _) {
            #expect(code == "NO_PENDING_GUARD")
        }
        #expect(await transport.requests().count == 1)
    }
}
