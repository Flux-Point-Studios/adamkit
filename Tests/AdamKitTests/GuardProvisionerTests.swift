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

@Suite struct GuardProvisionerTests {
    private func deployment(botId: String = "bot-1") -> GuardDeployment {
        GuardDeployment(
            provision: GuardProvision(
                unsignedCbor: "84a0a0f5f6", guardAddr: "addr_test1guard",
                deployTx: String(repeating: "d", count: 64), botId: botId,
                agentGasAddr: "addr_test1agentgas"
            ),
            bodyHashHex: "ab"
        )
    }

    /// Provision responses carry real deploy CBOR (a vector transaction), so
    /// the SDK-computed body hash is meaningful end to end.
    private func provisionJSON() throws -> (json: String, txHex: String, bodyHashHex: String) {
        let vectors = try ContractFiles.vector("tx-body.json", as: TxBodyVectors.self)
        let tx = vectors.cases[0]
        let json = """
            {"data":{"unsignedCbor":"\(tx.txHex)","guardAddr":"addr_test1guard",\
            "agentGasAddr":"addr_test1agentgas",\
            "deployTx":"\(String(repeating: "d", count: 64))","botId":"bot-1"}}
            """
        return (json, tx.txHex, tx.bodyHashHex)
    }

    @Test func deploymentComputesTheBodyHashFromTheServerCbor() async throws {
        let transport = StubHTTPTransport()
        let (json, txHex, bodyHashHex) = try provisionJSON()
        await transport.stub("POST", "/api/v1/guard/provision", status: 200, json: json)

        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        let deployment = try await provisioner.requestDeployment(principalAda: 50)
        #expect(deployment.provision.unsignedCbor == txHex)
        #expect(deployment.bodyHashHex == bodyHashHex)
        #expect(deployment.provision.guardAddr == "addr_test1guard")
        #expect(deployment.provision.agentGasAddr == "addr_test1agentgas")
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
        let deployment = try await provisioner.requestDeployment(principalAda: 50)
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
        let confirmation = try await provisioner.confirm(deployment(), attempts: 5)
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
            _ = try await provisioner.confirm(deployment(), attempts: 3)
        }
        #expect(await transport.requests().count == 3)
    }

    @Test func provisionSurfacesTheCapturedNoDbError() async throws {
        let transport = StubHTTPTransport()
        try await transport.stub(fixture: ContractFiles.fixture("guard-provision-no-db"))
        let provisioner = GuardProvisioner(
            api: try await makeAPI(transport), signer: FakeSigner(), sleep: { _ in })
        do {
            _ = try await provisioner.requestDeployment(principalAda: 100)
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
            _ = try await provisioner.confirm(deployment(), attempts: 5)
            Issue.record("expected NO_PENDING_GUARD to be final")
        } catch let AdamError.api(code, _, _) {
            #expect(code == "NO_PENDING_GUARD")
        }
        #expect(await transport.requests().count == 1)
    }
}
