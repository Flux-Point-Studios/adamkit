import Foundation

/// A guard deploy the server built and the owner must witness. `bodyHashHex`
/// is computed by the SDK from the CBOR — the host must decode the same bytes
/// and show the user the principal, script address, and datum before signing.
public struct GuardDeployment: Sendable, Equatable {
    public let provision: GuardProvision
    public let bodyHashHex: String
}

/// Drives per-user spending-guard provisioning: build → owner witness →
/// broadcast → on-chain confirm. The guard is the only delegation in the
/// system; the server-side session key it bounds is useless until the chain
/// proves the guard is live.
public actor GuardProvisioner {
    private let api: AuthorizedClient
    private let signer: any AdamHostSigner
    private let sleep: @Sendable (Duration) async throws -> Void

    public init(
        api: AuthorizedClient,
        signer: any AdamHostSigner,
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    ) {
        self.api = api
        self.signer = signer
        self.sleep = sleep
    }

    /// Build the owner-signed deploy transaction for `principalAda`.
    public func requestDeployment(principalAda: Double, botId: String? = nil) async throws -> GuardDeployment {
        struct ProvisionBody: Encodable {
            let principalAda: Double
            let botId: String?
        }
        let provision: GuardProvision = try await api.post(
            "/api/v1/guard/provision",
            body: ProvisionBody(principalAda: principalAda, botId: botId),
        )
        let tx = try Data(hexString: provision.unsignedCbor)
        let bodyHashHex = try CardanoTx.bodyHash(tx).hexString
        return GuardDeployment(provision: provision, bodyHashHex: bodyHashHex)
    }

    /// Witness the deploy with the owner key and broadcast. Returns the
    /// deposit transaction hash.
    public func signAndSubmit(_ deployment: GuardDeployment) async throws -> String {
        let witness = try await signer.witnessTransaction(
            unsignedCborHex: deployment.provision.unsignedCbor,
            bodyHashHex: deployment.bodyHashHex,
            context: .guardDeploy(deployment.provision),
        )
        let vkeyWitness = try witness.vkeyWitness()

        struct SubmitBody: Encodable {
            let botId: String?
            let vkeyHex: String
            let signatureHex: String
        }
        let result: GuardSubmitResult = try await api.post(
            "/api/v1/guard/provision/submit",
            body: SubmitBody(
                botId: deployment.provision.botId,
                vkeyHex: vkeyWitness.vkeyHex,
                signatureHex: vkeyWitness.signatureHex,
            ),
        )
        return result.deployTx
    }

    /// Poll until the chain shows the guard live and the server flips
    /// autonomy on. `GUARD_NOT_READY` means "not yet" and is retried; every
    /// other failure is final.
    public func confirm(
        botId: String? = nil,
        attempts: Int = 30,
        pollInterval: Duration = .seconds(4)
    ) async throws -> GuardConfirmation {
        struct ConfirmBody: Encodable {
            let botId: String?
        }
        var lastNotReady: AdamError?
        for attempt in 0..<max(attempts, 1) {
            if attempt > 0 { try await sleep(pollInterval) }
            do {
                return try await api.post("/api/v1/guard/provision/confirm", body: ConfirmBody(botId: botId))
            } catch let error as AdamError {
                guard case .api("GUARD_NOT_READY", _, _) = error else { throw error }
                lastNotReady = error
            }
        }
        throw lastNotReady ?? AdamError.contract("guard confirm exhausted attempts without a response")
    }
}
