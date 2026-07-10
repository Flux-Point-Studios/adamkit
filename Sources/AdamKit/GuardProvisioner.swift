import Foundation

/// A guard deploy the server built and the owner must witness. `bodyHashHex`
/// is computed by the SDK from the CBOR; `attestedDatum` is the on-chain guard
/// datum the SDK independently decoded, pinned to the universal guard address,
/// and verified against the owner's consent before this value ever exists — so
/// a non-consenting guard cannot be constructed, let alone witnessed.
public struct GuardDeployment: Sendable, Equatable {
    public let provision: GuardProvision
    public let bodyHashHex: String
    public let attestedDatum: GuardDatum

    /// The SDK-attested cap summary the host consent sheet should render.
    public var consentSummary: GuardConsentSummary { GuardConsentSummary(datum: attestedDatum) }
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

    /// Build the owner-signed deploy transaction for `principalAda` and attest
    /// it before returning. `consent` is the tradeable-token set + per-token/ADA
    /// caps the owner agreed to in the host consent sheet; it is forwarded in
    /// the provision request so the server builds the guard with exactly those
    /// caps, then attested against the returned deploy. After the body-hash
    /// check, the SDK pins the universal guard address, decodes the on-chain
    /// datum, and requires it to name the owner, the bundled STT policy, the
    /// agent bound to the deploy's funded gas address, and exactly the consented
    /// caps — throwing `AdamError.contract` on any mismatch so a non-consenting
    /// guard never reaches `signAndSubmit`.
    public func requestDeployment(
        principalAda: Double,
        consent: TokenCapConsent,
        botId: String? = nil
    ) async throws -> GuardDeployment {
        struct ProvisionBody: Encodable {
            struct Caps: Encodable {
                let perTxCapAda: Double
                let dailyCapAda: Double
                let windowLenMs: Int64
                let minPrincipalAda: Double
                let maxSpends: Int64
                let expiry: Int64
            }
            struct TokenCap: Encodable {
                let policy: String
                let name: String
                let perTx: String
                let daily: String
            }
            let principalAda: Double
            let botId: String?
            let caps: Caps
            let tokenCaps: [TokenCap]
        }
        // The request body is derived from the same consent `pinAndVerify`
        // attests below, so the caps sent and the caps verified cannot drift.
        // ADA caps cross the wire as decimal ADA, token quantities as strings
        // (lossless for any Int64), times as POSIX milliseconds.
        let provision: GuardProvision = try await api.post(
            "/api/v1/guard/provision",
            body: ProvisionBody(
                principalAda: principalAda,
                botId: botId,
                caps: .init(
                    perTxCapAda: Double(consent.adaPerTx) / 1_000_000,
                    dailyCapAda: Double(consent.adaDaily) / 1_000_000,
                    windowLenMs: consent.windowLen,
                    minPrincipalAda: Double(consent.minPrincipal) / 1_000_000,
                    maxSpends: consent.maxSpends,
                    expiry: consent.expiry
                ),
                tokenCaps: consent.tokens.map {
                    .init(
                        policy: $0.policy.hexString,
                        name: $0.name.hexString,
                        perTx: String($0.perTx),
                        daily: String($0.daily)
                    )
                }
            )
        )
        let tx = try Data(hexString: provision.unsignedCbor)
        let bodyHashHex = try CardanoTx.bodyHash(tx).hexString

        let ownerAddress = try await api.currentWalletAddress()
        let attestedDatum = try GuardAttestation.pinAndVerify(
            deployTx: tx,
            network: api.network,
            ownerAddress: ownerAddress,
            consent: consent,
            agentGasAddr: provision.agentGasAddr
        )
        return GuardDeployment(
            provision: provision, bodyHashHex: bodyHashHex, attestedDatum: attestedDatum)
    }

    /// Witness the deploy with the owner key and broadcast. Returns the
    /// deposit transaction hash.
    public func signAndSubmit(_ deployment: GuardDeployment) async throws -> String {
        let witness = try await signer.witnessTransaction(
            unsignedCborHex: deployment.provision.unsignedCbor,
            bodyHashHex: deployment.bodyHashHex,
            context: .guardDeploy(deployment.provision, consent: deployment.consentSummary)
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
                signatureHex: vkeyWitness.signatureHex
            )
        )
        return result.deployTx
    }

    /// Poll until the chain shows the guard live and the server flips
    /// autonomy on. Confirms the SAME bot the deployment provisioned —
    /// passing the deployment (not a bare optional) keeps multi-bot users from
    /// confirming the wrong bot. `GUARD_NOT_READY` means "not yet" and is
    /// retried; every other failure is final.
    public func confirm(
        _ deployment: GuardDeployment,
        attempts: Int = 30,
        pollInterval: Duration = .seconds(4)
    ) async throws -> GuardConfirmation {
        struct ConfirmBody: Encodable {
            let botId: String?
        }
        let body = ConfirmBody(botId: deployment.provision.botId)
        var lastNotReady: AdamError?
        for attempt in 0..<max(attempts, 1) {
            if attempt > 0 { try await sleep(pollInterval) }
            do {
                return try await api.post("/api/v1/guard/provision/confirm", body: body)
            } catch let error as AdamError {
                guard case .api("GUARD_NOT_READY", _, _) = error else { throw error }
                lastNotReady = error
            }
        }
        throw lastNotReady ?? AdamError.contract("guard confirm exhausted attempts without a response")
    }

    /// The persisted guard state (status, caps, expiry) for the current bot.
    public func status(botId: String? = nil) async throws -> GuardStatus {
        let query = botId.map { [("botId", $0)] } ?? []
        return try await api.get("/api/v1/guard/status", query: query)
    }

    /// Build the owner sweep tx — the unilateral withdraw-and-revoke. The body
    /// hash is computed from the server CBOR; the host must decode it and show
    /// the user that all funds return to their own address before signing.
    public func requestSweep(botId: String? = nil) async throws -> GuardSweep {
        struct SweepBody: Encodable {
            let botId: String?
        }
        let sweep: GuardSweepResponse = try await api.post(
            "/api/v1/guard/sweep",
            body: SweepBody(botId: botId)
        )
        let tx = try Data(hexString: sweep.unsignedCbor)
        let bodyHashHex = try CardanoTx.bodyHash(tx).hexString
        return GuardSweep(
            unsignedCbor: sweep.unsignedCbor,
            guardAddr: sweep.guardAddr,
            botId: sweep.botId,
            bodyHashHex: bodyHashHex
        )
    }

    /// Witness the sweep with the owner key and broadcast. Returns the sweep
    /// transaction hash; the guard is closed on-chain.
    public func signAndSubmitSweep(_ sweep: GuardSweep) async throws -> String {
        let witness = try await signer.witnessTransaction(
            unsignedCborHex: sweep.unsignedCbor,
            bodyHashHex: sweep.bodyHashHex,
            context: .guardSweep(sweep)
        )
        let vkeyWitness = try witness.vkeyWitness()

        struct SubmitBody: Encodable {
            let botId: String?
            let vkeyHex: String
            let signatureHex: String
        }
        let result: GuardSweepSubmitResult = try await api.post(
            "/api/v1/guard/sweep/submit",
            body: SubmitBody(
                botId: sweep.botId,
                vkeyHex: vkeyWitness.vkeyHex,
                signatureHex: vkeyWitness.signatureHex
            )
        )
        return result.sweepTx
    }
}
