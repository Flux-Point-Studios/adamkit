import Foundation

/// Lifecycle of one sign request inside the SDK.
public enum SignRequestState: Sendable, Equatable {
    /// Bind-to-bytes verified; safe to present to the user.
    case verified
    /// Witness submitted; the runtime re-verifies and broadcasts.
    case submitted(status: String)
    case declined
    /// Failed independent verification. Never presented, never signed.
    case invalid(reason: String)
}

/// The sign-request state machine. Every request is independently verified —
/// the body bytes are re-extracted from the CBOR and re-hashed — before it can
/// be presented or witnessed; a request whose server-claimed hash does not
/// match never reaches the host signer.
public actor SigningCoordinator {
    private let api: AuthorizedClient
    private let signer: any AdamHostSigner

    private var requests: [String: SignRequest] = [:]
    private var states: [String: SignRequestState] = [:]

    public init(api: AuthorizedClient, signer: any AdamHostSigner) {
        self.api = api
        self.signer = signer
    }

    /// Pull the authoritative pending list (REST is the delivery guarantee;
    /// call on connect, foreground, and `reconnected`). Returns the requests
    /// that passed verification, newly discovered ones included.
    @discardableResult
    public func reconcile() async throws -> [SignRequest] {
        let list: SignaturesList = try await api.get("/api/v1/agent/signatures")
        var verified: [SignRequest] = []
        for request in list.signatures {
            if ingest(request) == .verified {
                verified.append(request)
            }
        }
        // Requests the server no longer lists are resolved or expired.
        let live = Set(list.signatures.map(\.requestId))
        for requestId in requests.keys where !live.contains(requestId) {
            if states[requestId] == .verified {
                requests.removeValue(forKey: requestId)
                states.removeValue(forKey: requestId)
            }
        }
        return verified
    }

    /// Feed a realtime push. Returns the verified request when it is new and
    /// safe to present.
    public func handle(_ event: RealtimeEvent) -> SignRequest? {
        guard case .signRequired(let push) = event else { return nil }
        let request = SignRequest(
            requestId: push.requestId,
            unsignedCborHex: push.unsignedCborHex,
            bodyHashHex: push.bodyHashHex,
            stepId: push.stepId,
            action: push.action,
            tradeProtocol: push.tradeProtocol,
            description: push.description,
            rationale: push.rationale,
            estimatedValueAda: push.estimatedValueAda,
            estimatedFeeAda: push.estimatedFeeAda,
            createdAt: ISO8601DateFormatter().string(
                from: Date(timeIntervalSince1970: push.createdAt / 1000))
        )
        let isNew = requests[request.requestId] == nil
        return ingest(request) == .verified && isNew ? request : nil
    }

    /// Requests that passed verification and await a user decision.
    public var pending: [SignRequest] {
        requests.values.filter { states[$0.requestId] == .verified }
            .sorted { $0.requestId < $1.requestId }
    }

    public func state(of requestId: String) -> SignRequestState? {
        states[requestId]
    }

    /// Ask the host to witness, downgrade to the wire form, submit.
    public func approve(_ requestId: String) async throws -> SignRequestState {
        guard let request = requests[requestId], states[requestId] == .verified else {
            throw AdamError.contract("approve on unknown or non-verified request \(requestId)")
        }
        let witness = try await signer.witnessTransaction(
            unsignedCborHex: request.unsignedCborHex,
            bodyHashHex: request.bodyHashHex,
            context: .trade(request)
        )
        let vkeyWitness = try witness.vkeyWitness()

        struct SubmitBody: Encodable {
            let approved: Bool
            let vkeyHex: String
            let signatureHex: String
        }
        let status: DecisionStatus = try await api.post(
            "/api/v1/agent/signatures/\(requestId)",
            body: SubmitBody(
                approved: true,
                vkeyHex: vkeyWitness.vkeyHex,
                signatureHex: vkeyWitness.signatureHex
            )
        )
        let state = SignRequestState.submitted(status: status.status)
        states[requestId] = state
        return state
    }

    public func decline(_ requestId: String) async throws -> SignRequestState {
        struct DeclineBody: Encodable {
            let approved: Bool
        }
        let _: DecisionStatus = try await api.post(
            "/api/v1/agent/signatures/\(requestId)",
            body: DeclineBody(approved: false)
        )
        states[requestId] = .declined
        return .declined
    }

    private func ingest(_ request: SignRequest) -> SignRequestState {
        if let existing = states[request.requestId], existing != .verified {
            return existing
        }
        let state = Self.verify(request)
        requests[request.requestId] = request
        states[request.requestId] = state
        return state
    }

    /// Bind-to-bytes: recompute blake2b-256 over the exact body span and
    /// require it to equal the server's claim.
    static func verify(_ request: SignRequest) -> SignRequestState {
        do {
            let tx = try Data(hexString: request.unsignedCborHex)
            let computed = try CardanoTx.bodyHash(tx).hexString
            guard computed == request.bodyHashHex.lowercased() else {
                return .invalid(reason: "body hash mismatch: computed \(computed)")
            }
            return .verified
        } catch {
            return .invalid(reason: "unparseable transaction: \(error)")
        }
    }
}

/// Plan-level approvals (`approval_required`): decisions about intent, not
/// bytes — no signature involved.
public actor ApprovalCoordinator {
    private let api: AuthorizedClient

    public init(api: AuthorizedClient) {
        self.api = api
    }

    public func pending() async throws -> [PendingApproval] {
        let list: ApprovalsList = try await api.get("/api/v1/agent/approvals")
        return list.approvals
    }

    public func respond(planId: String, approved: Bool) async throws -> String {
        struct RespondBody: Encodable {
            let approved: Bool
        }
        let status: DecisionStatus = try await api.post(
            "/api/v1/agent/approvals/\(planId)",
            body: RespondBody(approved: approved)
        )
        return status.status
    }
}
