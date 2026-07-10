import Foundation

/// Arbitrary JSON — used where the gateway sends open-ended objects
/// (activity event payloads, forward-compatible fields).
public indirect enum JSONValue: Sendable, Codable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "not JSON")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

// MARK: - Auth

public struct AuthChallenge: Sendable, Codable, Equatable {
    public let nonce: String
    /// The exact text the wallet must sign (CIP-30 `signData` payload).
    public let message: String
    public let expiresIn: Int
}

public struct AdamUser: Sendable, Codable, Equatable {
    public let id: String
    public let walletAddress: String
    public let chain: String
    public let tier: String
    public let scopes: [String]
    public let createdAt: String
}

struct LoginResult: Codable {
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
    let tokenType: String
    let user: AdamUser
}

struct RefreshResult: Codable {
    let accessToken: String
    let refreshToken: String
    let expiresIn: Int
}

public struct StoredTokens: Sendable, Codable, Equatable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresAt: Date
    public let walletAddress: String
    public let deviceId: String

    public init(
        accessToken: String,
        refreshToken: String,
        expiresAt: Date,
        walletAddress: String,
        deviceId: String
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.walletAddress = walletAddress
        self.deviceId = deviceId
    }
}

// MARK: - Agent signing / approvals

/// A transaction the runtime built and is waiting on the wallet to witness
/// (REST form; `createdAt` is ISO-8601).
public struct SignRequest: Sendable, Codable, Equatable {
    public let requestId: String
    public let unsignedCborHex: String
    public let bodyHashHex: String
    public let stepId: String
    public let action: String
    public let tradeProtocol: String
    public let description: String
    public let rationale: String
    public let estimatedValueAda: Double
    public let estimatedFeeAda: Double
    public let createdAt: String

    enum CodingKeys: String, CodingKey {
        case requestId, unsignedCborHex, bodyHashHex, stepId, action
        case tradeProtocol = "protocol"
        case description, rationale, estimatedValueAda, estimatedFeeAda, createdAt
    }
}

public struct PendingApproval: Sendable, Codable, Equatable {
    public let planId: String
    public let stepId: String
    public let action: String
    public let tradeProtocol: String
    public let description: String
    public let rationale: String
    public let estimatedValueAda: Double
    public let estimatedFeeAda: Double
    public let createdAt: String

    enum CodingKeys: String, CodingKey {
        case planId, stepId, action
        case tradeProtocol = "protocol"
        case description, rationale, estimatedValueAda, estimatedFeeAda, createdAt
    }
}

struct SignaturesList: Codable {
    let runtimeConnected: Bool
    let signatures: [SignRequest]
}

struct ApprovalsList: Codable {
    let runtimeConnected: Bool
    let approvals: [PendingApproval]
}

/// Server acknowledgement of a signature or approval decision.
public struct DecisionStatus: Sendable, Codable, Equatable {
    public let status: String
}

// MARK: - Bot

public struct BotStatus: Sendable, Codable, Equatable {
    public let status: String
    public let runtimeConnected: Bool
}

public struct ArmResult: Sendable, Codable, Equatable {
    public let botId: String?
    public let status: String
    public let runtimeConnected: Bool
}

public struct ActivityEvent: Sendable, Codable, Equatable {
    public let id: String
    public let eventType: String
    public let tickId: String?
    public let data: JSONValue
    public let createdAt: String?
}

struct ActivityList: Codable {
    let events: [ActivityEvent]
}

// MARK: - Strategies

public struct StrategyRelease: Sendable, Codable, Equatable {
    public let paper: Bool
    public let live: String
}

public struct StrategyConstraintsSummary: Sendable, Codable, Equatable {
    public let maxPositions: Int?
    public let maxTokenExposurePct: Double?
    public let maxSlippageBps: Double?
    public let dailyLossLimitPct: Double?
    public let cycleIntervalSeconds: Double?
    public let minNativeReservePct: Double?
}

public struct Strategy: Sendable, Codable, Equatable {
    public let id: String
    public let label: String
    public let description: String
    public let riskTier: String
    public let protocols: [String]
    public let release: StrategyRelease
    public let constraints: StrategyConstraintsSummary
}

struct StrategiesList: Codable {
    let strategies: [Strategy]
}

// MARK: - Guard

/// The provision response: an owner-signed deploy transaction to witness.
public struct GuardProvision: Sendable, Codable, Equatable {
    public let unsignedCbor: String
    public let guardAddr: String
    public let deployTx: String
    public let botId: String
    /// The agent gas wallet address the deploy tx seeds (a deterministic function
    /// of the session key). A consent-decoding host allows exactly
    /// `{guardAddr, agentGasAddr}` as the deposit's non-change outputs. Optional
    /// for backward compatibility with gateways that don't yet supply it.
    public let agentGasAddr: String?
}

struct GuardSubmitResult: Codable {
    let deployTx: String
}

public struct GuardConfirmation: Sendable, Codable, Equatable {
    public let active: Bool
    public let guardAddr: String
}

public struct GuardCaps: Sendable, Codable, Equatable {
    public let perTxCapAda: Double
    public let dailyCapAda: Double
    public let minPrincipalAda: Double
    public let maxSpends: Double
}

/// The persisted guard's state. `status` is `none`, `pending`, or `active`.
public struct GuardStatus: Sendable, Codable, Equatable {
    public let status: String
    public let guardAddr: String?
    public let autonomousGuardMode: Bool?
    public let sweepPending: Bool?
    public let caps: GuardCaps?
    public let expiry: Double?
    public let botId: String?
}

/// An owner sweep the server built and the owner must witness to withdraw all
/// guard funds and permanently close the guard.
public struct GuardSweep: Sendable, Equatable {
    public let unsignedCbor: String
    public let guardAddr: String
    public let botId: String
    public let bodyHashHex: String
}

struct GuardSweepResponse: Codable {
    let unsignedCbor: String
    let guardAddr: String
    let botId: String
}

struct GuardSweepSubmitResult: Codable {
    let sweepTx: String
}

// MARK: - Guard datum (on-chain attestation)

/// A per-token spending cap declared in the guard datum. ADA uses the EMPTY
/// bytestring for both `policy` and `name` (CBOR `0x40`).
public struct AssetCap: Sendable, Equatable {
    public let policy: Data
    public let name: Data
    public let perTx: Int64
    public let daily: Int64

    public init(policy: Data, name: Data, perTx: Int64, daily: Int64) {
        self.policy = policy
        self.name = name
        self.perTx = perTx
        self.daily = daily
    }
}

/// One recorded spend in the guard's rolling window. ADA uses the EMPTY
/// bytestring for both `policy` and `name`.
public struct SpendRecord: Sendable, Equatable {
    public let policy: Data
    public let name: Data
    public let at: Int64
    public let amount: Int64

    public init(policy: Data, name: Data, at: Int64, amount: Int64) {
        self.policy = policy
        self.name = name
        self.at = at
        self.amount = amount
    }
}

/// The on-chain guard datum, decoded field-for-field from the deploy tx's
/// inline datum. This is the ground truth the guard validator enforces; the
/// SDK decodes it independently so a non-consenting guard never reaches the
/// owner's signature. Field order matches the frozen 12-field Constr-0 layout.
public struct GuardDatum: Sendable, Equatable {
    public let ownerVkh: Data
    public let sttPolicy: Data
    public let agentVkh: Data
    public let perTxCap: Int64
    public let dailyCap: Int64
    public let windowLen: Int64
    public let tokenCaps: [AssetCap]
    public let spends: [SpendRecord]
    public let minPrincipal: Int64
    public let maxSpends: Int64
    public let expiry: Int64
    public let kill: Bool

    public init(
        ownerVkh: Data, sttPolicy: Data, agentVkh: Data,
        perTxCap: Int64, dailyCap: Int64, windowLen: Int64,
        tokenCaps: [AssetCap], spends: [SpendRecord],
        minPrincipal: Int64, maxSpends: Int64, expiry: Int64, kill: Bool
    ) {
        self.ownerVkh = ownerVkh
        self.sttPolicy = sttPolicy
        self.agentVkh = agentVkh
        self.perTxCap = perTxCap
        self.dailyCap = dailyCap
        self.windowLen = windowLen
        self.tokenCaps = tokenCaps
        self.spends = spends
        self.minPrincipal = minPrincipal
        self.maxSpends = maxSpends
        self.expiry = expiry
        self.kill = kill
    }
}

/// The exact guard configuration the owner consented to. The host builds this
/// from the consent sheet and passes it down; `pinAndVerify` rejects any guard
/// whose on-chain datum differs in ANY security-relevant field, so the deployed
/// guard is byte-exactly the one the owner agreed to. ADA caps are named
/// explicitly rather than folded into `tokenCaps` — the on-chain `token_caps`
/// list carries only non-ADA assets. `windowLen` is the sliding-window length
/// the daily cap is measured over; a smaller window silently defeats the daily
/// cap (records age out instantly), so it is attested exactly like the caps.
public struct TokenCapConsent: Sendable, Equatable {
    /// A single consented non-ADA token cap.
    public struct Token: Sendable, Equatable {
        public let policy: Data
        public let name: Data
        public let perTx: Int64
        public let daily: Int64

        public init(policy: Data, name: Data, perTx: Int64, daily: Int64) {
            self.policy = policy
            self.name = name
            self.perTx = perTx
            self.daily = daily
        }
    }

    /// The non-ADA token caps, in the exact order they appear on-chain.
    public let tokens: [Token]
    public let adaPerTx: Int64
    public let adaDaily: Int64
    public let windowLen: Int64
    public let minPrincipal: Int64
    public let maxSpends: Int64
    public let expiry: Int64

    public init(
        tokens: [Token],
        adaPerTx: Int64,
        adaDaily: Int64,
        windowLen: Int64,
        minPrincipal: Int64,
        maxSpends: Int64,
        expiry: Int64
    ) {
        self.tokens = tokens
        self.adaPerTx = adaPerTx
        self.adaDaily = adaDaily
        self.windowLen = windowLen
        self.minPrincipal = minPrincipal
        self.maxSpends = maxSpends
        self.expiry = expiry
    }
}

/// A compact, host-renderable summary of the attested guard — carried in the
/// signing context so the consent sheet shows the caps the SDK actually
/// verified on-chain, not server-claimed numbers.
public struct GuardConsentSummary: Sendable, Equatable {
    public let ownerVkhHex: String
    public let agentVkhHex: String
    public let perTxCapAda: Int64
    public let dailyCapAda: Int64
    public let minPrincipalAda: Int64
    public let maxSpends: Int64
    public let expiry: Int64
    public let tokenCaps: [AssetCap]

    public init(datum: GuardDatum) {
        self.ownerVkhHex = datum.ownerVkh.hexString
        self.agentVkhHex = datum.agentVkh.hexString
        self.perTxCapAda = datum.perTxCap
        self.dailyCapAda = datum.dailyCap
        self.minPrincipalAda = datum.minPrincipal
        self.maxSpends = datum.maxSpends
        self.expiry = datum.expiry
        self.tokenCaps = datum.tokenCaps
    }
}

// MARK: - Realtime payloads

/// `sign_required` as pushed on the `notifications` channel (`createdAt` is
/// epoch milliseconds — the REST form of the same request uses ISO-8601).
public struct WsSignRequired: Sendable, Codable, Equatable {
    public let requestId: String
    public let unsignedCborHex: String
    public let bodyHashHex: String
    public let stepId: String
    public let action: String
    public let tradeProtocol: String
    public let description: String
    public let rationale: String
    public let estimatedValueAda: Double
    public let estimatedFeeAda: Double
    public let createdAt: Double

    enum CodingKeys: String, CodingKey {
        case requestId, unsignedCborHex, bodyHashHex, stepId, action
        case tradeProtocol = "protocol"
        case description, rationale, estimatedValueAda, estimatedFeeAda, createdAt
    }
}

public struct WsApprovalSummary: Sendable, Codable, Equatable {
    public let planId: String
    public let rationale: String
    public let action: String
    public let tradeProtocol: String
    public let estimatedValueAda: Double
    public let estimatedFeeAda: Double
    public let status: String

    enum CodingKeys: String, CodingKey {
        case planId, rationale, action
        case tradeProtocol = "protocol"
        case estimatedValueAda, estimatedFeeAda, status
    }
}

public struct WsApprovalRequired: Sendable, Codable, Equatable {
    public let id: String
    public let title: String
    public let message: String
    public let approval: WsApprovalSummary
}
