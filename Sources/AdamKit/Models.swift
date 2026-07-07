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
