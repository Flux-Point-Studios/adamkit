import Foundation

/// Bot lifecycle and read surfaces: arm/disarm, status, strategies, activity.
public struct BotAPI: Sendable {
    private let api: AuthorizedClient

    public init(api: AuthorizedClient) {
        self.api = api
    }

    private struct BotIdBody: Encodable {
        let botId: String?
    }

    public func arm(botId: String? = nil) async throws -> ArmResult {
        try await api.post("/api/v1/bot/arm", body: BotIdBody(botId: botId))
    }

    public func disarm(botId: String? = nil) async throws -> ArmResult {
        try await api.post("/api/v1/bot/disarm", body: BotIdBody(botId: botId))
    }

    public func status() async throws -> BotStatus {
        try await api.get("/api/v1/bot/status")
    }

    public func strategies() async throws -> [Strategy] {
        let list: StrategiesList = try await api.get("/api/v1/strategies")
        return list.strategies
    }

    public func activity(limit: Int = 50) async throws -> [ActivityEvent] {
        let list: ActivityList = try await api.get(
            "/api/v1/agent/activity",
            query: [("limit", String(limit))]
        )
        return list.events
    }
}
