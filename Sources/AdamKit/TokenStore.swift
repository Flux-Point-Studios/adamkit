import Foundation

/// Where session tokens live. Hosts back this with their secure storage
/// (Keychain on Apple platforms) — never UserDefaults.
public protocol TokenStore: Sendable {
    func load() async throws -> StoredTokens?
    func save(_ tokens: StoredTokens) async throws
    func clear() async throws
}

/// Process-lifetime store for tests and previews.
public actor InMemoryTokenStore: TokenStore {
    private var tokens: StoredTokens?

    public init() {}

    public func load() async throws -> StoredTokens? { tokens }
    public func save(_ tokens: StoredTokens) async throws { self.tokens = tokens }
    public func clear() async throws { tokens = nil }
}
