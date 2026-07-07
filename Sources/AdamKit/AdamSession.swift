import Foundation

struct LoginRequestBody: Encodable {
    let walletAddress: String
    let chain: String
    let message: String
    let signature: String
    let publicKey: String
    let deviceId: String
    let deviceName: String?
    let partnerId: String?
}

struct RefreshRequestBody: Encodable {
    let refreshToken: String
    let deviceId: String
}

struct LogoutRequestBody: Encodable {
    let refreshToken: String?
    let allDevices: Bool
}

/// Session lifecycle: challenge-response login through the host signer,
/// token persistence, and single-flight refresh (this is an actor, so
/// concurrent callers of `validAccessToken` serialize on one refresh).
public actor AdamSession {
    private let client: AdamClient
    private let signer: any AdamHostSigner
    private let tokenStore: any TokenStore
    private let now: @Sendable () -> Date

    /// Refresh this long before the access token actually expires.
    private static let expirySlack: TimeInterval = 60

    public init(
        client: AdamClient,
        signer: any AdamHostSigner,
        tokenStore: any TokenStore,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.client = client
        self.signer = signer
        self.tokenStore = tokenStore
        self.now = now
    }

    /// CIP-30 challenge-response: nonce → host `signData` → tokens.
    @discardableResult
    public func login(
        walletAddress: String,
        deviceId: String,
        deviceName: String? = nil
    ) async throws -> AdamUser {
        let challenge: AuthChallenge = try await client.get(
            "/api/v1/auth/nonce",
            query: [("walletAddress", walletAddress)],
        )
        let signature = try await signer.signAuthChallenge(challenge, walletAddress: walletAddress)
        let result: LoginResult = try await client.post(
            "/api/v1/auth/login",
            body: LoginRequestBody(
                walletAddress: walletAddress,
                chain: "cardano",
                message: challenge.message,
                signature: signature.signatureHex,
                publicKey: signature.publicKeyHex,
                deviceId: deviceId,
                deviceName: deviceName,
                partnerId: client.config.partnerId,
            ),
        )
        try await tokenStore.save(
            StoredTokens(
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
                expiresAt: now().addingTimeInterval(TimeInterval(result.expiresIn)),
                walletAddress: walletAddress,
                deviceId: deviceId,
            ))
        return result.user
    }

    /// A token safe to attach to a request, refreshing first when the stored
    /// one is expired or about to be.
    public func validAccessToken() async throws -> String {
        guard let stored = try await tokenStore.load() else {
            throw AdamError.notAuthenticated
        }
        if stored.expiresAt.timeIntervalSince(now()) > Self.expirySlack {
            return stored.accessToken
        }
        return try await refresh(stored).accessToken
    }

    /// Rotate tokens unconditionally (the 401-retry path).
    public func forceRefresh() async throws -> String {
        guard let stored = try await tokenStore.load() else {
            throw AdamError.notAuthenticated
        }
        return try await refresh(stored).accessToken
    }

    private func refresh(_ stored: StoredTokens) async throws -> StoredTokens {
        let result: RefreshResult
        do {
            result = try await client.post(
                "/api/v1/auth/refresh",
                body: RefreshRequestBody(refreshToken: stored.refreshToken, deviceId: stored.deviceId),
            )
        } catch let error as AdamError where error.isAuthExpiry {
            try await tokenStore.clear()
            throw AdamError.notAuthenticated
        }
        let rotated = StoredTokens(
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            expiresAt: now().addingTimeInterval(TimeInterval(result.expiresIn)),
            walletAddress: stored.walletAddress,
            deviceId: stored.deviceId,
        )
        try await tokenStore.save(rotated)
        return rotated
    }

    public func logout(allDevices: Bool = false) async throws {
        let stored = try await tokenStore.load()
        struct LogoutResult: Decodable {
            let message: String
        }
        if let stored {
            let _: LogoutResult = try await client.post(
                "/api/v1/auth/logout",
                body: LogoutRequestBody(refreshToken: stored.refreshToken, allDevices: allDevices),
                accessToken: stored.accessToken,
            )
        }
        try await tokenStore.clear()
    }
}

/// Client + session: attaches the bearer token and retries exactly once
/// through a forced refresh when the gateway answers 401.
public struct AuthorizedClient: Sendable {
    let client: AdamClient
    let session: AdamSession

    public init(client: AdamClient, session: AdamSession) {
        self.client = client
        self.session = session
    }

    func get<T: Decodable>(_ path: String, query: [(name: String, value: String)] = []) async throws -> T {
        let token = try await session.validAccessToken()
        do {
            return try await client.get(path, query: query, accessToken: token)
        } catch let error as AdamError where error.isAuthExpiry {
            return try await client.get(path, query: query, accessToken: session.forceRefresh())
        }
    }

    func post<T: Decodable>(_ path: String, body: (some Encodable & Sendable)?) async throws -> T {
        let token = try await session.validAccessToken()
        do {
            return try await client.post(path, body: body, accessToken: token)
        } catch let error as AdamError where error.isAuthExpiry {
            return try await client.post(path, body: body, accessToken: session.forceRefresh())
        }
    }
}
