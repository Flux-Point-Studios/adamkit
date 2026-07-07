// KeychainTokenStore — a complete, drop-in AdamKit `TokenStore` backed by the
// iOS/macOS Keychain. Session tokens are stored as one JSON blob under a generic
// password item, accessible only after first unlock, this-device-only (never
// synced to iCloud). Copy this file into gero-ios as-is.

#if canImport(Security)
import Foundation
import Security
import AdamKit

public actor KeychainTokenStore: TokenStore {
    private let service: String
    private let account: String

    /// - Parameters:
    ///   - service: Keychain service (bundle-scoped; defaults to the app's bundle id).
    ///   - account: item key. Use one per wallet if you support multiple accounts.
    public init(
        service: String = (Bundle.main.bundleIdentifier ?? "adamkit") + ".adam.session",
        account: String = "adam-session"
    ) {
        self.service = service
        self.account = account
    }

    public func load() async throws -> StoredTokens? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainError.status(status)
        }
        return try JSONDecoder().decode(StoredTokens.self, from: data)
    }

    public func save(_ tokens: StoredTokens) async throws {
        let data = try JSONEncoder().encode(tokens)

        // Update in place if present, else add. Avoids a delete/add race.
        let attributes: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound { throw KeychainError.status(updateStatus) }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError.status(addStatus) }
    }

    public func clear() async throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.status(status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

public enum KeychainError: Error, CustomStringConvertible {
    case status(OSStatus)

    public var description: String {
        switch self {
        case .status(let s):
            let msg = SecCopyErrorMessageString(s, nil) as String? ?? "unknown"
            return "Keychain error \(s): \(msg)"
        }
    }
}
#endif
