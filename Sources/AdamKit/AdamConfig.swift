import Foundation

public struct AdamConfig: Sendable {
    public enum Network: String, Sendable {
        case mainnet
        case preprod
    }

    public let baseURL: URL
    public let wsURL: URL
    public let network: Network
    /// Attribution-only partner identifier, sent with login. The gateway
    /// grants it no privileges.
    public let partnerId: String?

    public init(baseURL: URL, wsURL: URL? = nil, network: Network, partnerId: String? = nil) {
        self.baseURL = baseURL
        if let wsURL {
            self.wsURL = wsURL
        } else {
            var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
            components.scheme = components.scheme == "http" ? "ws" : "wss"
            self.wsURL = components.url!
        }
        self.network = network
        self.partnerId = partnerId
    }
}
