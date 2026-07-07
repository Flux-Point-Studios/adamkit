import Foundation

/// The façade a host wallet holds. Construction wires the pieces; the host
/// contributes exactly a signer (its keys, its UI) and a token store (its
/// secure storage).
public final class Adam: Sendable {
    public let config: AdamConfig
    public let session: AdamSession
    public let realtime: AdamRealtime
    public let signing: SigningCoordinator
    public let approvals: ApprovalCoordinator
    public let guardProvisioner: GuardProvisioner
    public let bot: BotAPI

    public init(
        config: AdamConfig,
        signer: any AdamHostSigner,
        tokenStore: any TokenStore,
        httpTransport: any HTTPTransport = URLSessionHTTPTransport(),
        wsTransport: any WebSocketTransport = URLSessionWebSocketTransport()
    ) {
        self.config = config
        let client = AdamClient(config: config, transport: httpTransport)
        let session = AdamSession(client: client, signer: signer, tokenStore: tokenStore)
        let api = AuthorizedClient(client: client, session: session)
        self.session = session
        self.realtime = AdamRealtime(config: config, session: session, transport: wsTransport)
        self.signing = SigningCoordinator(api: api, signer: signer)
        self.approvals = ApprovalCoordinator(api: api)
        self.guardProvisioner = GuardProvisioner(api: api, signer: signer)
        self.bot = BotAPI(api: api)
    }
}
