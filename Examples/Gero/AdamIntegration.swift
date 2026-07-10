// AdamIntegration — how gero-ios wires AdamKit together and drives the core
// flows (login, realtime sign-requests, autonomous guard provisioning). Reference
// code: adapt the presentation hooks to Gero's UI.

import Foundation
import AdamKit

public enum AdamIntegration {
    /// Wire AdamKit with the Gero adapters. `partnerId: "gero"` attributes the
    /// user to the Gero partner tier on the gateway.
    public static func make(
        baseURL: URL,
        network: AdamConfig.Network,
        wallet: any GeroWalletBridge,
        tokenStore: any TokenStore
    ) -> Adam {
        Adam(
            config: AdamConfig(baseURL: baseURL, network: network, partnerId: "gero"),
            signer: GeroHostSigner(wallet: wallet),
            tokenStore: tokenStore
        )
    }

    #if canImport(Security)
    /// iOS/macOS convenience: back the session with the Keychain store.
    public static func make(
        baseURL: URL,
        network: AdamConfig.Network,
        wallet: any GeroWalletBridge
    ) -> Adam {
        make(baseURL: baseURL, network: network, wallet: wallet, tokenStore: KeychainTokenStore())
    }
    #endif
}

/// The four flows a partner app drives. Each is a thin pass-through to AdamKit;
/// the SDK owns protocol correctness (bind-to-bytes, token refresh, WS lifecycle).
public struct AdamFlow: Sendable {
    private let adam: Adam

    public init(_ adam: Adam) {
        self.adam = adam
    }

    /// 1. Login: nonce → host cip8 `signData` → JWT (refresh rotation is internal).
    public func login(walletAddress: String, deviceId: String, deviceName: String? = nil) async throws -> AdamUser {
        try await adam.session.login(walletAddress: walletAddress, deviceId: deviceId, deviceName: deviceName)
    }

    /// 2. Realtime + reconciliation. Present each sign-request to the user; the SDK
    /// has already re-hashed the tx body, so `present` only ever sees verified
    /// requests. Reconcile over REST on every (re)connect — WS delivery is
    /// best-effort by contract.
    public func runRealtime(present: @Sendable @escaping (SignRequest) -> Void) async {
        for await event in await adam.realtime.start() {
            switch event {
            case .connected:
                if let pending = try? await adam.signing.reconcile() {
                    for request in pending { present(request) }
                }
            case .signRequired:
                if let request = await adam.signing.handle(event) { present(request) }
            default:
                break
            }
        }
    }

    /// 3. User approved in the UI → host witnesses → SDK assembles + submits.
    @discardableResult
    public func approve(_ requestId: String) async throws -> SignRequestState {
        try await adam.signing.approve(requestId)
    }

    @discardableResult
    public func decline(_ requestId: String) async throws -> SignRequestState {
        try await adam.signing.decline(requestId)
    }

    /// 4. Enable autonomous mode: the user witnesses ONE guard-deploy tx (present
    /// `deployment.consentSummary` — the SDK-attested principal, owner, per-tx +
    /// daily caps decoded from the on-chain datum — for consent), then the bot is
    /// armed. `consent` is the tradeable-token set + caps the user agreed to;
    /// `requestDeployment` pins the guard address and rejects any deploy whose
    /// on-chain caps differ. The owner can sweep + revoke unilaterally.
    public func enableAutonomous(principalAda: Double, consent: TokenCapConsent) async throws {
        let deployment = try await adam.guardProvisioner.requestDeployment(
            principalAda: principalAda, consent: consent)
        _ = try await adam.guardProvisioner.signAndSubmit(deployment)
        _ = try await adam.guardProvisioner.confirm(deployment)
        _ = try await adam.bot.arm()
    }
}
