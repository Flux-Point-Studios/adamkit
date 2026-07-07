// GeroHostSigner — the AdamKit custody seam for the Gero wallet.
//
// AdamKit never sees key material. The host wallet contributes exactly two
// operations, expressed here as `GeroWalletBridge`: sign a login challenge
// (CIP-30 signData) and witness a transaction. Conform Gero's existing wallet
// to `GeroWalletBridge` and hand a `GeroHostSigner` to `Adam(...)`.
//
// Copy this file (and KeychainTokenStore.swift) into gero-ios and implement
// `GeroWalletBridge` against Gero's CIP-30 / signing internals.

import Foundation
import AdamKit

/// A single vkey witness or a full CIP-30 witness set — whichever Gero's signing
/// path produces. AdamKit downgrades a witness set to the single vkey witness the
/// gateway expects (and refuses ambiguous sets).
public enum GeroWitness: Sendable {
    case vkey(vkeyHex: String, signatureHex: String)
    case witnessSet(cborHex: String)
}

/// The two operations AdamKit needs from the host wallet. This is the ONLY
/// surface Gero implements; everything else is protocol mechanics inside AdamKit.
public protocol GeroWalletBridge: Sendable {
    /// CIP-30 `signData(address, payload)`: sign `payloadHex` with the payment key
    /// of `addressBech32`. Return the COSE_Sign1 and the COSE_Key it produced,
    /// both hex — exactly the `{ signature, key }` CIP-30 `signData` yields.
    func signData(addressBech32: String, payloadHex: String) async throws -> (signatureHex: String, keyHex: String)

    /// Witness `unsignedTxCborHex` with the wallet's payment key.
    ///
    /// SECURITY: before signing, independently decode the transaction, recompute
    /// the blake2b-256 of its body bytes, and confirm it equals
    /// `expectedBodyHashHex` (AdamKit already verified this against the server's
    /// claimed hash; verifying again in the wallet is the third independent
    /// bind-to-bytes check). Present the decoded effect to the user for consent.
    /// Reject if the hash does not match.
    func witnessTransaction(unsignedTxCborHex: String, expectedBodyHashHex: String) async throws -> GeroWitness
}

/// Adapts `GeroWalletBridge` to AdamKit's `AdamHostSigner`.
public struct GeroHostSigner: AdamHostSigner {
    private let wallet: any GeroWalletBridge

    public init(wallet: any GeroWalletBridge) {
        self.wallet = wallet
    }

    public func signAuthChallenge(
        _ challenge: AuthChallenge,
        walletAddress: String
    ) async throws -> AuthSignature {
        // CIP-30 signData signs a byte payload; the gateway checks the COSE
        // payload equals the challenge text, so the payload is the message bytes.
        let payloadHex = Data(challenge.message.utf8).geroHexString
        let signed = try await wallet.signData(addressBech32: walletAddress, payloadHex: payloadHex)
        return AuthSignature(signatureHex: signed.signatureHex, coseKeyHex: signed.keyHex)
    }

    public func witnessTransaction(
        unsignedCborHex: String,
        bodyHashHex: String,
        context: SigningContext
    ) async throws -> TransactionWitness {
        // `context` (trade / guardDeploy / guardSweep) is available for richer
        // consent UI. Whatever the wallet does, it must sign exactly the bytes
        // whose body hashes to `bodyHashHex`.
        let witness = try await wallet.witnessTransaction(
            unsignedTxCborHex: unsignedCborHex,
            expectedBodyHashHex: bodyHashHex
        )
        switch witness {
        case .vkey(let vkeyHex, let signatureHex):
            return .vkey(vkeyHex: vkeyHex, signatureHex: signatureHex)
        case .witnessSet(let cborHex):
            return .witnessSet(cborHex: cborHex)
        }
    }
}

private extension Data {
    var geroHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
