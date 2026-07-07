import Foundation

/// What the host wallet returns for a login challenge.
public struct AuthSignature: Sendable {
    public let signatureHex: String
    public let publicKeyHex: String

    public init(signatureHex: String, publicKeyHex: String) {
        self.signatureHex = signatureHex
        self.publicKeyHex = publicKeyHex
    }
}

/// What the host wallet returns for a transaction: either the gateway's
/// single-witness wire form directly, or a full CIP-30 witness set (e.g.
/// Gero's `swapWitnessSet`), which the SDK downgrades by CBOR extraction.
public enum TransactionWitness: Sendable {
    case vkey(vkeyHex: String, signatureHex: String)
    case witnessSet(cborHex: String)
}

/// Why the SDK is asking for a witness — hosts must independently decode and
/// inspect the transaction before signing; these are display anchors, not
/// trusted amounts.
public enum SigningContext: Sendable {
    case trade(SignRequest)
    case guardDeploy(GuardProvision)
}

/// The entire custody seam. AdamKit never sees key material: the host signs
/// with keys it already protects, and everything else is protocol mechanics
/// inside the SDK.
public protocol AdamHostSigner: Sendable {
    /// Sign the login challenge text with the wallet's payment key
    /// (CIP-30 `signData` semantics).
    func signAuthChallenge(_ challenge: AuthChallenge, walletAddress: String) async throws -> AuthSignature

    /// Witness a transaction. `bodyHashHex` is recomputed by the SDK from
    /// `unsignedCborHex` before this is called; hosts should verify it again
    /// after their own decode and sign exactly those bytes.
    func witnessTransaction(
        unsignedCborHex: String,
        bodyHashHex: String,
        context: SigningContext
    ) async throws -> TransactionWitness
}

extension TransactionWitness {
    /// The gateway accepts one vkey witness. A set with any other number of
    /// vkey witnesses is ambiguous and refused.
    func vkeyWitness() throws -> CardanoTx.VkeyWitness {
        switch self {
        case .vkey(let vkeyHex, let signatureHex):
            return CardanoTx.VkeyWitness(vkeyHex: vkeyHex, signatureHex: signatureHex)
        case .witnessSet(let cborHex):
            let witnesses = try CardanoTx.vkeyWitnesses(inWitnessSet: Data(hexString: cborHex))
            guard witnesses.count == 1 else { throw AdamError.witnessCount(witnesses.count) }
            return witnesses[0]
        }
    }
}
