import Foundation

/// Cardano transaction byte-surgery: the bind-to-bytes primitives that let the
/// SDK independently verify what a sign request commits to before any of it
/// reaches the host wallet.
public enum CardanoTx {
    /// The exact original bytes of `transaction_body` — element 0 of the
    /// top-level `[body, witness_set, is_valid?, auxiliary_data?]` array.
    /// Slicing (never re-encoding) is what keeps non-canonical bodies hashing
    /// to the hash the ledger uses.
    public static func extractBodyBytes(_ tx: Data) throws -> Data {
        let outer = try CBOR.readHeader(tx, 0)
        guard outer.major == 4 else { throw CBORError.topLevelNotArray }
        let bodyOffset = outer.headerBytes
        let bodyLength = try CBOR.itemLength(tx, at: bodyOffset)
        let base = tx.startIndex + bodyOffset
        return Data(tx[base..<base + bodyLength])
    }

    /// blake2b-256 of the transaction body — the 32 bytes a vkey witness signs.
    public static func bodyHash(_ tx: Data) throws -> Data {
        Blake2b.hash(try extractBodyBytes(tx), digestLength: 32)
    }

    /// A single Ed25519 vkey witness in the gateway's wire form.
    public struct VkeyWitness: Sendable, Equatable {
        public let vkeyHex: String
        public let signatureHex: String

        public init(vkeyHex: String, signatureHex: String) {
            self.vkeyHex = vkeyHex
            self.signatureHex = signatureHex
        }
    }

    /// Extract the vkey witnesses (map key 0) from a `transaction_witness_set`
    /// — the CBOR a CIP-30 `signTx`/witness call returns. Entries under other
    /// keys are ignored; a set without key 0 yields `[]`.
    public static func vkeyWitnesses(inWitnessSet witnessSet: Data) throws -> [VkeyWitness] {
        guard case let .map(entries) = try CBOR.decode(witnessSet) else {
            throw CBORError.unsupportedShape("witness set is not a CBOR map")
        }
        guard let vkeysEntry = entries.first(where: { $0.key == .unsigned(0) }) else {
            return []
        }
        // Conway encodes set-typed fields as tag 258 around the array.
        var vkeysValue = vkeysEntry.value
        if case let .tagged(258, inner) = vkeysValue { vkeysValue = inner }
        guard case let .array(witnesses) = vkeysValue else {
            throw CBORError.unsupportedShape("vkey witnesses field is not an array")
        }
        return try witnesses.map { witness in
            guard case let .array(pair) = witness, pair.count == 2,
                case let .bytes(vkey) = pair[0], vkey.count == 32,
                case let .bytes(signature) = pair[1], signature.count == 64
            else {
                throw CBORError.unsupportedShape("vkey witness is not [32-byte key, 64-byte signature]")
            }
            return VkeyWitness(vkeyHex: vkey.hexString, signatureHex: signature.hexString)
        }
    }
}
