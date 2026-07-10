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

    /// The inline datum bytes of the guard-address output that carries the STT —
    /// the state-token singleton the on-chain validator actually governs by.
    ///
    /// The universal guard address is shared across every guard, so paying it is
    /// not enough: a malicious deploy can pay it TWICE, listing a benign
    /// consent-matching datum first (min-ADA, no STT) and the real,
    /// attacker-controlled datum second on the output that actually mints and
    /// holds the STT. Selecting by address alone binds to the benign decoy while
    /// the funds obey the malicious one. So this selects by the STT: it walks
    /// every output, and for each guard-address output inspects the value (key
    /// 1) — either bare `coin` (ada-only, no STT) or `[coin, multiasset]` — and
    /// keeps only those whose multiasset carries an asset under `sttPolicy` at
    /// quantity >= 1. EXACTLY ONE such output must exist (the STT is a
    /// singleton); zero or many is a non-consenting deploy and throws.
    ///
    /// `guardAddressBytes` / `sttPolicy` are the raw decoded bytes (NOT bech32 /
    /// hex). Returns the SLICED inline datum bytes — the CBOR is never
    /// re-encoded, so the datum hashes identically to what the ledger stores.
    /// Each post-Alonzo output is a map `{0: address, 1: value, 2: [1,
    /// tag24(datum_bytes)], 3: script_ref?}`; the legacy `[address, value]`
    /// array form carries no datum and is skipped.
    public static func guardOutputDatum(_ tx: Data, guardAddressBytes: Data, sttPolicy: Data) throws
        -> Data
    {
        guard case let .array(top) = try CBOR.decode(tx), let body = top.first,
            case let .map(bodyFields) = body
        else {
            throw CBORError.unsupportedShape("transaction is not [body,...] with a map body")
        }
        guard let outputsEntry = bodyFields.first(where: { $0.key == .unsigned(1) }),
            case let .array(outputs) = outputsEntry.value
        else {
            throw CBORError.unsupportedShape("transaction body has no outputs array (key 1)")
        }
        var sttDatums = [Data]()
        for output in outputs {
            guard case let .map(fields) = output else { continue }  // legacy array form: no datum
            guard let addressField = fields.first(where: { $0.key == .unsigned(0) }),
                case let .bytes(address) = addressField.value, address == guardAddressBytes
            else { continue }
            guard let valueField = fields.first(where: { $0.key == .unsigned(1) }),
                valueCarriesSTT(valueField.value, sttPolicy: sttPolicy)
            else { continue }  // guard-address output without the STT: the validator does not govern by it
            guard let datumField = fields.first(where: { $0.key == .unsigned(2) }) else {
                throw CBORError.unsupportedShape("guard STT output has no datum field (key 2)")
            }
            // Inline datum: [1, tag24(bytes(datum))]. A datum-hash output is
            // [0, bytes(hash)] — no inline datum to attest.
            guard case let .array(datumOption) = datumField.value, datumOption.count == 2,
                datumOption[0] == .unsigned(1),
                case let .tagged(24, inner) = datumOption[1],
                case let .bytes(datumBytes) = inner
            else {
                throw CBORError.unsupportedShape("guard STT output datum is not an inline datum")
            }
            sttDatums.append(datumBytes)
        }
        guard sttDatums.count == 1 else {
            throw CBORError.unsupportedShape(
                "expected exactly one guard-address output carrying the STT of the pinned policy, "
                    + "found \(sttDatums.count)")
        }
        return sttDatums[0]
    }

    /// Whether a Cardano output `value` (key 1) carries at least one asset under
    /// `sttPolicy`. The value is either `.unsigned(coin)` (ada-only → no STT) or
    /// `[coin, multiasset]` where multiasset is a map
    /// `{policy_bytes: {asset_name_bytes: qty}}`. The STT is present iff that map
    /// has an entry keyed by `sttPolicy` with some asset name at quantity >= 1.
    private static func valueCarriesSTT(_ value: CBORValue, sttPolicy: Data) -> Bool {
        guard case let .array(pair) = value, pair.count == 2,
            case let .map(multiasset) = pair[1]
        else {
            return false  // bare coin, or a shape with no multiasset: no STT
        }
        for (policyKey, assets) in multiasset {
            guard case let .bytes(policy) = policyKey, policy == sttPolicy,
                case let .map(names) = assets
            else { continue }
            for (_, qtyValue) in names {
                if case let .unsigned(qty) = qtyValue, qty >= 1 { return true }
            }
        }
        return false
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
