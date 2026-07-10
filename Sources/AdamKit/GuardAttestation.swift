import Foundation

/// Owner-consent attestation for the per-asset spending guard.
///
/// The guard validator is UNPARAMETERIZED — one universal script address for
/// every guard on a network — so the address is a bundled constant (the pin),
/// not something derived per-user on device. Before the owner witnesses the
/// deploy transaction, the SDK independently proves, from the deploy tx bytes
/// alone, that the on-chain guard bounds the owner's funds exactly as they
/// consented: the deploy pays the pinned guard address, the inline datum names
/// the owner as `owner`, pins the bundled STT policy, and carries the exact
/// consented caps. Any mismatch throws so a non-consenting guard never reaches
/// `signAndSubmit`.
public enum GuardAttestation {
    /// The frozen, unparameterized guard script — one address per network.
    public enum Pin {
        /// blake2b-224 script hash of the universal guard validator.
        public static let scriptHash = "ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6"
        public static let addressMainnet =
            "addr1w8kt8nsrwxyg08tlafr65hn7kn9mrcjy0xqkhapeu4avh3s9949sa"
        public static let addressPreprod =
            "addr_test1wrkt8nsrwxyg08tlafr65hn7kn9mrcjy0xqkhapeu4avh3s7dpelc"
        /// The universal STT (guard state token) minting policy id.
        public static let sttPolicyId = "5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"

        static func address(for network: AdamConfig.Network) -> String {
            switch network {
            case .mainnet: return addressMainnet
            case .preprod: return addressPreprod
            }
        }
    }

    /// Attest the deploy tx and return the decoded, consent-verified datum.
    ///
    /// - `deployTx`: the raw CBOR bytes of the owner-signed deploy transaction.
    /// - `network`: selects the bundled guard address to pin against.
    /// - `ownerAddress`: the login wallet address (bech32); its payment
    ///   credential must be a key-hash equal to the datum's `owner`.
    /// - `consent`: the tradeable-token set + per-token/ADA caps the owner agreed
    ///   to. Compared as an exact ordered list against the on-chain caps.
    @discardableResult
    public static func pinAndVerify(
        deployTx: Data,
        network: AdamConfig.Network,
        ownerAddress: String,
        consent: TokenCapConsent,
        agentGasAddr: String?
    ) throws -> GuardDatum {
        let guardAddressBytes = try CardanoAddress.rawBytes(bech32: Pin.address(for: network))
        let sttPolicy = try Data(hexString: Pin.sttPolicyId)

        // (a) the deploy must pay the pinned guard address on the output that
        // carries the pinned STT — the singleton the on-chain validator governs
        // by — with an inline datum. Any structural failure here — no STT output
        // to the guard address, a missing/ambiguous STT, no inline datum — means
        // this is not the guard the owner consented to, so it surfaces as a
        // contract (consent) failure, never a raw CBOR error.
        let datumBytes: Data
        do {
            datumBytes = try CardanoTx.guardOutputDatum(
                deployTx, guardAddressBytes: guardAddressBytes, sttPolicy: sttPolicy)
        } catch let error as CBORError {
            throw AdamError.contract("guard output attestation failed: \(error)")
        }

        // (b) decode the on-chain datum independently.
        let datum = try GuardDatum.decode(from: datumBytes)

        // (c) the datum's owner must be MY payment key-hash.
        let ownerVkh = try CardanoAddress.paymentKeyHash(bech32: ownerAddress)
        guard datum.ownerVkh == ownerVkh else {
            throw AdamError.contract(
                "guard owner mismatch: datum owner \(datum.ownerVkh.hexString) is not my key \(ownerVkh.hexString)")
        }

        // (d) the datum must pin the bundled STT policy.
        guard datum.sttPolicy == sttPolicy else {
            throw AdamError.contract(
                "guard STT policy mismatch: datum \(datum.sttPolicy.hexString) != pinned \(Pin.sttPolicyId)")
        }

        // (d2) the datum's agent must be the payment key-hash of the gas address
        // the deploy funds. This binds the AgentSpend-branch session key to the
        // one address the same deploy seeds, catching any tamper that changes the
        // agent field inconsistently with the funded gas output. `agentGasAddr`
        // is nil only for legacy/ADA-only deploys with no agent gas output, where
        // there is nothing to bind.
        if let agentGasAddr {
            let agentGasVkh = try CardanoAddress.paymentKeyHash(bech32: agentGasAddr)
            guard datum.agentVkh == agentGasVkh else {
                throw AdamError.contract(
                    "guard agent mismatch: datum agent \(datum.agentVkh.hexString) is not the funded gas key")
            }
        }

        // (d3) the sliding-window length bounding the daily cap must be exactly
        // the consented value. A smaller window silently defeats the daily cap —
        // records age out instantly, so the agent can spend up to daily_cap on
        // EVERY tx — and a larger one changes the bound the owner agreed to.
        guard datum.windowLen == consent.windowLen else {
            throw AdamError.contract(
                "guard window_len mismatch: datum \(datum.windowLen) != consent \(consent.windowLen)")
        }

        // (d4) min-principal, max-spends, and expiry are all consented bounds on
        // the autonomy; any drift is a different guard.
        guard datum.minPrincipal == consent.minPrincipal else {
            throw AdamError.contract(
                "guard min_principal mismatch: datum \(datum.minPrincipal) != consent \(consent.minPrincipal)")
        }
        guard datum.maxSpends == consent.maxSpends else {
            throw AdamError.contract(
                "guard max_spends mismatch: datum \(datum.maxSpends) != consent \(consent.maxSpends)")
        }
        guard datum.expiry == consent.expiry else {
            throw AdamError.contract(
                "guard expiry mismatch: datum \(datum.expiry) != consent \(consent.expiry)")
        }

        // (d5) a freshly-deployed guard must not be pre-killed.
        guard datum.kill == false else {
            throw AdamError.contract("guard is pre-killed: datum kill=true")
        }

        // (d6) a freshly-deployed guard MUST have an EMPTY spends list. The
        // on-chain `sum_active_for` has no non-negativity guard, so a seeded
        // NEGATIVE spend record (e.g. amount = -1e9 within the current window)
        // drives the daily-window sum negative and lets the agent move
        // daily_cap + |seeded amount| per window — a direct daily-cap bypass.
        // Any prior record at deploy is non-consensual, so require none.
        guard datum.spends.isEmpty else {
            throw AdamError.contract(
                "guard deploy datum has non-empty spends — a fresh guard must have no prior spend records")
        }

        // (e) the caps must equal the consented set exactly (ordered).
        //
        // At this point every security-relevant datum field is attested against
        // the owner's consent + the bundled pins (including an empty spends list,
        // so no seeded record pre-loads the spend window), so the on-chain guard
        // is exactly the one the owner agreed to. The ONLY residual is that the
        // agent SESSION KEY itself is server-generated: the client has no
        // owner-derived "correct" agent to compare against, so a fully-malicious
        // gateway that picks BOTH the agent key AND a matching gas address is not
        // caught by attestation. That residual is bounded by the consented
        // per_tx/daily caps + window_len + expiry + the owner's unrestricted
        // OwnerSpend revoke/sweep — the accepted bounded-autonomy design.
        try verifyCaps(datum: datum, consent: consent)

        return datum
    }

    /// Exact-match the on-chain caps against consent: ADA per-tx/daily and the
    /// ordered non-ADA token list. A reordered, padded, or truncated token list
    /// is a DIFFERENT guard.
    static func verifyCaps(datum: GuardDatum, consent: TokenCapConsent) throws {
        guard datum.perTxCap == consent.adaPerTx, datum.dailyCap == consent.adaDaily else {
            throw AdamError.contract(
                "guard ADA cap mismatch: datum per_tx=\(datum.perTxCap) daily=\(datum.dailyCap), "
                    + "consent per_tx=\(consent.adaPerTx) daily=\(consent.adaDaily)")
        }
        guard datum.tokenCaps.count == consent.tokens.count else {
            throw AdamError.contract(
                "guard token-cap count mismatch: datum has \(datum.tokenCaps.count), "
                    + "consent has \(consent.tokens.count)")
        }
        for (index, (cap, token)) in zip(datum.tokenCaps, consent.tokens).enumerated() {
            guard cap.policy == token.policy, cap.name == token.name,
                cap.perTx == token.perTx, cap.daily == token.daily
            else {
                throw AdamError.contract(
                    "guard token cap #\(index) mismatch: datum "
                        + "\(cap.policy.hexString).\(cap.name.hexString) per_tx=\(cap.perTx) daily=\(cap.daily), "
                        + "consent \(token.policy.hexString).\(token.name.hexString) "
                        + "per_tx=\(token.perTx) daily=\(token.daily)")
            }
        }
    }
}

// MARK: - GuardDatum decoding

extension GuardDatum {
    /// Decode the on-chain inline datum bytes into a `GuardDatum`. Any shape
    /// mismatch throws `AdamError.contract` — a datum that does not decode
    /// cleanly is never trusted.
    public static func decode(from cbor: Data) throws -> GuardDatum {
        let value = try CBOR.decode(cbor)
        let fields = try PlutusData.constrFields(value, tag: 0, expected: "GuardDatum")
        guard fields.count == 12 else {
            throw AdamError.contract("GuardDatum expected 12 fields, got \(fields.count)")
        }
        return GuardDatum(
            ownerVkh: try PlutusData.bytes(fields[0], "owner"),
            sttPolicy: try PlutusData.bytes(fields[1], "stt_policy"),
            agentVkh: try PlutusData.bytes(fields[2], "agent"),
            perTxCap: try PlutusData.int(fields[3], "per_tx_cap"),
            dailyCap: try PlutusData.int(fields[4], "daily_cap"),
            windowLen: try PlutusData.int(fields[5], "window_len"),
            tokenCaps: try PlutusData.list(fields[6], "token_caps").map(AssetCap.decode),
            spends: try PlutusData.list(fields[7], "spends").map(SpendRecord.decode),
            minPrincipal: try PlutusData.int(fields[8], "min_principal"),
            maxSpends: try PlutusData.int(fields[9], "max_spends"),
            expiry: try PlutusData.int(fields[10], "expiry"),
            kill: try PlutusData.bool(fields[11], "kill")
        )
    }
}

extension AssetCap {
    static func decode(_ value: CBORValue) throws -> AssetCap {
        let fields = try PlutusData.constrFields(value, tag: 0, expected: "AssetCap")
        guard fields.count == 4 else {
            throw AdamError.contract("AssetCap expected 4 fields, got \(fields.count)")
        }
        return AssetCap(
            policy: try PlutusData.bytes(fields[0], "AssetCap.policy"),
            name: try PlutusData.bytes(fields[1], "AssetCap.name"),
            perTx: try PlutusData.int(fields[2], "AssetCap.per_tx"),
            daily: try PlutusData.int(fields[3], "AssetCap.daily")
        )
    }
}

extension SpendRecord {
    static func decode(_ value: CBORValue) throws -> SpendRecord {
        let fields = try PlutusData.constrFields(value, tag: 0, expected: "SpendRecord")
        guard fields.count == 4 else {
            throw AdamError.contract("SpendRecord expected 4 fields, got \(fields.count)")
        }
        return SpendRecord(
            policy: try PlutusData.bytes(fields[0], "SpendRecord.policy"),
            name: try PlutusData.bytes(fields[1], "SpendRecord.name"),
            at: try PlutusData.int(fields[2], "SpendRecord.at"),
            amount: try PlutusData.int(fields[3], "SpendRecord.amount")
        )
    }
}

// MARK: - Plutus Data helpers over CBORValue

/// Reads the Plutus-on-CBOR shapes the guard datum uses: Constr (CBOR tag
/// 121 + N = constructor N, field array either definite `0x8N` or indefinite
/// `0x9F..0xFF`), bytestrings, integers (including bignum tag 2), and Bool as
/// Constr 0 [] / Constr 1 []. Every reader throws `AdamError.contract` on a
/// shape mismatch — nothing is guessed.
enum PlutusData {
    /// The constructor index a CBOR tag encodes, or `nil` if it is not a
    /// Plutus constructor tag. Alonzo encodes constructors 0..6 as tags
    /// 121..127, 7..127 as 1280.., and anything else under the general tag 102.
    static func constructorIndex(forTag tag: UInt64) -> UInt64? {
        switch tag {
        case 121...127: return tag - 121
        case 1280...1400: return tag - 1280 + 7
        default: return nil
        }
    }

    /// The fields of a constructor with the given index, unwrapping the tag and
    /// accepting both the definite and indefinite field-array encodings. The
    /// TRAP: an EMPTY constructor serialises DEFINITE (`D8 79 80`), a non-empty
    /// one indefinite (`D8 79 9F .. FF`); the CBOR decoder normalises both to
    /// `.array`, so this reader accepts either transparently.
    static func constrFields(_ value: CBORValue, tag expectedIndex: UInt64, expected: String) throws
        -> [CBORValue]
    {
        guard case let .tagged(tag, inner) = value, let index = constructorIndex(forTag: tag) else {
            throw AdamError.contract("\(expected): expected a Plutus constructor, got \(value)")
        }
        guard index == expectedIndex else {
            throw AdamError.contract(
                "\(expected): expected constructor \(expectedIndex), got \(index)")
        }
        guard case let .array(fields) = inner else {
            throw AdamError.contract("\(expected): constructor payload is not an array")
        }
        return fields
    }

    static func bytes(_ value: CBORValue, _ field: String) throws -> Data {
        guard case let .bytes(data) = value else {
            throw AdamError.contract("\(field): expected bytes, got \(value)")
        }
        return data
    }

    /// A non-negative Plutus integer. Handles small ints directly and CBOR
    /// bignum (tag 2, unsigned) for values wider than the CBOR header; throws
    /// if the value does not fit `Int64` (real caps/amounts never approach it).
    static func int(_ value: CBORValue, _ field: String) throws -> Int64 {
        switch value {
        case let .unsigned(u):
            guard let i = Int64(exactly: u) else {
                throw AdamError.contract("\(field): integer \(u) exceeds Int64")
            }
            return i
        case let .negative(u):
            // -1 - u; only representable when u <= Int64.max.
            guard let magnitude = Int64(exactly: u) else {
                throw AdamError.contract("\(field): negative integer -1-\(u) exceeds Int64")
            }
            return -1 - magnitude
        case let .tagged(2, inner):
            // Unsigned bignum: big-endian bytestring.
            let data = try bytes(inner, "\(field) (bignum)")
            guard data.count <= 8 else {
                throw AdamError.contract("\(field): bignum wider than 8 bytes exceeds Int64")
            }
            var acc: UInt64 = 0
            for byte in data { acc = acc << 8 | UInt64(byte) }
            guard let i = Int64(exactly: acc) else {
                throw AdamError.contract("\(field): bignum \(acc) exceeds Int64")
            }
            return i
        case let .tagged(3, inner):
            let data = try bytes(inner, "\(field) (negative bignum)")
            guard data.count <= 8 else {
                throw AdamError.contract("\(field): negative bignum wider than 8 bytes exceeds Int64")
            }
            var acc: UInt64 = 0
            for byte in data { acc = acc << 8 | UInt64(byte) }
            guard let magnitude = Int64(exactly: acc) else {
                throw AdamError.contract("\(field): negative bignum \(acc) exceeds Int64")
            }
            return -1 - magnitude
        default:
            throw AdamError.contract("\(field): expected integer, got \(value)")
        }
    }

    static func list(_ value: CBORValue, _ field: String) throws -> [CBORValue] {
        guard case let .array(items) = value else {
            throw AdamError.contract("\(field): expected a list, got \(value)")
        }
        return items
    }

    /// Plutus Bool: `Constr 0 []` = False, `Constr 1 []` = True.
    static func bool(_ value: CBORValue, _ field: String) throws -> Bool {
        guard case let .tagged(tag, inner) = value, let index = constructorIndex(forTag: tag) else {
            throw AdamError.contract("\(field): expected a Plutus Bool constructor, got \(value)")
        }
        guard case let .array(fields) = inner, fields.isEmpty else {
            throw AdamError.contract("\(field): Bool constructor must have no fields")
        }
        switch index {
        case 0: return false
        case 1: return true
        default: throw AdamError.contract("\(field): Bool constructor index \(index) is not 0/1")
        }
    }
}

// MARK: - Cardano address (bech32 → raw bytes → payment key-hash)

/// The bech32 + Shelley-address surgery the SDK needs to pin the guard address
/// and derive the owner's payment key-hash — no native CardanoKit dependency,
/// so the attestation runs entirely inside AdamKit.
enum CardanoAddress {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    /// Decode a bech32 string to (hrp, 8-bit data bytes), verifying the
    /// checksum. Rejects mixed case and out-of-charset characters.
    static func rawBytes(bech32: String) throws -> Data {
        let lower = bech32.lowercased()
        guard lower == bech32 || bech32.uppercased() == bech32 else {
            throw AdamError.contract("bech32 address has mixed case: \(bech32)")
        }
        guard let sep = lower.lastIndex(of: "1"), sep != lower.startIndex else {
            throw AdamError.contract("bech32 address has no separator: \(bech32)")
        }
        let hrp = String(lower[lower.startIndex..<sep])
        let dataPart = lower[lower.index(after: sep)...]
        guard dataPart.count >= 6 else {
            throw AdamError.contract("bech32 address too short: \(bech32)")
        }
        var values = [UInt8]()
        values.reserveCapacity(dataPart.count)
        for ch in dataPart {
            guard let v = charset.firstIndex(of: ch) else {
                throw AdamError.contract("bech32 address has invalid char '\(ch)': \(bech32)")
            }
            values.append(UInt8(v))
        }
        guard verifyChecksum(hrp: hrp, values: values) else {
            throw AdamError.contract("bech32 address checksum failed: \(bech32)")
        }
        let payload = Array(values.dropLast(6))
        return try convertBits(payload, from: 5, to: 8, pad: false)
    }

    /// The 28-byte payment key-hash of a Shelley address: byte 0 is the header
    /// (its high nibble is the address type), bytes 1..28 are the payment
    /// credential. Only a KEY-hash payment credential is accepted (address type
    /// high nibble 0..3 and 6..7 use a key-hash payment part; a script payment
    /// part — types 1,3,5,7 low bit... ) — we require the payment credential to
    /// be a key-hash, which is address types 0,1,2,3,6,7 with an even type bit.
    static func paymentKeyHash(bech32: String) throws -> Data {
        let raw = try rawBytes(bech32: bech32)
        guard raw.count >= 29 else {
            throw AdamError.contract("address too short for a payment credential: \(bech32)")
        }
        let header = raw[raw.startIndex]
        let addressType = header >> 4
        // Payment-part-is-script address types: 0b0001 (1), 0b0011 (3),
        // 0b0111 (7 = script/script), 0b1111... Enterprise script is 0b0111.
        // The payment credential is a key-hash when the low bit of the type is 0
        // for base/pointer/enterprise addresses (types 0,2,4,6). Types 1,3,5,7
        // put a SCRIPT in the payment part.
        let paymentIsScript = (addressType & 0b0001) == 1
        guard !paymentIsScript else {
            throw AdamError.contract("address payment credential is a script, not a key-hash: \(bech32)")
        }
        let base = raw.startIndex + 1
        return Data(raw[base..<base + 28])
    }

    private static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) throws -> Data {
        var acc = 0
        var bits = 0
        var out = [UInt8]()
        let maxv = (1 << to) - 1
        for value in data {
            acc = (acc << from) | Int(value)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxv)) }
        } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
            throw AdamError.contract("bech32 payload has invalid padding")
        }
        return Data(out)
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x01ff_ffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 {
                chk ^= gen[i]
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        return bytes.map { $0 >> 5 } + [0] + bytes.map { $0 & 0x1f }
    }

    private static func verifyChecksum(hrp: String, values: [UInt8]) -> Bool {
        polymod(hrpExpand(hrp) + values) == 1
    }
}
