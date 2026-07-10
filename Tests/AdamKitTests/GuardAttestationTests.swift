import Foundation
import Testing

@testable import AdamKit

/// The pinned GuardDatum CBOR conformance vector (asg-wt
/// validators/datum_cbor_conformance_test.ak). A 12-field Constr-0 datum with
/// one AssetCap and a two-record spends list (ADA + token).
private let datumVectorHex =
    "d8799f581c00000000000000000000000000000000000000000000000000000a0a"
    + "581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
    + "581c00000000000000000000000000000000000000000000000000000b0b"
    + "1a01312d001a02faf0801a05265c00"
    + "9fd8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1901f41903e8ffff"
    + "9fd8799f40401b000000e8d4a5fa601a00989680ff"
    + "d8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1b000000e8d4a5fa6019012cffff"
    + "1a004c4b400a1b000001d1a94a2000d87980ff"

/// The FRESH-DEPLOY datum: `datumVectorHex` with the spends list (field 7)
/// emptied — `9f <ADA record> <token record> ff` replaced by `80` (definite
/// empty array). A freshly-deployed guard must have no prior spend records
/// (a seeded record pre-loads the daily-window sum), so the attestation
/// happy-path fixtures use this; only owner/stt/agent/caps/window/minP/
/// maxSpends/expiry/kill are kept, all equal to the vector's values so
/// `matchingConsent()` still matches.
private let freshDeployDatumHex = datumVectorHex.replacingOccurrences(
    of:
        "9fd8799f40401b000000e8d4a5fa601a00989680ff"
        + "d8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1b000000e8d4a5fa6019012cffff",
    with: "80")

private let tokenPolicy = "00000000000000000000000000000000000000000000000000001111"
private let tokenNameHex = "544b4e"  // "TKN"
private let sttPolicy = "5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
private let ownerVkhHex = "00000000000000000000000000000000000000000000000000000a0a"
private let agentVkhHex = "00000000000000000000000000000000000000000000000000000b0b"

/// The owner login address whose payment key-hash equals the datum's `owner`
/// (a preprod base address: header 0x00 + owner VKH + zero stake key-hash).
private let ownerAddressBech32 =
    "addr_test1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5zsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6au4c9"

/// The guard output's value (key 1): `[coin, {sttPolicy: {sttName: 1}}]` — the
/// output carries the STT singleton the on-chain validator governs by, so the
/// pin binds its datum. `82` array(2), coin `1a02faf080`, multiasset `a1` map(1)
/// keyed by the 28-byte STT policy → `a1` map(1) of the 32-byte STT name → qty 1.
private let sttValueHex =
    "821a02faf080a1581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
    + "a15820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01"

/// A realistic deploy tx: `[body, witness_set, is_valid, aux]` where the body's
/// outputs (key 1) are `[guardOutput, changeOutput]`; the guard output pays the
/// bundled PREPROD guard address, carries the STT, and holds the FRESH-DEPLOY
/// inline datum (empty spends).
private let deployTxHex = deployTx(wrapping: freshDeployDatumHex)

/// Same deploy but the datum-bearing output pays a DIFFERENT (non-guard)
/// address — the pin must reject it.
private let deployTxWrongAddrHex = deployTx(
    wrapping: freshDeployDatumHex, guardAddressHex: "71" + String(repeating: "aa", count: 28))

/// The CONSENT-BYPASS attack: two outputs to the (universal) guard address —
/// output A FIRST carries a benign consent-matching datum but only min-ADA (NO
/// STT); output B SECOND carries a MALICIOUS datum (owner = attacker VKH `cc…`)
/// and holds the minted STT + principal. The old address-first selection bound
/// A and passed; the fix binds to the STT-bearing output B and rejects. B's
/// datum is the FRESH-DEPLOY datum with the 28-byte owner field swapped to `cc…`
/// (empty spends, so the ONLY reason it is rejected is the STT-binding owner).
private let maliciousDatumHex = freshDeployDatumHex.replacingOccurrences(
    of: "581c" + ownerVkhHex, with: "581c" + String(repeating: "cc", count: 28))

/// The guard output header + address (map(3), key 0 = 29-byte preprod guard
/// script address) shared by both guard outputs below.
private let guardOutputHead = "a300581d" + preprodGuardAddressHex
/// A bare-lovelace value (key 1, 50 000 000) — an output with NO STT.
private let bareValueHex = "011a02faf080"
/// An inline-datum output field (key 2): `02 8201 d818 <len> <datum>`, length
/// prefix computed from the datum size (single-byte < 256).
private func inlineDatumField(_ datumHex: String) -> String {
    let n = datumHex.count / 2
    let lenPrefix = n < 256 ? "58" + String(format: "%02x", n) : "59" + String(format: "%04x", n)
    return "028201d818" + lenPrefix + datumHex
}
/// The inline-datum field (key 2) wrapping the benign fresh-deploy datum.
private let benignDatumField = inlineDatumField(freshDeployDatumHex)
/// The inline-datum field (key 2) wrapping the malicious datum.
private let maliciousDatumField = inlineDatumField(maliciousDatumHex)
private let changeOutputHex =
    "a20058390000000000000000000000000000000000000000000000000000000a0a00000000000000000000000000000000000000000000000000000000011a00895440"

/// Deploy with TWO guard outputs: A first (benign datum, NO STT), B second
/// (malicious datum, carries the STT). Outputs array has 3 entries (A, B,
/// change). The fix must bind B and reject.
private let deployTxTwoGuardOutputsHex =
    "84a3008001" + "83"
    + guardOutputHead + bareValueHex + benignDatumField
    + guardOutputHead + "01" + sttValueHex + maliciousDatumField
    + changeOutputHex
    + "021a0002bf20a0f5f6"

/// Deploy with a single guard output that has a consent-matching datum but NO
/// STT in any output — nothing for the pin to bind, so it throws.
private let deployTxNoSttHex =
    "84a3008001" + "82"
    + guardOutputHead + bareValueHex + benignDatumField
    + changeOutputHex
    + "021a0002bf20a0f5f6"

/// The consent that exactly matches the vector datum's full config: ADA/token
/// caps, window length, min-principal, max-spends, and expiry.
private func matchingConsent() throws -> TokenCapConsent {
    TokenCapConsent(
        tokens: [
            .init(
                policy: try Data(hexString: tokenPolicy),
                name: try Data(hexString: tokenNameHex),
                perTx: 500, daily: 1000)
        ],
        adaPerTx: 20_000_000,
        adaDaily: 50_000_000,
        windowLen: 86_400_000,
        minPrincipal: 5_000_000,
        maxSpends: 10,
        expiry: 2_000_000_000_000
    )
}

/// The agent gas address the happy-path deploy funds: an enterprise address
/// (`0x60 || keyhash28`) whose payment key-hash equals the vector datum's agent
/// VKH, so the agent-binding check passes.
private func matchingAgentGasAddr() throws -> String {
    try encodeBech32(hrp: "addr_test", data: Data([0x60]) + Data(hexString: agentVkhHex))
}

/// The 29-byte raw address (header + 28-byte credential) of the STT-carrying
/// guard output: the bundled PREPROD guard script address.
private let preprodGuardAddressHex = "70ecb3ce037188879d7fea47aa5e7eb4cbb1e24479816bf439e57acbc6"

/// Wrap an inline-datum hex into a full deploy tx that pays the STT-carrying
/// guard output — the shape `pinAndVerify` attests. Takes an arbitrary
/// (variable-length) datum so a single tampered field can be tested, and an
/// optional guard address so a wrong-address deploy can be built. The
/// inline-datum length prefix is computed from the datum length.
private func deployTx(wrapping datumHex: String, guardAddressHex: String = preprodGuardAddressHex)
    -> String
{
    let datumBytes = datumHex.count / 2
    let lenPrefix = datumBytes < 256 ? "58" + String(format: "%02x", datumBytes)
        : "59" + String(format: "%04x", datumBytes)
    let guardOutput =
        "a300581d" + guardAddressHex + "01"
        + sttValueHex + "028201d818" + lenPrefix + datumHex
    let changeOutput =
        "a20058390000000000000000000000000000000000000000000000000000000a0a"
        + "00000000000000000000000000000000000000000000000000000000011a00895440"
    return "84a3008001" + "82" + guardOutput + changeOutput + "021a0002bf20a0f5f6"
}

@Suite struct GuardDatumDecodeTests {
    @Test func decodesThePinnedVectorFieldForField() throws {
        let datum = try GuardDatum.decode(from: try Data(hexString: datumVectorHex))

        #expect(datum.ownerVkh.hexString == ownerVkhHex)
        #expect(datum.sttPolicy.hexString == sttPolicy)
        #expect(datum.agentVkh.hexString == agentVkhHex)
        #expect(datum.perTxCap == 20_000_000)
        #expect(datum.dailyCap == 50_000_000)
        #expect(datum.windowLen == 86_400_000)
        #expect(datum.minPrincipal == 5_000_000)
        #expect(datum.maxSpends == 10)
        #expect(datum.expiry == 2_000_000_000_000)
        #expect(datum.kill == false)

        #expect(datum.tokenCaps.count == 1)
        let cap = try #require(datum.tokenCaps.first)
        #expect(cap.policy.hexString == tokenPolicy)
        #expect(cap.name.hexString == tokenNameHex)
        #expect(cap.perTx == 500)
        #expect(cap.daily == 1000)

        #expect(datum.spends.count == 2)
        // First spend is the ADA record: empty policy + empty name.
        let ada = datum.spends[0]
        #expect(ada.policy.isEmpty)
        #expect(ada.name.isEmpty)
        #expect(ada.at == 1_000_000_060_000)
        #expect(ada.amount == 10_000_000)
        // Second is the token record.
        let tok = datum.spends[1]
        #expect(tok.policy.hexString == tokenPolicy)
        #expect(tok.name.hexString == tokenNameHex)
        #expect(tok.at == 1_000_000_060_000)
        #expect(tok.amount == 300)
    }

    @Test func decodesEmptyDefiniteConstructorLists() throws {
        // The TRAP: empty token_caps/spends serialise DEFINITE (0x80), and
        // kill=False is the empty constructor d87980. A datum with both lists
        // empty must still decode. Build one field-for-field: owner, stt, agent
        // (28b each), three ints, empty token_caps (80), empty spends (80),
        // three ints, kill=false (d87980).
        let hex =
            "d8799f"
            + "581c" + ownerVkhHex
            + "581c" + sttPolicy
            + "581c" + agentVkhHex
            + "1a01312d00" + "1a02faf080" + "1a05265c00"
            + "80"  // token_caps = [] (definite empty array)
            + "80"  // spends = [] (definite empty array)
            + "1a004c4b40" + "0a" + "1b000001d1a94a2000"
            + "d87980"  // kill = False (empty constructor, definite)
            + "ff"
        let datum = try GuardDatum.decode(from: try Data(hexString: hex))
        #expect(datum.tokenCaps.isEmpty)
        #expect(datum.spends.isEmpty)
        #expect(datum.kill == false)
    }

    @Test func decodesKillTrueConstructor() throws {
        // kill=True is Constr 1 [] = d87a80.
        let hex =
            "d8799f"
            + "581c" + ownerVkhHex + "581c" + sttPolicy + "581c" + agentVkhHex
            + "1a01312d00" + "1a02faf080" + "1a05265c00" + "80" + "80"
            + "1a004c4b40" + "0a" + "1b000001d1a94a2000" + "d87a80" + "ff"
        let datum = try GuardDatum.decode(from: try Data(hexString: hex))
        #expect(datum.kill == true)
    }

    @Test func rejectsAWrongFieldCount() throws {
        // Constr 0 with 11 fields (drop the trailing kill) must throw.
        let truncated = "d8799f" + "581c" + ownerVkhHex + "ff"
        #expect(throws: AdamError.self) {
            _ = try GuardDatum.decode(from: try Data(hexString: truncated))
        }
    }
}

@Suite struct GuardAttestationTests {
    @Test func acceptsADeployMatchingConsent() throws {
        let datum = try GuardAttestation.pinAndVerify(
            deployTx: try Data(hexString: deployTxHex),
            network: .preprod,
            ownerAddress: ownerAddressBech32,
            consent: try matchingConsent(),
            agentGasAddr: try matchingAgentGasAddr()
        )
        #expect(datum.ownerVkh.hexString == ownerVkhHex)
        #expect(datum.tokenCaps.first?.perTx == 500)
    }

    @Test func rejectsADeployWhoseAgentIsNotTheFundedGasKey() throws {
        // The datum's agent is the vector agent VKH; the gas address the deploy
        // funds resolves to a DIFFERENT payment key-hash (all-ff enterprise
        // address). The pin must reject: the AgentSpend-branch session key is not
        // the key the deploy actually seeds with gas.
        let wrongGasAddr = try encodeBech32(
            hrp: "addr_test", data: Data([0x60]) + Data(repeating: 0xff, count: 28))
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod,
                ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(),
                agentGasAddr: wrongGasAddr
            )
        }
    }

    @Test func acceptsADeployWhoseAgentMatchesTheFundedGasKey() throws {
        // Positive side of the agent binding: with a gas address whose payment
        // key-hash equals the datum's agent VKH, attestation passes.
        let datum = try GuardAttestation.pinAndVerify(
            deployTx: try Data(hexString: deployTxHex),
            network: .preprod,
            ownerAddress: ownerAddressBech32,
            consent: try matchingConsent(),
            agentGasAddr: try matchingAgentGasAddr()
        )
        #expect(datum.agentVkh.hexString == agentVkhHex)
    }

    @Test func rejectsASmallerWindowLen() throws {
        // window_len collapsed to 1 (ms): the sliding window is destroyed so the
        // daily cap is defeated — records age out instantly and the agent can
        // spend up to daily_cap on every tx. Consent pins 86_400_000, so reject.
        let tampered = freshDeployDatumHex.replacingOccurrences(of: "1a05265c00", with: "01")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTx(wrapping: tampered)),
                network: .preprod, ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(), agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAHigherExpiry() throws {
        // expiry pushed from 2e12 to 3e12 — a longer autonomy window than
        // consented. Reject.
        let tampered = freshDeployDatumHex.replacingOccurrences(
            of: "1b000001d1a94a2000", with: "1b000002ba7def3000")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTx(wrapping: tampered)),
                network: .preprod, ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(), agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsALowerMinPrincipal() throws {
        // min_principal dropped from 5_000_000 to 1_000_000 — a weaker floor than
        // consented. Reject.
        let tampered = freshDeployDatumHex.replacingOccurrences(of: "1a004c4b40", with: "1a000f4240")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTx(wrapping: tampered)),
                network: .preprod, ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(), agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAPreKilledGuard() throws {
        // kill=true on a fresh deploy (d87980 → d87a80): a guard deployed already
        // dead is not what the owner consented to. Reject.
        let tampered = freshDeployDatumHex.replacingOccurrences(of: "d87980ff", with: "d87a80ff")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTx(wrapping: tampered)),
                network: .preprod, ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(), agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsADeployWithSeededSpends() throws {
        // The seeded-spends attack: a fresh deploy whose spends list is not empty
        // but carries a NEGATIVE ADA record (amount = -1e9). The on-chain
        // `sum_active_for` has no non-negativity guard, so the daily-window sum
        // goes negative and the agent can move daily_cap + 1e9 per window. A fresh
        // guard must have zero prior records, so pinAndVerify must reject. Built
        // from the fresh datum with the empty spends list (`80`) replaced by a
        // one-element list holding SpendRecord{"","",1_000_000_060_000,-1e9}.
        let seeded = freshDeployDatumHex.replacingOccurrences(
            of: "ff801a004c4b40",
            with: "ff81d8799f40401b000000e8d4a5fa603a3b9ac9ffff1a004c4b40")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTx(wrapping: seeded)),
                network: .preprod, ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(), agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func extractsTheInlineDatumForTheGuardOutput() throws {
        let guardRaw = try CardanoAddress.rawBytes(bech32: GuardAttestation.Pin.addressPreprod)
        let sttPolicy = try Data(hexString: GuardAttestation.Pin.sttPolicyId)
        let datumBytes = try CardanoTx.guardOutputDatum(
            try Data(hexString: deployTxHex), guardAddressBytes: guardRaw, sttPolicy: sttPolicy)
        #expect(datumBytes.hexString == freshDeployDatumHex)
    }

    @Test func decodesGuardAddressToThePinnedScriptHash() throws {
        for addr in [GuardAttestation.Pin.addressMainnet, GuardAttestation.Pin.addressPreprod] {
            let raw = try CardanoAddress.rawBytes(bech32: addr)
            #expect(raw.count == 29)
            #expect(raw.suffix(28).hexString == GuardAttestation.Pin.scriptHash)
        }
    }

    @Test func rejectsADeployWhereTheSttOutputHasANonConsentingDatum() throws {
        // The consent-bypass attack: output A (first) pays the guard address a
        // benign consent-matching datum but holds NO STT; output B (second) pays
        // the SAME address a MALICIOUS datum (attacker as owner) and holds the
        // STT the on-chain validator governs by. The pin must bind B and reject,
        // not the benign first output. Without the fix, this deploy PASSES.
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxTwoGuardOutputsHex),
                network: .preprod,
                ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(),
                agentGasAddr: try matchingAgentGasAddr()
            )
        }
    }

    @Test func rejectsADeployWithNoSttOutput() throws {
        // A guard-address output with a consent-matching datum but NO STT in any
        // output: the validator governs no such UTxO, so there is nothing to
        // bind and the pin must reject.
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxNoSttHex),
                network: .preprod,
                ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(),
                agentGasAddr: try matchingAgentGasAddr()
            )
        }
    }

    @Test func rejectsATamperedGuardAddress() throws {
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxWrongAddrHex),
                network: .preprod,
                ownerAddress: ownerAddressBech32,
                consent: try matchingConsent(),
                agentGasAddr: try matchingAgentGasAddr()
            )
        }
    }

    @Test func rejectsAnOwnerThatIsNotMyKey() throws {
        // A different valid enterprise address (payment VKH all-ff): its
        // key-hash cannot match the datum's owner.
        let raw = Data([0x60] + [UInt8](repeating: 0xff, count: 28))
        let bech = try encodeBech32(hrp: "addr_test", data: raw)
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod,
                ownerAddress: bech,
                consent: try matchingConsent(),
                agentGasAddr: try matchingAgentGasAddr()
            )
        }
    }

    @Test func rejectsATokenQuantityMismatch() throws {
        let consent = TokenCapConsent(
            tokens: [
                .init(
                    policy: try Data(hexString: tokenPolicy),
                    name: try Data(hexString: tokenNameHex),
                    perTx: 999, daily: 1000)  // per_tx tampered (datum has 500)
            ],
            adaPerTx: 20_000_000, adaDaily: 50_000_000,
            windowLen: 86_400_000, minPrincipal: 5_000_000, maxSpends: 10, expiry: 2_000_000_000_000)
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod, ownerAddress: ownerAddressBech32, consent: consent,
                agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAnExtraToken() throws {
        let consent = TokenCapConsent(
            tokens: [
                .init(
                    policy: try Data(hexString: tokenPolicy),
                    name: try Data(hexString: tokenNameHex), perTx: 500, daily: 1000),
                .init(
                    policy: try Data(hexString: tokenPolicy),
                    name: try Data(hexString: "beef"), perTx: 1, daily: 2),
            ],
            adaPerTx: 20_000_000, adaDaily: 50_000_000,
            windowLen: 86_400_000, minPrincipal: 5_000_000, maxSpends: 10, expiry: 2_000_000_000_000)
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod, ownerAddress: ownerAddressBech32, consent: consent,
                agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAMissingToken() throws {
        let consent = TokenCapConsent(
            tokens: [], adaPerTx: 20_000_000, adaDaily: 50_000_000,
            windowLen: 86_400_000, minPrincipal: 5_000_000, maxSpends: 10, expiry: 2_000_000_000_000)
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod, ownerAddress: ownerAddressBech32, consent: consent,
                agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAnAdaCapMismatch() throws {
        let consent = TokenCapConsent(
            tokens: [
                .init(
                    policy: try Data(hexString: tokenPolicy),
                    name: try Data(hexString: tokenNameHex), perTx: 500, daily: 1000)
            ],
            adaPerTx: 1, adaDaily: 50_000_000,  // ADA per-tx tampered
            windowLen: 86_400_000, minPrincipal: 5_000_000, maxSpends: 10, expiry: 2_000_000_000_000)
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: deployTxHex),
                network: .preprod, ownerAddress: ownerAddressBech32, consent: consent,
                agentGasAddr: try matchingAgentGasAddr())
        }
    }

    @Test func rejectsAWrongSttPolicy() throws {
        // Swap the datum's stt_policy field bytes for a different policy: the
        // pin must reject a guard that does not bind the bundled STT.
        let tampered = deployTxHex.replacingOccurrences(
            of: sttPolicy, with: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        #expect(throws: AdamError.self) {
            _ = try GuardAttestation.pinAndVerify(
                deployTx: try Data(hexString: tampered),
                network: .preprod, ownerAddress: ownerAddressBech32, consent: try matchingConsent(),
                agentGasAddr: try matchingAgentGasAddr())
        }
    }
}

/// Minimal bech32 encoder for building test addresses (not shipped in the SDK,
/// which only ever DECODES addresses).
private func encodeBech32(hrp: String, data: Data) throws -> String {
    let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    func convertBits(_ bytes: [UInt8], from: Int, to: Int) -> [UInt8] {
        var acc = 0
        var bits = 0
        var out = [UInt8]()
        let maxv = (1 << to) - 1
        for b in bytes {
            acc = (acc << from) | Int(b)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxv)) }
        return out
    }
    func polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = (chk & 0x01ff_ffff) << 5 ^ UInt32(v)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 { chk ^= gen[i] }
        }
        return chk
    }
    func hrpExpand(_ s: String) -> [UInt8] {
        let b = Array(s.utf8)
        return b.map { $0 >> 5 } + [0] + b.map { $0 & 0x1f }
    }
    let data5 = convertBits([UInt8](data), from: 8, to: 5)
    let pm = polymod(hrpExpand(hrp) + data5 + [0, 0, 0, 0, 0, 0]) ^ 1
    let checksum = (0..<6).map { UInt8((pm >> (5 * (5 - $0))) & 0x1f) }
    return hrp + "1" + String((data5 + checksum).map { charset[Int($0)] })
}
