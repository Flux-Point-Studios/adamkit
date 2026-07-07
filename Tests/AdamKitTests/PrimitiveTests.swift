import Foundation
import Testing

@testable import AdamKit

@Suite struct Blake2bTests {
    @Test func matchesReferenceVectors() throws {
        let vectors = try ContractFiles.vector("blake2b.json", as: BlakeVectors.self)
        #expect(vectors.cases.count >= 21)
        for testCase in vectors.cases {
            let input = try Data(hexString: testCase.inputHex)
            let digest = Blake2b.hash(input, digestLength: testCase.digestLength)
            #expect(digest.hexString == testCase.digestHex, "\(testCase.name)")
        }
    }

    @Test func streamingEqualsOneShot() throws {
        let input = (0..<1000).map { UInt8(truncatingIfNeeded: $0) }
        var streaming = Blake2b(digestLength: 32)
        for chunk in input.chunks(ofCount: 7) {
            streaming.update(chunk)
        }
        #expect(streaming.finalize() == Blake2b.hash(input, digestLength: 32))
    }
}

extension Array {
    func chunks(ofCount count: Int) -> [[Element]] {
        stride(from: 0, to: self.count, by: count).map {
            Array(self[$0..<Swift.min($0 + count, self.count)])
        }
    }
}

@Suite struct CBORWalkerTests {
    @Test func validItemsSpanTheirFullEncoding() throws {
        let vectors = try ContractFiles.vector("cbor-items.json", as: CborVectors.self)
        for item in vectors.valid {
            let wrapped = try Data(hexString: "81" + item.cborHex)
            let length = try CBOR.itemLength(wrapped, at: 1)
            #expect(length == item.spanLength, "\(item.name)")
        }
    }

    @Test func invalidItemsThrow() throws {
        let vectors = try ContractFiles.vector("cbor-items.json", as: CborVectors.self)
        for item in vectors.invalid {
            let bytes = try Data(hexString: item.cborHex)
            #expect(throws: CBORError.self, "\(item.name)") {
                _ = try CardanoTx.extractBodyBytes(bytes)
            }
        }
    }

    @Test func truncatedInputThrowsInsteadOfMisreading() throws {
        let vectors = try ContractFiles.vector("cbor-items.json", as: CborVectors.self)
        for item in vectors.truncated {
            let bytes = try Data(hexString: item.cborHex)
            #expect(throws: CBORError.self, "\(item.name)") {
                _ = try CardanoTx.extractBodyBytes(bytes)
            }
        }
    }

    @Test func decoderRoundTripsStructures() throws {
        let doc = try Data(hexString: "a201820203039f0405ff")
        let value = try CBOR.decode(doc)
        guard case let .map(pairs) = value else {
            Issue.record("expected map")
            return
        }
        #expect(pairs.count == 2)
        #expect(pairs[0].key == .unsigned(1))
        #expect(pairs[0].value == .array([.unsigned(2), .unsigned(3)]))
        #expect(pairs[1].key == .unsigned(3))
        #expect(pairs[1].value == .array([.unsigned(4), .unsigned(5)]))
    }

    @Test func decoderRejectsTrailingBytes() throws {
        let doc = try Data(hexString: "0000")
        #expect(throws: CBORError.self) {
            _ = try CBOR.decode(doc)
        }
    }
}

@Suite struct TxBodyTests {
    @Test func extractsExactBodySpanAndHash() throws {
        let vectors = try ContractFiles.vector("tx-body.json", as: TxBodyVectors.self)
        #expect(vectors.cases.count >= 8)
        for testCase in vectors.cases {
            let tx = try Data(hexString: testCase.txHex)
            #expect(try CardanoTx.extractBodyBytes(tx).hexString == testCase.bodyHex, "\(testCase.name)")
            #expect(try CardanoTx.bodyHash(tx).hexString == testCase.bodyHashHex, "\(testCase.name)")
        }
    }
}

@Suite struct WitnessSetTests {
    @Test func extractsVkeyWitnesses() throws {
        let vectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        for testCase in vectors.cases {
            let witnesses = try CardanoTx.vkeyWitnesses(
                inWitnessSet: Data(hexString: testCase.witnessSetHex))
            #expect(witnesses.count == testCase.expected.count, "\(testCase.name)")
            for (extracted, expected) in zip(witnesses, testCase.expected) {
                #expect(extracted.vkeyHex == expected.vkeyHex, "\(testCase.name)")
                #expect(extracted.signatureHex == expected.signatureHex, "\(testCase.name)")
            }
        }
    }

    @Test func setsWithoutVkeysYieldNone() throws {
        let vectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        for testCase in vectors.noVkeyCases {
            let witnesses = try CardanoTx.vkeyWitnesses(
                inWitnessSet: Data(hexString: testCase.witnessSetHex))
            #expect(witnesses.isEmpty, "\(testCase.name)")
        }
    }

    @Test func downgradeRequiresExactlyOneWitness() throws {
        let vectors = try ContractFiles.vector("witness-set.json", as: WitnessSetVectors.self)
        let single = try #require(vectors.cases.first { $0.expected.count == 1 })
        let double = try #require(vectors.cases.first { $0.expected.count == 2 })

        let witness = try TransactionWitness.witnessSet(cborHex: single.witnessSetHex).vkeyWitness()
        #expect(witness.vkeyHex == single.expected[0].vkeyHex)

        #expect(throws: AdamError.witnessCount(2)) {
            _ = try TransactionWitness.witnessSet(cborHex: double.witnessSetHex).vkeyWitness()
        }
        #expect(throws: AdamError.witnessCount(0)) {
            _ = try TransactionWitness.witnessSet(cborHex: "a0").vkeyWitness()
        }
    }
}
