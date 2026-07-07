import Foundation
import Testing

@testable import AdamKit

/// Loads the committed wire-contract artifacts from packages/sdk-contract.
/// AdamKit is pinned to them: if the gateway or reference signer changes them,
/// the drift test fails over there and these tests fail over here.
enum ContractFiles {
    static var root: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // AdamKitTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // adamkit
            .appendingPathComponent("sdk-contract")
    }

    static func vector<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        let url = root.appendingPathComponent("vectors").appendingPathComponent(name)
        return try JSONDecoder().decode(type, from: Data(contentsOf: url))
    }

    static func fixture(_ name: String) throws -> EndpointFixture {
        let url =
            root
            .appendingPathComponent("fixtures/current")
            .appendingPathComponent("\(name).json")
        return try JSONDecoder().decode(EndpointFixture.self, from: Data(contentsOf: url))
    }
}

struct EndpointFixture: Decodable {
    struct Request: Decodable {
        let method: String
        let url: String
    }
    struct Response: Decodable {
        let statusCode: Int
        let body: JSONValue
    }
    let request: Request
    let response: Response
}

struct BlakeVectors: Decodable {
    struct Case: Decodable {
        let name: String
        let inputHex: String
        let digestLength: Int
        let digestHex: String
    }
    let cases: [Case]
}

struct CborVectors: Decodable {
    struct Valid: Decodable {
        let name: String
        let cborHex: String
        let spanLength: Int
    }
    struct Invalid: Decodable {
        let name: String
        let cborHex: String
    }
    let valid: [Valid]
    let invalid: [Invalid]
    let truncated: [Invalid]
}

struct TxBodyVectors: Decodable {
    struct Case: Decodable {
        let name: String
        let txHex: String
        let bodyHex: String
        let bodyHashHex: String
    }
    let cases: [Case]
}

struct WitnessSetVectors: Decodable {
    struct Expected: Decodable {
        let vkeyHex: String
        let signatureHex: String
    }
    struct Case: Decodable {
        let name: String
        let witnessSetHex: String
        let expected: [Expected]
    }
    struct NoVkeyCase: Decodable {
        let name: String
        let witnessSetHex: String
    }
    let cases: [Case]
    let noVkeyCases: [NoVkeyCase]
}
