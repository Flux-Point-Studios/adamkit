import Foundation

extension Data {
    init(hexString: String) throws {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { throw AdamError.invalidHex(hexString) }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        func nibble(_ c: UInt8) throws -> UInt8 {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            case 0x41...0x46: return c - 0x41 + 10
            default: throw AdamError.invalidHex(hexString)
            }
        }
        var i = 0
        while i < chars.count {
            bytes.append(try nibble(chars[i]) << 4 | nibble(chars[i + 1]))
            i += 2
        }
        self.init(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
