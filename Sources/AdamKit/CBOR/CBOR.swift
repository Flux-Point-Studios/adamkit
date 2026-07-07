import Foundation

/// A decoded CBOR item. Only the shapes Cardano wire structures use; anything
/// else fails loudly rather than being guessed at.
public indirect enum CBORValue: Sendable, Equatable {
    case unsigned(UInt64)
    /// Negative integer encoded as -1 - argument.
    case negative(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([(key: CBORValue, value: CBORValue)])
    case tagged(UInt64, CBORValue)
    case boolean(Bool)
    case null
    case undefined
    case simple(UInt8)
    case float(Double)

    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case let (.unsigned(a), .unsigned(b)): return a == b
        case let (.negative(a), .negative(b)): return a == b
        case let (.bytes(a), .bytes(b)): return a == b
        case let (.text(a), .text(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.map(a), .map(b)):
            return a.count == b.count
                && zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
        case let (.tagged(t1, v1), .tagged(t2, v2)): return t1 == t2 && v1 == v2
        case let (.boolean(a), .boolean(b)): return a == b
        case (.null, .null), (.undefined, .undefined): return true
        case let (.simple(a), .simple(b)): return a == b
        case let (.float(a), .float(b)): return a == b
        default: return false
        }
    }
}

/// Strict CBOR reader: a span walker (the byte length of the item at an
/// offset, so original bytes can be sliced without re-encoding) and a value
/// decoder. Matches the reference TS walker byte-for-byte on valid input and
/// throws `.truncated` where JS out-of-range indexing would misread.
public enum CBOR {
    struct Header {
        let major: UInt8
        let headerBytes: Int
        let arg: UInt64
        let indefinite: Bool
    }

    static func readHeader(_ bytes: Data, _ offset: Int) throws -> Header {
        guard offset < bytes.count else { throw CBORError.truncated }
        let first = bytes[bytes.startIndex + offset]
        let major = first >> 5
        let ai = first & 0x1f
        func wide(_ count: Int) throws -> UInt64 {
            guard offset + count < bytes.count else { throw CBORError.truncated }
            var arg: UInt64 = 0
            for i in 1...count {
                arg = arg << 8 | UInt64(bytes[bytes.startIndex + offset + i])
            }
            return arg
        }
        switch ai {
        case 0..<24: return Header(major: major, headerBytes: 1, arg: UInt64(ai), indefinite: false)
        case 24: return Header(major: major, headerBytes: 2, arg: try wide(1), indefinite: false)
        case 25: return Header(major: major, headerBytes: 3, arg: try wide(2), indefinite: false)
        case 26: return Header(major: major, headerBytes: 5, arg: try wide(4), indefinite: false)
        case 27: return Header(major: major, headerBytes: 9, arg: try wide(8), indefinite: false)
        case 31: return Header(major: major, headerBytes: 1, arg: 0, indefinite: true)
        default: throw CBORError.invalidAdditionalInfo(ai)
        }
    }

    private static func byteAt(_ bytes: Data, _ offset: Int) throws -> UInt8 {
        guard offset < bytes.count else { throw CBORError.truncated }
        return bytes[bytes.startIndex + offset]
    }

    /// Total byte length of the item starting at `offset`.
    public static func itemLength(_ bytes: Data, at offset: Int) throws -> Int {
        let h = try readHeader(bytes, offset)
        switch h.major {
        case 0, 1:
            return h.headerBytes
        case 7:
            if h.indefinite { throw CBORError.unexpectedBreak }
            return h.headerBytes
        case 2, 3:
            if !h.indefinite {
                let len = h.headerBytes + Int(h.arg)
                guard offset + len <= bytes.count else { throw CBORError.truncated }
                return len
            }
            var len = h.headerBytes
            while try byteAt(bytes, offset + len) != 0xff {
                len += try itemLength(bytes, at: offset + len)
            }
            return len + 1
        case 4:
            var len = h.headerBytes
            if h.indefinite {
                while try byteAt(bytes, offset + len) != 0xff {
                    len += try itemLength(bytes, at: offset + len)
                }
                return len + 1
            }
            for _ in 0..<h.arg {
                len += try itemLength(bytes, at: offset + len)
            }
            return len
        case 5:
            var len = h.headerBytes
            if h.indefinite {
                while try byteAt(bytes, offset + len) != 0xff {
                    len += try itemLength(bytes, at: offset + len)
                    len += try itemLength(bytes, at: offset + len)
                }
                return len + 1
            }
            for _ in 0..<h.arg {
                len += try itemLength(bytes, at: offset + len)
                len += try itemLength(bytes, at: offset + len)
            }
            return len
        default: // major 6
            return h.headerBytes + (try itemLength(bytes, at: offset + h.headerBytes))
        }
    }

    /// Decode the single item at `offset`, returning it and the offset just
    /// past its end.
    public static func decodeItem(_ bytes: Data, at offset: Int) throws -> (CBORValue, Int) {
        let h = try readHeader(bytes, offset)
        let payloadStart = offset + h.headerBytes

        func slice(_ start: Int, _ count: Int) throws -> Data {
            guard start + count <= bytes.count else { throw CBORError.truncated }
            let base = bytes.startIndex + start
            return Data(bytes[base..<base + count])
        }

        switch h.major {
        case 0:
            return (.unsigned(h.arg), payloadStart)
        case 1:
            return (.negative(h.arg), payloadStart)
        case 2, 3:
            var data: Data
            var end: Int
            if h.indefinite {
                data = Data()
                end = payloadStart
                while try byteAt(bytes, end) != 0xff {
                    let chunk = try readHeader(bytes, end)
                    guard chunk.major == h.major, !chunk.indefinite else {
                        throw CBORError.unsupportedShape("mixed chunk in indefinite string")
                    }
                    data.append(try slice(end + chunk.headerBytes, Int(chunk.arg)))
                    end += chunk.headerBytes + Int(chunk.arg)
                }
                end += 1
            } else {
                data = try slice(payloadStart, Int(h.arg))
                end = payloadStart + Int(h.arg)
            }
            if h.major == 2 { return (.bytes(data), end) }
            guard let text = String(data: data, encoding: .utf8) else {
                throw CBORError.unsupportedShape("non-UTF8 text string")
            }
            return (.text(text), end)
        case 4:
            var items = [CBORValue]()
            var cursor = payloadStart
            if h.indefinite {
                while try byteAt(bytes, cursor) != 0xff {
                    let (item, next) = try decodeItem(bytes, at: cursor)
                    items.append(item)
                    cursor = next
                }
                return (.array(items), cursor + 1)
            }
            for _ in 0..<h.arg {
                let (item, next) = try decodeItem(bytes, at: cursor)
                items.append(item)
                cursor = next
            }
            return (.array(items), cursor)
        case 5:
            var pairs = [(key: CBORValue, value: CBORValue)]()
            var cursor = payloadStart
            if h.indefinite {
                while try byteAt(bytes, cursor) != 0xff {
                    let (key, afterKey) = try decodeItem(bytes, at: cursor)
                    let (value, afterValue) = try decodeItem(bytes, at: afterKey)
                    pairs.append((key, value))
                    cursor = afterValue
                }
                return (.map(pairs), cursor + 1)
            }
            for _ in 0..<h.arg {
                let (key, afterKey) = try decodeItem(bytes, at: cursor)
                let (value, afterValue) = try decodeItem(bytes, at: afterKey)
                pairs.append((key, value))
                cursor = afterValue
            }
            return (.map(pairs), cursor)
        case 6:
            let (inner, end) = try decodeItem(bytes, at: payloadStart)
            return (.tagged(h.arg, inner), end)
        default: // major 7
            if h.indefinite { throw CBORError.unexpectedBreak }
            switch h.headerBytes {
            case 1, 2:
                switch h.arg {
                case 20: return (.boolean(false), payloadStart)
                case 21: return (.boolean(true), payloadStart)
                case 22: return (.null, payloadStart)
                case 23: return (.undefined, payloadStart)
                default: return (.simple(UInt8(truncatingIfNeeded: h.arg)), payloadStart)
                }
            case 3:
                return (.float(halfToDouble(UInt16(truncatingIfNeeded: h.arg))), payloadStart)
            case 5:
                return (.float(Double(Float(bitPattern: UInt32(truncatingIfNeeded: h.arg)))), payloadStart)
            default:
                return (.float(Double(bitPattern: h.arg)), payloadStart)
            }
        }
    }

    /// Decode a complete document: exactly one item spanning all input.
    public static func decode(_ bytes: Data) throws -> CBORValue {
        let (value, end) = try decodeItem(bytes, at: 0)
        guard end == bytes.count else {
            throw CBORError.unsupportedShape("trailing bytes after CBOR item")
        }
        return value
    }

    private static func halfToDouble(_ half: UInt16) -> Double {
        let sign = Double((half >> 15) & 1) == 0 ? 1.0 : -1.0
        let exponent = Int((half >> 10) & 0x1f)
        let mantissa = Double(half & 0x3ff)
        switch exponent {
        case 0: return sign * mantissa * pow(2, -24)
        case 31: return mantissa == 0 ? sign * .infinity : .nan
        default: return sign * (1 + mantissa / 1024) * pow(2, Double(exponent - 15))
        }
    }
}
