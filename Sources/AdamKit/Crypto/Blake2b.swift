import Foundation

/// BLAKE2b (RFC 7693), unkeyed, digest lengths 1...64. Cardano hashes with it
/// everywhere AdamKit needs a hash: tx body (32) and credentials (28).
/// Verified byte-for-byte against the sdk-contract blake2b vectors, which are
/// generated from the same library the reference signer uses.
public struct Blake2b: Sendable {
    private static let iv: [UInt64] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt64]
    private var buffer = [UInt8]()
    private var counter: UInt64 = 0
    private let digestLength: Int

    public init(digestLength: Int) {
        precondition((1...64).contains(digestLength), "digest length must be 1...64")
        self.digestLength = digestLength
        h = Self.iv
        h[0] ^= 0x0101_0000 ^ UInt64(digestLength)
    }

    public mutating func update(_ input: some Sequence<UInt8>) {
        for byte in input {
            if buffer.count == 128 {
                counter &+= 128
                compress(isLast: false)
                buffer.removeAll(keepingCapacity: true)
            }
            buffer.append(byte)
        }
    }

    public mutating func finalize() -> Data {
        counter &+= UInt64(buffer.count)
        while buffer.count < 128 { buffer.append(0) }
        compress(isLast: true)
        var out = [UInt8]()
        out.reserveCapacity(digestLength)
        for i in 0..<digestLength {
            out.append(UInt8(truncatingIfNeeded: h[i / 8] >> (8 * UInt64(i % 8))))
        }
        return Data(out)
    }

    public static func hash(_ input: some Sequence<UInt8>, digestLength: Int) -> Data {
        var state = Blake2b(digestLength: digestLength)
        state.update(input)
        return state.finalize()
    }

    private mutating func compress(isLast: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            var word: UInt64 = 0
            for j in (0..<8).reversed() {
                word = word << 8 | UInt64(buffer[i * 8 + j])
            }
            m[i] = word
        }

        var v = h + Self.iv
        v[12] ^= counter
        // v[13] carries the high half of the 128-bit counter; inputs this SDK
        // hashes are far below 2^64 bytes, so it stays untouched.
        if isLast { v[14] = ~v[14] }

        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotr(v[d] ^ v[a], 32)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 63)
        }

        for round in 0..<12 {
            let s = Self.sigma[round % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    private func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }
}
