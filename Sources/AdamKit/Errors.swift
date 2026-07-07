import Foundation

/// Every failure AdamKit surfaces to the host app.
public enum AdamError: Error, Sendable, Equatable {
    /// The gateway returned its error envelope. `code` is the stable contract
    /// key (e.g. `SIGN_REQUEST_NOT_FOUND`); `message` is human-readable and
    /// may change without notice.
    case api(code: String, message: String, statusCode: Int)
    /// The response was not the shape the contract fixtures pin.
    case contract(String)
    case transport(String)
    case notAuthenticated
    /// The recomputed blake2b-256 of the transaction body did not match the
    /// hash the server claimed. The request must never be shown or signed.
    case bodyHashMismatch(requestId: String)
    /// A witness set contained zero or more than one vkey witness, so it
    /// cannot be downgraded to the gateway's single-witness form.
    case witnessCount(Int)
    case invalidHex(String)
    case cbor(CBORError)
    /// The WebSocket is not connected (send attempted while disconnected).
    case realtimeDisconnected
}

/// CBOR structural failures. The walker is strict: reads past the end of the
/// input are `truncated`, never silently misread.
public enum CBORError: Error, Sendable, Equatable {
    case truncated
    case invalidAdditionalInfo(UInt8)
    case unexpectedBreak
    case topLevelNotArray
    case unsupportedShape(String)
}
