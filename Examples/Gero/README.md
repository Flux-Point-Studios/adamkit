# Gero integration adapters

Reference host adapters for embedding AdamKit in **gero-ios**. Copy these three
files into the app and implement one protocol — `GeroWalletBridge` — against
Gero's existing CIP-30 / signing internals. Everything else (login, token
refresh, WebSocket lifecycle, bind-to-bytes verification, tx assembly) is handled
inside AdamKit.

| File | What it is | What you do |
|------|-----------|-------------|
| `GeroHostSigner.swift` | Adapts `GeroWalletBridge` → AdamKit's `AdamHostSigner` | Implement `GeroWalletBridge` (2 methods) |
| `KeychainTokenStore.swift` | Complete Keychain-backed `TokenStore` | Use as-is |
| `AdamIntegration.swift` | Wiring + the four app flows | Adapt the presentation hooks to your UI |

## 1. Implement `GeroWalletBridge`

```swift
struct GeroBridge: GeroWalletBridge {
    func signData(addressBech32: String, payloadHex: String) async throws -> (signatureHex: String, keyHex: String) {
        // Gero's CIP-30 signData(address, payload). Return the COSE_Sign1 hex and
        // the COSE_Key hex it produces — this is what makes login address-bound.
    }

    func witnessTransaction(unsignedTxCborHex: String, expectedBodyHashHex: String) async throws -> GeroWitness {
        // Decode the tx, recompute blake2b-256 of the BODY, confirm it equals
        // expectedBodyHashHex, present the effect to the user, then witness with
        // the payment key. Return .vkey(...) or .witnessSet(cborHex:).
    }
}
```

That's the entire custody seam. AdamKit never sees key material.

## 2. Wire it up

```swift
let adam = AdamIntegration.make(
    baseURL: URL(string: "https://gateway.adam.example")!,
    network: .preprod,               // .mainnet for production
    wallet: GeroBridge()             // Keychain TokenStore is the default on iOS
)
let flow = AdamFlow(adam)
```

## 3. Drive the flows

```swift
let user = try await flow.login(walletAddress: wallet, deviceId: deviceId)

// Long-lived task: present each verified sign-request in your UI.
Task { await flow.runRealtime { request in present(request) } }

// User approves → host witnesses → SDK submits.
try await flow.approve(request.requestId)

// Autonomous mode: user witnesses ONE guard-deploy tx, then the bot trades 24/7
// within on-chain per-tx + daily caps (owner can sweep + revoke unilaterally).
try await flow.enableAutonomous(principalAda: 100)
```

## Security: bind-to-bytes

The transaction bytes are the only authority — `SignRequest.description` /
`estimatedValueAda` are display anchors, not trusted amounts. AdamKit re-extracts
the tx-body span and re-hashes it (blake2b-256) before a request ever reaches
your bridge, and drops any request whose server-claimed hash doesn't match. In
`witnessTransaction`, verify `expectedBodyHashHex` **again** after your own decode
and sign exactly those bytes — bind-to-bytes is checked at three independent
points (SDK, wallet, server assembly).

Login uses cip8 (CIP-30 `signData`): the gateway binds the signing key to the
claimed wallet address (COSE address header + the key hashing to the address
credential), so a login can't be spoofed for a wallet you don't control.

## Consuming the SDK

AdamKit ships as a standalone SwiftPM package (a `git subtree split` of
`packages/adamkit`). Add it as a dependency:

```swift
.package(url: "https://github.com/<org>/adamkit.git", from: "0.1.0")
```

then `import AdamKit`. These `Examples/Gero` files are **not** part of the
`AdamKit` product — copy them into your app; they conform your wallet to the SDK.
