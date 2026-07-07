# AdamKit

Zero-dependency Swift SDK for embedding ADAM autonomous trading in a partner
wallet. The host wallet keeps custody — AdamKit owns protocol correctness
against the ADAM api-gateway (`/api/v1` REST + `/ws/v1` WebSocket).

```
Host wallet (keys, UI, consent)          AdamKit                    ADAM backend
──────────────────────────────  ───────────────────────────  ──────────────────────
AdamHostSigner                   AdamSession   (login/tokens)  nonce → CIP-30 login
  signAuthChallenge  ──────────▶ AdamRealtime  (WS lifecycle)  sign_required pushes
  witnessTransaction ──────────▶ SigningCoordinator            builds unsigned tx,
TokenStore (Keychain)            ApprovalCoordinator           assembles + submits
                                 GuardProvisioner              on-chain spending guard
                                 BotAPI                        strategy + execution
```

## Custody model

The SDK never sees key material. The host contributes exactly two protocol
implementations:

- **`AdamHostSigner`** — two methods. `signAuthChallenge` signs the login
  challenge text (CIP-30 `signData` semantics). `witnessTransaction` witnesses
  a transaction and may return either a bare vkey witness or a full CIP-30
  witness set (`TransactionWitness.witnessSet`) — the SDK extracts the single
  vkey witness from the set (Conway tag-258 encoding included) and refuses
  ambiguous sets.
- **`TokenStore`** — session token persistence. Back it with the Keychain.

Before any sign request reaches `witnessTransaction`, the SDK independently
re-extracts the transaction body bytes from the CBOR (exact span, no
re-encode) and re-hashes them with blake2b-256; a request whose server-claimed
hash does not match is marked invalid and never surfaces. Hosts should verify
the same hash again after their own decode and sign exactly those bytes —
bind-to-bytes is checked at three independent points (SDK, host wallet,
server assembly).

Autonomous mode delegates nothing from the host: the user witnesses ONE
transaction (the guard deploy, via `GuardProvisioner`), funding an on-chain
spending guard whose per-transaction and rolling daily caps are enforced by
the Cardano ledger. The backend holds only the guard-bounded session key; the
owner can sweep and revoke unilaterally with nothing but their own signature.

## Usage

```swift
let adam = Adam(
    config: AdamConfig(
        baseURL: URL(string: "https://gateway.adam.example")!,
        network: .preprod,
        partnerId: "gero"
    ),
    signer: MyWalletSignerAdapter(),      // implements AdamHostSigner
    tokenStore: MyKeychainTokenStore()    // implements TokenStore
)

// Login: nonce → host signData → JWT (rotated refresh handled internally).
let user = try await adam.session.login(walletAddress: wallet, deviceId: deviceId)

// Realtime + reconciliation. WS delivery is best-effort by contract:
// reconcile over REST on every connect/foreground.
let events = await adam.realtime.start()
for await event in events {
    switch event {
    case .connected:
        for request in try await adam.signing.reconcile() { present(request) }
    case .signRequired:
        if let request = await adam.signing.handle(event) { present(request) }
    default: break
    }
}

// User approves in your UI → host witnesses → SDK submits.
try await adam.signing.approve(request.requestId)

// Guard provisioning (autonomous mode).
let deployment = try await adam.guardProvisioner.requestDeployment(principalAda: 100)
// Decode deployment.provision.unsignedCbor, show the user the principal,
// guard address, and datum; then:
let depositTx = try await adam.guardProvisioner.signAndSubmit(deployment)
let confirmation = try await adam.guardProvisioner.confirm()
_ = try await adam.bot.arm()
```

`/ws/v1` upgrades carry both credentials: the `Authorization: Bearer` header
(passes the gateway's global JWT hook) and `?token=` (validated by the WS
handler). `AdamRealtime` reconnects with exponential backoff and resubscribes;
consume `.connected` / `.reconnecting` / `.disconnected` for lifecycle UI.

## Wire contract

The SDK speaks the subset of the gateway API pinned by
[`packages/sdk-contract`](../sdk-contract): endpoint fixtures captured from a
live gateway, plus cross-language vectors for blake2b, CBOR span-walking,
tx-body extraction/hashing, and witness-set extraction (generated from the
CSL-byte-identity-tested reference signer). The vectors and fixtures are the
source of truth in both CI directions: the gateway's drift test fails when a
change would break a pinned SDK, and AdamKit's tests consume the same files.

Numbers carried in `SignRequest` (`estimatedValueAda`, descriptions,
rationale) are display anchors, not trusted amounts — the transaction bytes
are the only authority, which is why every verification step works on the
CBOR itself.

## Testing

`swift test` (Swift 6.1+, macOS 14+/Linux). Tests are hermetic: HTTP and
WebSocket transports are protocol seams (`HTTPTransport`,
`WebSocketTransport`) with scripted fakes; no network. The same suites run as
CI on Linux (`swift:6.1` container) and macOS via
`.github/workflows/adamkit.yml`, alongside the sdk-contract drift check.

## Gateway prerequisites (Phase 0)

AdamKit is written to the designed contract. Three things must land in
`packages/api-gateway` before it can talk to a production (non-`DEV_MODE`)
gateway — the Phase 0 hardening from the integration plan:

- **Real CIP-30 login verification.** The current `/api/v1/auth/login` verifier
  is demo-grade; it must verify the COSE_Sign1 the SDK's `signAuthChallenge`
  produces against the wallet's key, or login only succeeds under `DEV_MODE`.
- **`partnerId` persistence.** The SDK sends `partnerId` on login; the gateway
  must accept and store it (a `partners` table + `users.partnerId`) for
  attribution to exist. Until then it is silently ignored, harmlessly.
- **Server-side logout.** `logout()` posts the refresh token; the gateway must
  revoke that session even when the access token has expired, or a logged-out
  refresh token stays valid for its full TTL.

These are gateway changes, not SDK changes — AdamKit already speaks the
contract they complete.

## Repo placement

AdamKit lives in this monorepo next to the gateway and the contract artifacts
it is pinned to. SwiftPM requires `Package.swift` at the repository root for
remote dependencies, so partner apps consume it either by vendoring the
`packages/adamkit` directory, or — once a partner needs versioned remote
consumption — via `git subtree split` of this directory into a standalone
repo, which needs no code changes.
