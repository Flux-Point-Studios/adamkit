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

// Guard provisioning (autonomous mode). `consent` is the TokenCapConsent the
// user approved in your caps sheet — it is sent to the server (which builds
// the guard with exactly those caps) AND independently attested against the
// returned deploy's on-chain datum; any mismatch throws before witnessing.
let deployment = try await adam.guardProvisioner.requestDeployment(
    principalAda: 100, consent: consent)
// Render deployment.consentSummary (the SDK-attested caps) to the user; then:
let depositTx = try await adam.guardProvisioner.signAndSubmit(deployment)
let confirmation = try await adam.guardProvisioner.confirm(deployment)
_ = try await adam.bot.arm()
```

`/ws/v1` upgrades carry both credentials: the `Authorization: Bearer` header
(passes the gateway's global JWT hook) and `?token=` (validated by the WS
handler). `AdamRealtime` reconnects with exponential backoff and resubscribes;
consume `.connected` / `.reconnecting` / `.disconnected` for lifecycle UI.

## Wire contract

The SDK speaks the subset of the gateway API pinned by the `sdk-contract`
package (in the ADAM monorepo): endpoint fixtures captured from a live gateway,
plus cross-language vectors for blake2b, CBOR span-walking, tx-body
extraction/hashing, and witness-set extraction (generated from the
CSL-byte-identity-tested reference signer). Those vectors and fixtures are
bundled here under `Tests/AdamKitTests/Resources/contract` and are the source
of truth in both CI directions: the gateway's drift test fails when a change
would break a pinned SDK, and AdamKit's tests consume the same files.

Numbers carried in `SignRequest` (`estimatedValueAda`, descriptions,
rationale) are display anchors, not trusted amounts — the transaction bytes
are the only authority, which is why every verification step works on the
CBOR itself.

## Testing

`swift test` (Swift 6.1+, macOS 14+/Linux). Tests are hermetic: HTTP and
WebSocket transports are protocol seams (`HTTPTransport`,
`WebSocketTransport`) with scripted fakes; no network. CI runs the suite in a
`swift:6.1` container (the `adamkit-swift-test` step in `.woodpecker.yml`);
the sdk-contract drift check runs in the same pipeline via `pnpm -r run test`.

## Gateway prerequisites (Phase 0)

AdamKit is written to the designed contract; the Phase 0 gateway hardening it
depends on now lives in `packages/api-gateway`:

- **Real CIP-30 login verification** (`src/lib/cip8-verify.ts`) — verifies the
  COSE_Sign1 the SDK's `signAuthChallenge` produces, binding the key to the
  claimed address. The demo hash-substring fallback is deleted.
- **`partnerId` persistence** — a `partners` table + `users.partnerId`; login
  provisions a partner's users at the partner's `defaultTier` and records
  attribution. `partnerId` confers no privileges beyond that tier.
- **Server-side logout** — `logout()` revokes the session by refresh-token
  possession, so a logged-out token is invalidated even with an expired access
  token.

## Repo placement

AdamKit lives in this monorepo next to the gateway and the contract artifacts
it is pinned to. SwiftPM requires `Package.swift` at the repository root for
remote dependencies, so partner apps consume it either by vendoring the
`packages/adamkit` directory, or — once a partner needs versioned remote
consumption — via `git subtree split` of this directory into a standalone
repo, which needs no code changes.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). `SPDX-License-Identifier: Apache-2.0`.
Copyright 2026 Flux Point Studios.
