# Aviato Pilot's License — Overview

A high-level map of how the four SDKs in this repo fit together. For the cryptographic details see [`whitepaper.md`](./whitepaper.md); for client integration see [`getting-started.md`](./getting-started.md).

## Roles in one picture

```
                ┌──────────────────┐
                │      User        │
                │  (passkey + M)   │
                └────────┬─────────┘
                         │ signs cert, assertions, revocations with M
                         │ (M decrypted on device only)
                         ▼
                ┌──────────────────┐         relays sealed bundles
                │   Aviato Tower   │◄────────── opaque to Tower ──────┐
                │   (pilot-tower)  │                                  │
                │                  │  registers servers; resolves     │
                │                  │  8-digit pairing codes; stores   │
                │                  │  encrypted vault + signed        │
                │                  │  ServerConnInfo rows             │
                └────┬─────────┬───┘                                  │
                     │         │                                      │
              pair   │         │   pair                               │
                     ▼         ▼                                      │
        ┌──────────────────┐ ┌──────────────────┐                     │
        │   Client app     │ │   Media server   │                     │
        │  (pilot-client)  │ │  (pilot-server)  │                     │
        │  Cn keypair      │ │  S keypair + K   │                     │
        └────────┬─────────┘ └────────┬─────────┘                     │
                 │                    │                               │
                 │ cert-auth sign-in (challenge + Cn-signed assertion)│
                 └──────────────► direct, no Tower in the loop ───────┘
```

## Package responsibilities

| Package | Audience | What it owns |
|---|---|---|
| [`pilot-core`](../packages/core) | every SDK | Zod schemas, JCS, sealedbox, Ed25519 / X25519 / AES-GCM helpers, cert + assertion + conn-info + revocation builders and verifiers. **The wire contract.** |
| [`pilot-client-sdk`](../packages/client-sdk) | client apps | `AviatoPilotClient`: pair → hydrate → sign-in → renew → subscribe. `IdentityStorage` backends (LocalStorage, SubtleCrypto/IndexedDB, Memory). |
| [`pilot-client-react`](../packages/client-react) | React consumers | `<PilotProvider>`, `usePilotConnections`, `usePilotConnection`, `usePilotIdentity`, `usePairing`, `useSignInToServer`, `useSignOut`. Backed by `useSyncExternalStore`. |
| [`pilot-server-sdk`](../packages/server-sdk) | media-server hosts | `PairingService`, cert-auth verifier, `ConnInfoPublisher`, persistence-agnostic store interfaces. |
| [`pilot-tower-sdk`](../packages/tower-sdk) | Tower web | Vault encrypt / decrypt, passkey-PRF wrap helpers, master-signed assertion + cert builders. Pure crypto, zero HTTP. |

## Flows

### Vault creation (Tower web, first sign-up)

```
Browser                                Tower
   │  POST /auth/register/begin            │
   │ ────────────────────────────────────►  │  issues prfSalt + WebAuthn challenge
   │ ◄────────────────────────────────────  │
   │  WebAuthn create() → PRF output       │
   │  generate M, VK; encrypt vault;       │
   │  HKDF(PRF, "aviato-vault-wrap/v1");   │
   │  wrap VK; encrypt vault payload       │
   │  POST /auth/register/complete         │
   │  + POST /identity/vault/init          │
   │ ────────────────────────────────────►  │  stores ciphertext + wraps
```

Tower stores opaque ciphertext + per-passkey wrapped VK copies. Plaintext M only exists in browser memory.

### Server-link pairing

```
Media server                Tower                       User (browser)
    │  POST /pairing/register   │                              │
    │ ────────────────────────►  │  returns code + requestId    │
    │ ◄────────────────────────  │                              │
    │  display 8-digit code OR open https://tower.aviato.media/pair?code=… │
    │                            │                              │
    │                            │  user taps passkey, unwraps VK
    │                            │  GET /identity/code/:code/resolve
    │                            │ ◄──────────────────────────  │
    │                            │  → {serverPubKey, serverName, scope}
    │                            │                              │
    │                            │  sign server-link assertion with M
    │                            │  POST /identity/code/:code/complete
    │                            │ ◄──────────────────────────  │
    │  poll /pairing/:requestId  │                              │
    │ ────────────────────────►  │  returns signedAssertion     │
    │ ◄────────────────────────  │                              │
    │  verify M.pub sig          │                              │
    │  generate per-user K; build PairingResponse: sealedbox(K → user X25519) + Ed25519 sig │
    │  POST /pairing/:requestId/response                        │
    │ ────────────────────────►  │                              │
    │                            │  ◄── user fetches response   │
    │                            │  verifies server sig         │
    │                            │  opens sealedbox; writes vault.servers[] (K, serverPubKey, …)
```

After this leg, the user's vault knows `(serverPubKey, K, serverName)` for the new server.

### Client-pair (third-party app)

```
Client app                  Tower                       User (browser)
    │  generate Cn (Ed25519 + X25519)                            │
    │  POST /api/identity/clients/pair/begin                    │
    │ ────────────────────────►  │  returns {requestId, code, expiresAt} │
    │  display code or open ${towerWebUrl}/pair?code=…          │
    │                            │  user opens Tower, taps passkey
    │                            │  consent screen: review appId, pick servers
    │                            │                              │
    │                            │  buildClientPairCert (sign with M)
    │                            │  buildClientPairBundle: each chosen server's K
    │                            │  sealedboxed to Cn.encPubKey
    │                            │  Tower stores completed request
    │                            │                              │
    │  GET /api/identity/clients/pair/:requestId  (poll)        │
    │ ◄────────────────────────  │  cert + sealed K bundles     │
    │  open each sealed K with Cn.encPrivKey; store (cert, serverPubKey, K) │
```

The cert never embeds the server list — the bundle is delivered alongside.

### Cert-auth sign-in (per server, no Tower involved)

```
Client (with cert + K)               Media server
    │  fetch ServerConnInfoRecord from Tower / well-known
    │  verify Tower-sig and server-sig against serverPubKey
    │  AES-GCM decrypt under K, AAD = "aviato-server-conninfo-v1" ‖ pubKeyHex ‖ u64BE(version)
    │  → {publicHost, port, protocol}
    │
    │  POST /auth/identity-session/begin { cert }
    │ ────────────────────────────────────────────►  │  validates cert, returns challenge
    │ ◄────────────────────────────────────────────  │
    │  sign session assertion with Cn over JCS({cert, challenge, serverId, ts})
    │  POST /auth/identity-session/complete
    │ ────────────────────────────────────────────►  │  verifies; returns sessionToken
    │ ◄────────────────────────────────────────────  │
```

The cert-auth complete response can carry an optional `refreshedConnInfoKey` (a `SessionConnInfoEnvelope` sealed to `Cn.encPub`) that re-delivers the current `K`, so K rotations propagate automatically without re-pairing. Unlike the initial pairing-response leg, this envelope is smaller — it carries only `{v, connInfoKey, issuedAtSec}` (no `serverPubKey`) since cert-auth has already established the server's identity.

## Wire-contract guarantees

The byte format is what keeps these three implementations interoperable:

- All canonical JSON uses [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) JCS via the `canonicalize` npm package.
- All public keys are 64-char lowercase hex on the wire (`HEX_32` regex in `pilot-core/src/schemas`).
- All signatures, ciphertexts, and sealed bytes are base64url-no-pad.
- Sealedbox: X25519 ECDH → HKDF-SHA256, info `"aviato-sealedbox-v1"` → AES-GCM-256 (12-byte random nonce, 16-byte tag).
- Vault wrap: HKDF-SHA256, info `"aviato-vault-wrap/v1"`, key derived from the WebAuthn PRF output.
- Conn-info AEAD AAD: `"aviato-server-conninfo-v1"` ‖ utf8(serverPubKey hex) ‖ u64BE(version).
- The integration test at `packages/integration-tests/__tests__/full-handshake.test.ts` exercises Tower → server → client in one suite. If it stays green, the four packages stay in protocol sync.

## What lives where

| Concern | Package | Path |
|---|---|---|
| Crypto primitives | `pilot-core` | `src/crypto/` |
| Wire schemas | `pilot-core` | `src/schemas/` |
| Cert build / verify | `pilot-core` | `src/cert/` |
| Assertion build / verify | `pilot-core` | `src/assertions/` |
| Conn-info seal / AAD / publish-sig | `pilot-core` | `src/conn-info/` |
| Revocation build / verify | `pilot-core` | `src/revocation/` |
| `AviatoPilotClient` orchestrator | `pilot-client-sdk` | `src/identity-client.ts` |
| Storage backends | `pilot-client-sdk` | `src/storage.ts`, `src/subtle-crypto-storage.ts` |
| React hooks and provider | `pilot-client-react` | `src/hooks.ts`, `src/context.tsx` |
| Pairing service | `pilot-server-sdk` | `src/pairing.ts` |
| Conn-info publisher | `pilot-server-sdk` | `src/conn-info-publisher.ts` |
| Cert-auth verifier | `pilot-server-sdk` | `src/cert-auth.ts`, `src/verify.ts` |
| Vault crypto + PRF | `pilot-tower-sdk` | `src/vault.ts`, `src/prf.ts` |
| Master-signing helpers | `pilot-tower-sdk` | `src/assertions.ts`, `src/client-pair.ts`, `src/pairing-response.ts` |

## See also

- [`whitepaper.md`](./whitepaper.md) — deeper dive into primitives, key model, threat model.
- [`getting-started.md`](./getting-started.md) — quickstart for client-app integrators.
- [`../packages/client-sdk/README.md`](../packages/client-sdk/README.md) — full client SDK reference.
