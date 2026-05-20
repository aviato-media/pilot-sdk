# Aviato Pilot's License — Whitepaper

Status: design baseline. This document supersedes the older `docs/specs/aviato-identity-*.md` design notes.

## 1. Goals

Aviato Pilot's License is a privacy-preserving, multi-server identity protocol. A single license, held in a user-owned vault on the [Aviato Tower](https://tower.aviato.media), authenticates a user to many independent Aviato-compatible media servers. The Tower acts as a registration authority and an opaque relay; it never sees the bytes that flow between client and media server, and no media server learns anything about another.

The protocol is designed so that:

- **The user's master signing key never leaves the user's device unencrypted.** It lives encrypted in the Tower vault, surfacing only in browser memory long enough to sign a cert or assertion.
- **Tower's correctness is required only at pairing-code resolution.** Once a pair completes, the client holds the media server's public key directly and verifies everything against it.
- **A compromised Tower cannot impersonate users, forge identities, or read server payloads.** It can only refuse service (DoS).
- **A compromised media server affects only its own content.** It cannot impersonate the user against other servers.

## 2. Roles

| Role | What it holds | What it does |
|---|---|---|
| **User** | Passkey(s); master keypair M (encrypted in vault) | Approves pairings; signs delegation certs and pairing assertions with M |
| **Tower** | Encrypted user vaults; pairing-request rows; registered server pubkeys; signed `ServerConnInfoRecord`s | Lookup-by-code; relays sealed payloads; verifies signatures on stored records as a defense-in-depth check |
| **Media server** | Ed25519 server identity keypair; per-user `K` (conn-info encryption key); paired-user roster | Mints session tokens after verifying client certs and assertions; publishes encrypted conn-info to Tower |
| **Client app** | Per-device client keypair `Cn` (Ed25519 + X25519); cached delegation cert and bundle of paired servers | Pairs with Tower; signs session assertions; talks to servers directly after pair |

## 3. Cryptographic primitives

All primitives are auditable TypeScript in [`@aviato-media/pilot-core`](../packages/core); there are no native blobs.

| Use | Algorithm | Library |
|---|---|---|
| Identity / delegation / assertion signatures | Ed25519 | `@noble/curves/ed25519` |
| Sealedbox key agreement | X25519 ECDH | `@noble/curves/ed25519` |
| Key derivation | HKDF-SHA256 | `@noble/hashes/hkdf` |
| Symmetric encryption (vault, sealedbox, conn-info) | AES-GCM-256, 12-byte random nonce, 16-byte tag | WebCrypto (`crypto.subtle`) |
| Hashing | SHA-256 | `@noble/hashes/sha2` |
| Canonical JSON | RFC 8785 JCS | [`canonicalize`](https://www.npmjs.com/package/canonicalize) (RFC author's reference impl) |
| Hex / base64url-no-pad | — | `@noble/hashes/utils`, `@scure/base/base64urlnopad` |

### 3.1 Cross-system constants

These are the load-bearing wire facts. Any change requires a coordinated three-repo update (pilot-sdk + Aviato media-server + Tower):

| Constant | Value | Location |
|---|---|---|
| HKDF info, sealedbox | `"aviato-sealedbox-v1"` | `packages/core/src/crypto/sealedbox.ts` |
| HKDF info, vault wrap | `"aviato-vault-wrap/v1"` | `packages/tower-sdk/src/prf.ts` |
| AEAD AAD prefix, conn-info | `"aviato-server-conninfo-v1"` ‖ utf8(serverPubKey hex) ‖ u64BE(version) | `packages/core/src/conn-info/aad.ts` |
| Pairing-response sig binding | utf8(serverPubKey hex) ‖ utf8(canonical JSON `{ct, ephPub, nonce}`) | `packages/core/src/conn-info/pairing-response.ts` |
| Wire encoding | pubkeys hex 64 lowercase; signatures + ciphertext base64url-no-pad | enforced by Zod `HEX_32` in `packages/core/src/schemas/` |

### 3.2 Sealedbox

A one-shot anonymous public-key encryption envelope: the sender generates an ephemeral X25519 keypair, performs ECDH with the recipient's static X25519 pubkey, derives a 32-byte symmetric key via HKDF-SHA256 (info = `"aviato-sealedbox-v1"`), encrypts the plaintext with AES-GCM-256 under a random 12-byte nonce, then publishes `{ ct, ephPub, nonce }`. The recipient does the symmetric ECDH and decrypts.

Sealedbox is used to deliver per-user secrets (most importantly the per-server `K`) from media servers to users via Tower without Tower being able to read them.

## 4. Key & data model

### 4.1 Keys

- **M** — User's master Ed25519 keypair. The trust root for everything signed by the user. Public half published in the vault; private half lives encrypted in the vault and is unwrapped on the user's device just long enough to sign.
- **VK** — Vault key, 32 random bytes. Encrypts the vault payload with AES-GCM-256. Each enrolled passkey holds a wrapped copy.
- **PRF<sub>i</sub>** — Output of the [WebAuthn PRF extension](https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/) when the user taps passkey `i`. 32 bytes. Run through HKDF-SHA256 (info = `"aviato-vault-wrap/v1"`) to derive a per-passkey wrap key for VK.
- **C<sub>n</sub>** — Per-device client keypair. The pilot-client-sdk generates two: Ed25519 for signing session assertions, X25519 for opening sealed envelopes (the per-server K, conn-info bundles). Private halves live in OS-secure storage (Keychain / Keystore / IndexedDB non-extractable `CryptoKey`) and never leave the device.
- **S** — Media server's Ed25519 identity keypair. Registered with Tower at server startup.
- **K** — Per-server, per-user 32-byte AEAD key. Used to encrypt that server's `ServerConnInfo` row published to Tower. The server holds `K` for each linked user and re-delivers it sealed-to-user on every sign-in.

### 4.2 Vault payload

Plaintext shape (encrypted under VK, served from Tower as opaque ciphertext). Schema lives at `packages/core/src/schemas/vault.ts` (`VaultPayloadSchema`):

```
{
  v: 1,
  masterPubKey:   <hex M.pub>,
  masterPrivKey:  <base64url Ed25519 priv>,
  userEncPubKey:  <hex user X25519 pub>,
  userEncPrivKey: <base64url X25519 priv>,
  servers:        VaultServerEntry[]
}
```

The vault carries both signing (`master*`) and encryption (`userEnc*`) keypairs for the user. Tower stores only the ciphertext, IV, and an array of per-passkey wrapped VK copies. The list of paired client apps is not in the vault — Tower tracks issued certs separately (see `pilot-tower-sdk` `PairedClientStore`).

### 4.3 Client delegation cert

Wire form is JCS-canonical JSON, base64url-no-pad. Signed by M (key order shown alphabetical, matching JCS):

```
{
  appId,
  clientEncPubKey: <hex Cn.encPub>,
  clientId,
  clientPubKey:    <hex Cn.signPub>,
  deviceName,
  exp,
  iat,
  scope:           ["servers:*"],
  userEncPubKey:   <hex user vault X25519 pub>,
  userId,
  userPubKey:      <hex M.pub>,
  v: 1
}
```

Schema lives at `packages/core/src/schemas/cert.ts` (`ClientDelegationCertPayloadSchema`). `userEncPubKey` is the user-vault X25519 public half — embedding it in the cert lets servers seal `K` back to the user via the pairing-response leg on every sign-in without an out-of-band lookup.

TTL: 60 days. Renewable at the 30-day mark. The `appId` binds the cert to the app that the user paired through; servers MAY filter sessions by `appId`.

### 4.4 Session assertion (per-session, client → server)

Field order shown alphabetical, matching the JCS canonical bytes the signature is computed over:

```
{
  cert:      { payload, sig },
  challenge: <server nonce, hex>,
  serverId:  <hex S.pub>,
  ts:        <unix ms>,
  sig:       <Ed25519 by Cn over JCS({cert, challenge, serverId, ts})>
}
```

Schema: `IdentitySessionAssertionSchema` in `packages/core/src/schemas/assertions.ts`. Server verifies (via `verifySessionAssertion` in `packages/core/src/assertions/session.ts`): cert.sig against cert.userPubKey, cert not expired, sig against cert.clientPubKey, `serverId` matches its own S.pub, challenge fresh and unused, ts within ±60s skew, and (if a master-signed revocation list is held) that `clientId` is not revoked.

### 4.5 ServerConnInfo

Plaintext shape (encrypted under K, AEAD AAD bound to `serverPubKey` + monotonic `version`). Schema: `ServerConnInfoPayloadSchema` in `packages/core/src/schemas/conn-info.ts`:

```
{
  v: 1,
  publicHost,                       // FQDN or IP
  port,                             // positive int
  protocol: 'http' | 'https',
  fingerprint?: <64-char lowercase hex (TLS cert)>,
  paths?: { [key: string]: string }, // open record, e.g. { api: '/api' }
  rotationCounter,                  // int
  issuedAtSec
}
```

The encrypted envelope is wrapped in a `ServerConnInfoRecord` signed by the server's Ed25519 over `JSON.stringify({ct, nonce, serverPubKey, version})` (the explicit 4-key alphabetical literal in `packages/core/src/conn-info/publish-sig.ts` is byte-equivalent to JCS for these flat fields) and PUT to Tower. Tower verifies the signature, enforces strict-monotonic `version`, and stores the row. Clients fetch the row, verify Tower-side and server-side signatures, then decrypt with `K`.

### 4.6 Revocation

User signs a revocation envelope (`{ clientId, revokedAt }`) with M. Tower stores it; servers either poll Tower's CRL or accept a push from another of the user's devices over an existing cert-auth session.

## 5. Flows

### 5.1 Vault creation

1. User signs up at `tower.aviato.media/signup`. Tower's `register/begin` issues a WebAuthn challenge with a fresh 32-byte `prfSalt` in `extensions.prf.eval.first`.
2. Browser runs WebAuthn `create()`, captures the PRF output, generates M, generates VK, encrypts the vault payload, wraps VK with HKDF(PRF, info=`"aviato-vault-wrap/v1"`) → AES-GCM.
3. Browser calls `register/complete` with the credential and `M.pub`, then `POST /api/identity/vault/init` with `{ ciphertext, iv, wraps: [{ credentialId, prfSalt, wrappedKey, wrapIv }] }`.

The plaintext master key only ever exists in browser memory.

### 5.2 Server registration

The media server generates an Ed25519 identity keypair (`S`) and registers it with Tower out-of-band, receiving a bearer token used by all subsequent server-bearer endpoints. This step is Tower-side: pilot-server-sdk does not implement it (the bearer is supplied to `TowerClient` at construction). Registration is expected to be idempotent on the server pubkey; a fresh bearer is reissued on each registration so a server restart is always safe.

### 5.3 Server-link pairing

A media server links a user to itself:

1. Server: `POST /api/identity/pairing/register` (bearer) → `{ requestId, code, expiresAt }`. Displays the 8-digit code to the user, or opens `https://tower.aviato.media/pair?code=…`.
2. User opens Tower, taps passkey to unwrap VK and decrypt the vault.
3. Browser: `GET /api/identity/code/:code/resolve` → `{ kind: 'server-link', serverPubKey, serverName, scope, requestId, … }` (request context that Tower rendered the consent screen from; only `kind`, `requestId`, `serverPubKey` enter the signed bytes). The user reviews the consent screen.
4. Browser builds a `ServerLinkAssertionPayload` (see `packages/core/src/schemas/assertions.ts`) — `{ kind: 'server-link', requestId, serverPubKey, ts, userEncPubKey, userId, userPubKey, v: 1 }` — JCS-canonicalizes it, signs with M (`approveServerLink` in `pilot-tower-sdk/src/assertions.ts`), and POSTs `/api/identity/code/:code/complete { approve: true, signedAssertionBytes, assertionSignature }`.
5. Server polls `/api/identity/pairing/:requestId`; on `state: 'completed'` it verifies the assertion against M.pub (`verifyServerLinkAssertion`), generates a random 32-byte `K` for this user, and PUTs a `PairingResponse` to Tower at `/api/identity/pairing/:requestId/response`. The sealed plaintext is `{ v: 1, connInfoKey: <base64url K>, issuedAtSec, serverPubKey }` (JCS-canonicalized, sealedboxed to `userEncPubKey`); the envelope `{ ct, ephPub, nonce }` is then signed by the server with Ed25519 over `utf8(serverPubKey hex) ‖ utf8(JSON.stringify({ct, ephPub, nonce}))`.
6. Browser fetches the pairing response, verifies the server sig against the `serverPubKey` it just approved (`claimConnInfoKey` in `pilot-tower-sdk/src/pairing-response.ts`), opens the sealedbox with `userEncPrivKey`, and writes the new `vault.servers[]` entry containing `K`.

### 5.4 Client-pair (third-party app)

A client app obtains a delegation cert and the list of servers it may reach. The SDK paths called are in `packages/client-sdk/src/tower-client.ts`:

1. App generates `Cn` (Ed25519 + X25519 keypairs, or non-extractable handles via `KeyOps`). POSTs Tower `/api/identity/clients/pair/begin { appId, clientPubKey, clientEncPubKey, deviceName }` → `{ requestId, code, expiresAt }`. Displays `code` or opens `${towerWebUrl}/pair?code=…`.
2. User opens Tower, unwraps VK, reviews the app's consent screen (rendered from the `appId` registration at `/developer/apps`), selects which `vault.servers[]` entries to share.
3. Tower-web builds a `ClientDelegationCert` payload (see §4.3), JCS-canonicalizes, signs with M (`buildClientPairCert`), and assembles a `ClientPairBundle` (`buildClientPairBundle` in `pilot-tower-sdk/src/client-pair.ts`) where each chosen server's `K` is sealed to `clientEncPubKey`. The completed request is stored on Tower.
4. App polls `GET /api/identity/clients/pair/:requestId` (same endpoint, repeated `GET`); on `state: 'completed'` it receives the cert + sealed bundles, opens each sealed K with `Cn.encPriv`, stores `(serverPubKey, K, cert)` locally.

The cert never carries the server list; servers are delivered alongside the cert.

### 5.5 Server cert-auth sign-in

Per-server, after the client has the cert and `K`:

1. Client fetches the latest `ServerConnInfoRecord` from Tower (or the server's well-known endpoint), verifies Tower-side and server-side signatures against `serverPubKey`, decrypts under `K` → `{ publicHost, port, protocol, … }`.
2. Client `POST /api/auth/identity-session/begin { cert }` → `{ challenge }`.
3. Client builds a session assertion (§4.4), signs with `Cn.signPriv`, `POST /api/auth/identity-session/complete` → `{ sessionToken, expiresAt, refreshedConnInfoKey? }`.
4. The `refreshedConnInfoKey`, when present, is a `SessionConnInfoEnvelope` — a sealedbox containing `{ v: 1, connInfoKey, issuedAtSec }` (no `serverPubKey`, since the cert-auth handshake already pinned the server). The server uses `sealSessionConnInfoEnvelope` (`packages/server-sdk/src/session-envelope.ts`) to mint it; the client opens it with `Cn.encPriv` to refresh a rotated `K` without re-pairing. If conn-info decryption fails on the next fetch (stale K), the client surfaces `stale_k` and picks up the new `K` from the next sign-in's envelope.

### 5.6 Cert renewal

`AviatoPilotClient.renewCertIfNeeded(withinDays = 30)` (`packages/client-sdk/src/identity-client.ts`) calls `POST /api/identity/clients/:clientId/renew` to obtain a fresh signature over a new payload (same M, same `clientPubKey`, bumped `iat` / `exp`). The renewed cert is passed through `verifyClientCert(..., { expectedUserPubKey })` against the userPubKey learned at first pair — Tower cannot swap to a different user via renewal. Returns `'renewed' | 'not-needed' | 'unavailable' | 'failed'`.

## 6. Signature inventory

Every payload that names a server pubkey or carries user-bound bytes is signed and verified end-to-end.

| Payload | Signer | Verifier | Binding |
|---|---|---|---|
| `ServerConnInfoRecord` | server S | client + Tower (defense-in-depth) | `JSON.stringify({ct, nonce, serverPubKey, version})` (explicit 4-key alphabetical literal; byte-equivalent to JCS for these primitive fields) |
| `ServerConnInfo` AEAD | server S (K-keyed AES-GCM) | client | AAD = `"aviato-server-conninfo-v1"` ‖ serverPubKeyHex ‖ u64BE(version) |
| `PairingResponse` (sealed K) | server S | user, with expectedServerPubKey | utf8(serverPubKey hex) ‖ utf8(canonical JSON of `{ct, ephPub, nonce}`) |
| Pairing assertions (`server-link`, `server-sign-in`) | user M | server, with expectedServerPubKey + expectedRequestId | JCS over assertion body |
| `ClientDelegationCert` | user M | server (sign-in) + client (renewal) | JCS over cert payload |
| Session assertion | client `Cn` | server, with expectedServerPubKey + expectedChallenge | JCS over `{cert, challenge, serverId, ts}` |
| Revocation envelope | user M | server / other client | JCS over `{clientId, revokedAt}` |

## 7. Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Network passive | Sees ciphertext | TLS + signed payloads |
| Network active MITM at first pair | Can substitute a master pubkey | TOFU fingerprint shown to user on both Tower and server's UI |
| Compromised Tower web app | Could inject JS into a vault-open session | SRI + strict CSP; native apps perform crypto natively. Residual risk. |
| Compromised Tower API + DB | Read encrypted vaults (useless without VK); refuse renewals; substitute vault blobs (rejected by AEAD) | Cannot forge identity assertions, cannot read server lists, cannot decrypt conn-info |
| Compromised user device | Leaks that device's `Cn` and cached session tokens | Other devices unaffected. User revokes via Tower. |
| Lost passkey | — | Recover via other enrolled passkeys or recovery codes |
| Compromised media server | Owns its own content | Cannot impersonate the user against other servers |

**Privacy boundaries.** The Tower is structurally unable to:

- see which users have access to which servers' data,
- know the network address of any server,
- read user profiles, display names, or any relay content,
- deauthorize users or block access to servers,
- decrypt escrowed key bundles.

If the Tower is unavailable, existing client ↔ server connections continue to work. Only new pairings and cert renewals are affected.

**Explicit non-goals.** Hiding from Tower *that* a user exists or *how many* servers they have (Tower sees vault entry counts and pairing requests). Resisting endpoint malware on a fully compromised device.

## 8. Pointers

- Cross-system schemas, builders, verifiers: [`@aviato-media/pilot-core`](../packages/core)
- Client integration: [`@aviato-media/pilot-client-sdk`](../packages/client-sdk)
- React bindings: [`@aviato-media/pilot-client-react`](../packages/client-react)
- Media-server integration: [`@aviato-media/pilot-server-sdk`](../packages/server-sdk)
- Tower vault + passkey-PRF + master-signing helpers: [`@aviato-media/pilot-tower-sdk`](../packages/tower-sdk)
- High-level summary and flowcharts: [`overview.md`](./overview.md)
- Getting started as a client integrator: [`getting-started.md`](./getting-started.md)
