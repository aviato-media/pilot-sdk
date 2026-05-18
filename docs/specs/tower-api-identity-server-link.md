# Aviato Identity — Server Integration Guide

This document describes how an Aviato media server backend integrates with
Tower's Identity endpoints to link users, sign them in, and publish
encrypted connection info that paired client apps can discover.

Audience: developers implementing the **server side** of the integration
(the "Aviato media server"). The endpoints are implemented in
`packages/tower-api/src/routes/identity-*.ts`.

For the **client-side** integrations, see:

- `identity-client-app.md` — native client apps (Aviato TV and mobile apps)
- `identity-web.md` — browser-based web apps (Aviato Web)

---

## Concept

Tower is an **identity broker**, never a custodian. The user owns a master
Ed25519 keypair encrypted under their passkey-PRF vault; the server owns
its own Ed25519 keypair registered with Tower. When the user wants to link
their identity to a server, Tower brokers a short pairing that produces a
user-signed assertion the server verifies and stores. Tower never sees the
user's master private key.

Three pairing flows share this broker pattern:

| Pairing kind     | Lifetime          | Produces                                  | Typical UX                          |
|------------------|-------------------|-------------------------------------------|-------------------------------------|
| `server-link`    | One-shot          | Master-signed `server-link` assertion     | First-time setup                    |
| `server-sign-in` | One-shot (session)| Master-signed `server-sign-in` assertion  | Streamlined web sign-in to a server |
| `client-pair`    | 1-year delegation cert | Client-bearing delegation cert + K bundle | Native app onboarding               |

This guide covers `server-link` and `server-sign-in`. `client-pair` is
covered in `identity-client-app.md`.

---

## Trust model

- **Tower-api never sees plaintext** of the master private key, signed
  assertion contents (treated as opaque bytes during relay), or server
  connection-info ciphertext.
- **The user's vault** stores the master signing key + a separate X25519
  encryption key, both behind passkey-PRF.
- **Server registration** establishes the server's Ed25519 identity with
  Tower and issues a bearer token used by all server-side endpoints.
- **The pairing-response leg** lets the server deliver per-user secrets
  (notably the connection-info decryption key K) sealed to the user's
  X25519 pubkey, with Tower acting as an opaque relay.

---

## Prerequisites

Before integrating, the server must:

1. **Generate an Ed25519 keypair** (the server's identity). Persist it
   securely; rotation means re-registration and re-linking by all users.
2. **Register with Tower** to receive a bearer token. See
   *Server registration* below.
3. **Implement the sealedbox primitive** (see *Cryptography reference*)
   for sealing the connection-info K back to users via the
   pairing-response leg.

---

## Server registration

`POST /api/identity/server-registration`

One-shot. The bearer returned here authenticates every subsequent server
endpoint. Re-register only if the Ed25519 keypair is rotated.

**Request** (no auth):

```json
{
  "serverPubKey": "<base64url 32 bytes>",
  "displayName": "Friendly Server Name"
}
```

**Response 201**:

```json
{
  "serverId": "<UUID>",
  "bearer": "<opaque-token>",
  "expiresAt": "ISO 8601"
}
```

Store `bearer` and `serverId` server-side. The bearer is long-lived; rotate
by re-registering when needed.

---

## Authentication

All server-side endpoints use the standard bearer header:

```
Authorization: Bearer <bearer>
```

The bearer is bound to a specific server registration (and therefore a
specific `serverPubKey`). Any endpoint that accepts a `serverPubKey` in
the body cross-checks it against the bearer's registration and rejects
with `400 server_pubkey_mismatch` on disagreement.

---

## server-link pairing

Used the first time a user is linking to your server. Produces a signed
assertion the server stores as proof-of-link, then optionally delivers
the connection-info K to the user via the response leg.

### 1. Initiate the pairing

`POST /api/identity/pairing/register` (server bearer)

```json
{
  "serverName": "Bob's Plex Server",
  "serverIcon": "https://example.com/icon.png",
  "callbackUrl": "https://bobs-plex.example.com/aviato/callback",
  "scope": "media:read"
}
```

All fields are optional except by your own preference. Tower renders
`serverName` and `serverIcon` on the user's consent screen.

**Response 201**:

```json
{
  "requestId": "<UUID>",
  "code": "12345678",
  "expiresAt": "ISO 8601 (5 minutes)"
}
```

Display the 8-digit `code` to the user, or build a deep link:

```
https://tower.aviato.media/pair?code=12345678
```

### 2. Poll for completion

`GET /api/identity/pairing/:requestId` (server bearer)

Poll every ~2 seconds. The endpoint is rate-limited to 150 polls per
requestId; budget your interval accordingly. A `state: 'completed'`
response is returned without burning a poll slot, so retries after a
network blip are safe.

**Response shape**:

```json
{
  "state": "pending" | "claimed_by_user" | "completed" | "denied" | "expired",
  "requestId": "<UUID>",
  "expiresAt": "ISO 8601",
  "signedAssertionBytes": "<base64url>",     // when completed
  "assertionSignature": "<base64url>"        // when completed
}
```

### 3. Verify the assertion

`signedAssertionBytes` is the base64url of canonical JCS bytes the user's
master key signed. Do NOT re-canonicalize — verify the signature against
the exact bytes Tower returned.

Decode `signedAssertionBytes` and parse the JSON. Validate the shape
against `ServerLinkAssertionPayloadSchema` in `@aviato/common`:

```typescript
{
  kind: "server-link",
  requestId: "<UUID>",                     // must equal the pairing requestId
  serverPubKey: "<hex 64>",                // must equal your server's pubkey
  ts: <unix-ms>,                           // accept within ±10 min skew
  userId: "<string>",
  userPubKey: "<hex 64>",                  // Ed25519 signing pubkey
  userEncPubKey: "<hex 64>",               // X25519 encryption pubkey (NEW in v2.1)
  v: 1
}
```

Verify the Ed25519 signature `assertionSignature` (base64url) over the
canonical bytes using `userPubKey`. On success, persist `(userId,
userPubKey, userEncPubKey)` as a linked user in your database.

### 4. (Recommended) Attach the pairing-response with K

`POST /api/identity/pairing/:requestId/response` (server bearer)

Once verified, deliver the per-user connection-info decryption key K to
the user by sealing it to `userEncPubKey` and posting it through Tower.
The user's browser polls `/api/identity/pairing-response/:requestId`,
verifies your signature, and writes K into their vault for the next
client-pair to bundle.

Build the sealed payload:

```typescript
const sealed_plaintext = {
  v: 1,
  connInfoKey: <base64url 32 bytes — your per-server symmetric K>,
  issuedAtSec: Math.floor(Date.now() / 1000),
  serverPubKey: "<hex 64>"  // your pubkey, duplicated for cross-check
}

const sealed = sealedBoxEncrypt(
  canonicalJSON(sealed_plaintext),
  recipientPubKey: hexToBytes(userEncPubKey)
)
// sealed = { ct, ephPub, nonce } (each base64url)
```

Sign the sealed body:

```typescript
const canonicalSealed = JSON.stringify({
  ct: sealed.ct,
  ephPub: sealed.ephPub,
  nonce: sealed.nonce
})
const message = utf8(serverPubKey_hex) ++ utf8(canonicalSealed)
const sig = ed25519_sign(serverPriv, message)  // base64url
```

POST:

```json
{
  "sealed": { "ct": "...", "ephPub": "...", "nonce": "..." },
  "sig": "<base64url>"
}
```

**Response 201**: `{ "ok": true }`

**Errors**:
- `403 not_owner` — bearer doesn't own this pairing
- `400 wrong_kind` — pairing was client-pair (no response leg)
- `409 not_completed` — assertion not yet completed; verify first

The browser has up to 5 minutes (pairing TTL) to retrieve. After that the
row TTLs out and the user must sign in to receive K via the next
server-sign-in response.

---

## server-sign-in pairing

A streamlined web sign-in flow: the user proves identity to your server
without producing a long-lived credential. Same broker pattern as
server-link; produces a one-shot assertion the server uses to mint a
session cookie. The pairing-response leg works identically — every
sign-in re-delivers the current K, which doubles as the K rotation
channel.

### 1. Initiate

`POST /api/identity/server-sign-in/begin` (server bearer)

```json
{
  "serverPubKey": "<hex 64>",     // must match the bearer's registration
  "serverName": "Bob's Plex Server"
}
```

**Response 201**: `{ requestId, code, expiresAt }`

### 2. Poll

`GET /api/identity/server-sign-in/:requestId` (server bearer)

Same shape as `pairing/:requestId` above. Same poll-counter discipline.

### 3. Verify

The assertion's `kind` is `"server-sign-in"`. Otherwise the shape is
identical to the server-link assertion. Verify the Ed25519 signature
against the exact bytes Tower returned.

The assertion is one-shot: bind your session cookie to it (or to a derived
identifier), but do not store the assertion bytes as a long-lived
credential.

### 4. Attach response with current K

Same as server-link step 4. On every successful sign-in, send the
**current** K — if you've rotated K, the user's vault picks up the new
value here. This is the user-facing rotation path; stale clients then
get the new K through their own session response when they next
authenticate.

---

## Publishing connection info

`POST /api/identity/server-conninfo` (server bearer)

Your server publishes its current connection info (host/port/protocol)
as AEAD ciphertext encrypted with the per-server K. Tower stores it
opaquely. Linked users — and their paired clients — fetch the row and
decrypt with K.

### Encrypt the connection info

The plaintext shape is documented in `@aviato/common`'s
`ServerConnInfoPayloadSchema`:

```typescript
{
  v: 1,
  publicHost: "media.example.com",   // FQDN or IP
  port: 8443,
  protocol: "https",
  fingerprint?: "<TLS cert fingerprint>",
  paths?: { api: "/api", media: "/m" },
  rotationCounter: <number, monotonic per server>,
  issuedAtSec: <unix sec>
}
```

Encrypt with AES-GCM-256 using K. **AEAD AAD** MUST be:

```
ASCII("aviato-server-conninfo-v1") ++ serverPubKey (hex) ++ version (8-byte big-endian unsigned)
```

This binds the ciphertext to its version slot so an attacker who captured
an older POST can't swap its ct into the current row.

**AES-GCM nonce discipline**: cryptographically random 12-byte nonce per
encryption. Random is safe up to ~2^32 messages per K — generous for
real-world server lifetimes. NEVER reuse a (K, nonce) pair under AES-GCM.

### Sign the wire body

```typescript
const canonicalBody = JSON.stringify({
  ct: <base64url>,
  nonce: <base64url>,
  serverPubKey: <hex 64>,
  version: <number>
})
const sig = ed25519_sign(serverPriv, canonicalBody)  // base64url
```

### POST the body

```json
{
  "ct": "<base64url ≤ 8192 chars>",
  "nonce": "<base64url 12 bytes>",
  "serverPubKey": "<hex 64>",
  "sig": "<base64url>",
  "version": <number, strictly greater than the stored version>
}
```

**Response 200**: `{ "ok": true, "version": <stored>, "lastUpdatedAtSec": <unix> }`

**Errors**:
- `400 invalid_body` — schema validation failed
- `400 server_pubkey_mismatch` — body pubkey doesn't match bearer
- `403 invalid_signature` — sig didn't verify against the registered pubkey
- `409 stale_version` — `version` not strictly greater than the stored version

### Update cadence

The row TTLs out 72h after the last publish. Republish at least once
every ~24h to stay live. On every dynamic-DNS change, port change, or
TLS rotation, increment `version` and publish.

If you rotate K, you must:

1. Re-encrypt and publish the row under the new K (with a bumped version).
2. Deliver the new K to every signing-in user via the pairing-response
   leg (server-sign-in step 4). Stale clients fail to decrypt → user
   re-pairs them through your app's normal "auth refresh" flow.

---

## Reading published rows

`GET /api/identity/server-conninfo/:hash`

Unauthenticated. `:hash` is `sha256(serverPubKey-bytes).base64url` (43
chars). Compute it identically on the server side and the client side.
Tower caches with `Cache-Control: public, max-age=30`, so multiple
clients on the same network won't all hit the origin.

**Response 200**:

```json
{
  "serverPubKey": "<hex 64>",
  "ct": "<base64url>",
  "nonce": "<base64url>",
  "sig": "<base64url>",
  "version": <number>,
  "lastUpdatedAtSec": <unix>
}
```

**Response 404**: row not present or TTL'd out (server hasn't reported in
≥72h). Clients should treat 404 as "server offline."

Servers usually don't need to read their own row, but the endpoint is
public so you can probe it from operational tooling.

---

## Cryptography reference

### Sealedbox (X25519 + AES-GCM)

Used for the pairing-response leg (`server → user`) and for any future
sealing-to-userEncPubKey channels.

```
1. ephPriv = random 32 bytes (X25519 secret key)
2. ephPub  = X25519(ephPriv) (public key, 32 bytes)
3. shared  = X25519(ephPriv, recipientPub)        # 32 bytes ECDH output
4. key     = HKDF-SHA-256(
                ikm=shared,
                salt=empty,
                info=ASCII("aviato-sealedbox-v1"),
                len=32)
5. nonce   = random 12 bytes
6. ct      = AES-GCM-256(key, nonce, plaintext)   # GCM tag appended
7. output  = { ephPub, nonce, ct } (each base64url)
```

The recipient reverses by computing `shared = X25519(recipientPriv,
ephPub)` and following steps 4–6 in reverse.

A reference implementation lives in
`packages/tower-web/src/lib/sealedbox.ts`. Server-side ports must produce
byte-for-byte identical output for the same inputs.

### Ed25519 signature inputs

| Use                              | Message bytes                                                              |
|----------------------------------|----------------------------------------------------------------------------|
| `assertionSignature`             | The exact `signedAssertionBytes` Tower returned (base64url-decoded)        |
| Pairing-response `sig`           | `utf8(serverPubKey_hex)` ++ `utf8(JSON.stringify({ct, ephPub, nonce}))`    |
| `server-conninfo` POST `sig`     | `utf8(JSON.stringify({ct, nonce, serverPubKey, version}))`                 |

All canonical-JSON inputs are alphabetical-keyed `JSON.stringify` with
explicit field order in code — adequate for the small, flat objects in
question (no Unicode or numeric edge cases).

---

## Error codes summary

| Code  | Where                                  | Meaning                                                |
|-------|----------------------------------------|--------------------------------------------------------|
| 400   | `pairing/register`, `server-sign-in/begin` | Invalid body / `server_pubkey_mismatch`               |
| 400   | `server-conninfo` POST                 | Invalid body / pubkey mismatch                          |
| 400   | `pairing/:id/response`                 | `wrong_kind` for client-pair rows                       |
| 401   | Any server endpoint                    | Bearer missing / invalid                                |
| 403   | `server-conninfo` POST                 | `invalid_signature` — sig didn't verify                 |
| 403   | `pairing/:id`, `pairing/:id/response`  | `not_owner` — bearer doesn't own this pairing           |
| 404   | `server-conninfo/:hash`                | Row not present / TTL'd out (treat as offline)          |
| 409   | `pairing/:id/response`                 | `not_completed` — assertion not yet completed           |
| 409   | `server-conninfo` POST                 | `stale_version` — `version` not strictly greater        |
| 429   | All poll endpoints                     | Per-requestId 150-poll cap exhausted                    |

---

## Implementation checklist

- [ ] Generate Ed25519 server keypair, persist server-side
- [ ] POST `/api/identity/server-registration`, store bearer + serverId
- [ ] Implement sealedbox encrypt (X25519 + AES-GCM-256 + HKDF-SHA-256)
- [ ] Implement Ed25519 verify against assertion bytes
- [ ] `server-link` happy path: register → display code → poll → verify
      assertion → attach response with K → record linked user
- [ ] `server-sign-in` happy path: same, but mint session cookie + always
      deliver current K via response leg
- [ ] Per-server K generation + safe persistence (TPM / disk encryption)
- [ ] `server-conninfo` publish on startup + on every connection-info
      change + heartbeat every ~24h
- [ ] AES-GCM AAD construction matches the spec (binds version)
- [ ] Monotonic `version` counter persisted across restarts
- [ ] Handle `409 stale_version` by re-reading and bumping
- [ ] Handle bearer expiry by re-registering
- [ ] Document for ops: "if K rotates, all clients need re-pair"
