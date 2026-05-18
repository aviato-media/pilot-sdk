# Aviato Identity — Native Client App Integration Guide

This document describes how a native client app (Aviato TV and mobile apps)
integrates with Tower's Identity endpoints to obtain a long-lived delegation
cert from a user and discover the connection info for that user's linked media
servers.

Audience: developers implementing a **native client app**. For
**web-based** clients (Aviato Web, browser SPAs), see `identity-web.md`
— the underlying endpoints are the same, but the credential storage
strategy differs. For the **server side** (publishing connection info,
verifying client certs at session-establishment), see
`identity-server-link.md`.

---

## Concept

Your app holds a per-install **delegation cert** signed by the user's
master Ed25519 key. The cert says "I, the user, authorize this specific
client (clientPubKey) to act on my behalf at media servers, for one
year." Media servers verify the cert chain (`cert.userPubKey ==
user's_registered_pubkey`, `cert.sig` valid under master) and accept
sessions authenticated by signatures from the client's own keypair.

Alongside the cert, you receive a **sealed K-bundle** containing the
per-server connection-info decryption keys for the servers the user
approved at pair time. With those K's, you decrypt the unauthenticated
`SERVER_CONNINFO` rows Tower caches and learn where each server is
listening today.

---

## Trust model

- **Tower-api never sees** your private keys, the master key, or the
  plaintext K bundle. Tower handles only opaque ciphertext + signed
  bytes verifiable against published pubkeys.
- **Your client keypairs** are generated locally. The Ed25519 signing
  key proves you are the rightful holder of the cert; the X25519
  encryption key receives the sealed K-bundle.
- **The cert delegates** scoped authority from the user to your client.
  Revocation lives on a Tower-published CRL that media servers fetch.

---

## Prerequisites

1. **Register your app** at https://tower.aviato.media/developer/apps.
   You'll receive an `appId` (kebab-case, e.g. `aviato-mobile`)
   that Tower uses to look up your app's metadata for the consent
   screen. This is a one-time developer action, not a per-install API
   call.
2. **Implement two crypto primitives**: Ed25519 signing and the
   sealedbox primitive (X25519 + AES-GCM-256 + HKDF-SHA-256). The
   sealedbox construction is documented in `identity-server-link.md`
   §"Cryptography reference" and a reference implementation lives in
   `packages/tower-web/src/lib/sealedbox.ts`.
3. **Choose secure key storage** for the client signing private key.
   On native platforms, prefer the OS keychain (iOS Keychain, Android
   Keystore, macOS Keychain, Windows Credential Manager). The
   encryption private key + sealed K bundle can sit in app-private
   storage protected by the OS.

---

## The pair-time flow

### 1. Generate keypairs

```typescript
// Ed25519 signing keypair (long-lived, identifies this client install)
const ed = ed25519_generate()   // { priv: 32B, pub: 32B }

// X25519 encryption keypair (long-lived, receives sealed K bundles)
const x  = x25519_generate()    // { priv: 32B, pub: 32B }
```

Persist both private keys in the secure storage chosen above. Lose them
and the user must re-pair.

### 2. Initiate the pairing

`POST /api/identity/clients/pair/begin` (no auth)

```json
{
  "appId": "aviato-mobile",
  "clientPubKey": "<base64url 32 bytes — Ed25519 pub>",
  "clientEncPubKey": "<base64url 32 bytes — X25519 pub>",
  "displayName": "Bob's iPhone",
  "platform": "ios"
}
```

`platform` is one of `tvos | ios | android | windows | macos | linux |
web | other`. `displayName` is what the user sees in the consent screen
and in their dashboard's "Connected Apps" list.

**Response 201**:

```json
{
  "requestId": "<UUID>",
  "code": "12345678",
  "expiresAt": "ISO 8601 (5 minutes)"
}
```

### 3. Display the code

Show the 8-digit code to the user. Offer a QR code or deep link:

```
https://tower.aviato.media/pair?code=12345678
```

The user visits Tower-web, signs in (if needed), reviews your app's name
and icon, picks which of their linked servers to expose to your app, and
approves. The whole UX is ~30 seconds for a logged-in user, up to a
couple of minutes if they need to find their phone for a passkey.

### 4. Poll for completion

`GET /api/identity/clients/pair/:requestId` (no auth — the `requestId`
itself is the capability token, 122 bits of entropy in the UUID).

Poll every ~2 seconds. The endpoint is rate-limited to 150 polls per
requestId. Completed rows return immediately without burning a poll
slot — retries after transient failures are safe.

**Response shape**:

```json
{
  "state": "pending" | "claimed_by_user" | "completed" | "denied" | "expired",
  "requestId": "<UUID>",
  "expiresAt": "ISO 8601",
  "signedCertBytes": "<base64url>",          // when completed
  "certSignature": "<base64url>",            // when completed
  "sealedConnInfoBundle": {                  // when completed, may be null
    "ct": "<base64url>",
    "ephPub": "<base64url>",
    "nonce": "<base64url>"
  } | null
}
```

`sealedConnInfoBundle` is `null` if the user has no linked servers yet
or chose to expose none — your app should still accept the cert and
prompt the user to link a server next.

### 5. Persist the cert + decrypt the bundle

Decode `signedCertBytes` to get the canonical JSON the user signed.
Validate it matches `ClientDelegationCertPayloadSchema` in
`@aviato/common`:

```typescript
{
  v: 1,
  appId: "aviato-mobile",       // must equal your appId
  clientId: "<UUID>",                // your stable identifier per cert
  clientPubKey: "<hex 64>",          // must equal hex(your clientPubKey)
  clientEncPubKey: "<hex 64>",       // must equal hex(your clientEncPubKey)
  deviceName: "<string>",
  iat: <unix sec>,
  exp: <unix sec, +1 year>,
  scope: ["servers:*"],
  userId: "<string>",
  userPubKey: "<hex 64>",
  userEncPubKey: "<hex 64>",
  v: 1
}
```

Verify `certSignature` (base64url) is a valid Ed25519 sig over the
canonical bytes (NOT a re-canonicalized JSON — the bytes Tower returned).
The verification key is the cert's `userPubKey`. You don't need to know
the user's actual identity yet; the media server will resolve that.

Decrypt `sealedConnInfoBundle` (if present) with your X25519 private key.
The plaintext shape is `ClientKeyBundleContentsSchema` in `@aviato/common`:

```typescript
{
  v: 1,
  issuedAtSec: <unix sec>,
  servers: [
    { serverPubKey: "<hex 64>", connInfoKey: "<base64url 32 bytes>" },
    ...
  ]
}
```

Persist:

- The signed cert bytes + signature (you'll present them to media servers)
- The `clientId` (you'll need it for renewal + revocation lookups)
- The `connInfoKey` (K) for each `serverPubKey`, keyed by pubkey

---

## Discovering a server

For each `serverPubKey` you have a K for:

### 1. Fetch the encrypted connection info

```typescript
const hash = base64url(sha256(hex2bytes(serverPubKey)))   // 43 chars
const row  = await fetch(`https://tower.aviato.media/api/identity/server-conninfo/${hash}`)
```

No auth required. Tower caches with `Cache-Control: public, max-age=30`
so polling is cheap.

**Response 200**: the encrypted row (see `identity-server-link.md`
§"Reading published rows").

**Response 404**: the server hasn't reported to Tower in ≥72h — show
"offline" in the UI.

### 2. Verify the server's signature

Verify `row.sig` is a valid Ed25519 signature over the canonical bytes:

```typescript
const message = JSON.stringify({
  ct: row.ct,
  nonce: row.nonce,
  serverPubKey: row.serverPubKey,
  version: row.version
})
ed25519_verify(serverPubKey, sig=row.sig, message)
```

Reject and surface as an error if verification fails. A signature
mismatch means Tower (or a network attacker) tampered with the row.

### 3. Decrypt with K

```typescript
const aad = (
  utf8("aviato-server-conninfo-v1")
  ++ utf8(row.serverPubKey)
  ++ uint64BE(row.version)
)
const plaintext = aes_gcm_decrypt(
  key:   base64url_decode(K),
  nonce: base64url_decode(row.nonce),
  ct:    base64url_decode(row.ct),
  aad
)
```

If AEAD decrypt fails, K is stale (server rotated). See *Handling K
rotation* below.

The plaintext is `ServerConnInfoPayloadSchema`:

```typescript
{
  v: 1,
  publicHost: "media.example.com",
  port: 8443,
  protocol: "https",
  fingerprint?: "<TLS cert fingerprint>",
  paths?: { api: "/api", media: "/m" },
  rotationCounter: <number>,
  issuedAtSec: <unix sec>
}
```

Cache the result client-side. Re-fetch on a refresh cadence appropriate
to your product (every few minutes for a media app; on every reconnect
for a control app).

### 4. Connect to the server

The server's HTTPS endpoint at `publicHost:port` accepts your delegation
cert as the authentication credential. See
`identity-server-link.md` for the verifier side; the wire flow your
client implements is:

```typescript
// Build an identity-session assertion
const challenge = utf8(serverPubKey hex) ++ utf8(serverChallengeNonce)  // server-provided
const payload = JSON.stringify({
  cert:      { payload: signedCertBytes, sig: certSignature },
  challenge: <hex>,
  serverId:  <hex 64 serverPubKey>,
  ts:        <unix sec>
})
const sig = ed25519_sign(clientPriv, payload)
// POST payload + sig to the media server's session-establishment endpoint
```

See `IdentitySessionAssertionSchema` in `@aviato/common` for the exact
wire shape.

---

## Cert renewal

Certs expire after one year. Tower pre-issues a fresh cert into a renewal
slot when the user next signs into Tower-web (or you can call
`/api/identity/clients/preissue` from a user-authenticated session).
Clients pick up the renewed cert by signing a one-shot challenge.

`POST /api/identity/clients/:clientId/renew` (no Authorization header)

Where `:clientId` is `sha256(clientPubKey-bytes).hex` (64 hex chars).
Note this is a hash of your **Ed25519 signing pubkey**, not the cert's
`clientId` UUID field.

```json
{
  "requestedAt": "ISO 8601 timestamp (within ±5 min)",
  "signature": "<base64url Ed25519 sig over canonical { clientId, requestedAt }>"
}
```

The canonical bytes to sign are:

```typescript
utf8(JSON.stringify({ clientId, requestedAt }))   // alphabetical-keyed
```

**Response 200**: a fresh cert + signature + new expiry.

**Errors**:
- `401 request_too_old` — `requestedAt` skew > 5 min
- `404 cert_not_available` — no pre-issued cert; user needs to sign into
  Tower-web (which triggers pre-issuance)
- `403 invalid_signature` — sig didn't verify against the client pubkey
  on file

Recommended cadence: attempt renewal at 30 days remaining; retry every
24h until renewed or expiry. After expiry, prompt the user to re-pair.

---

## Handling K rotation

If a server rotates K, your cached K stops decrypting their
`server-conninfo` row (AEAD tag mismatch). You can detect this:

```typescript
try {
  const conn = decryptConnInfo(row, K)
} catch (AeadTagMismatch) {
  // K is stale; re-pair required
}
```

Recovery: prompt the user to re-pair from Tower-web. The fresh sealed
bundle will carry the new K alongside any updated cert. There is no
in-band K refresh path for paired clients — the spec deliberately keeps
Tower out of the rotation channel for users you no longer trust.

UX recommendation: show "Connection refresh needed for [Server Name]
— re-pair from Aviato Tower" with a button that opens
`https://tower.aviato.media/pair` (or a QR for handoff). Rotation is
rare (admin reset, suspected K leak), so this UX rarely fires.

---

## Revocation

The user can revoke your cert from their dashboard. Tower publishes a
CRL feed every media server should poll:

```
GET https://tower.aviato.media/api/identity/crl
```

Cache-friendly (long max-age + ETag). Clients themselves don't need to
poll the CRL — media servers reject revoked certs at session
establishment.

A revoked client will see `401 cert_revoked` from media servers and
should:

1. Surface to the user: "This device's access was revoked. Re-pair to
   continue."
2. Discard the cert + K bundle.
3. Prompt for re-pair.

---

## Storage and lifecycle

| Item                     | Lifetime           | Storage recommendation                          |
|--------------------------|--------------------|-------------------------------------------------|
| `clientPriv` (Ed25519)   | Per install        | OS keychain                                     |
| `clientEncPriv` (X25519) | Per install        | OS keychain                                     |
| `signedCertBytes` + sig  | 1 year             | App-private storage                             |
| `clientId` (UUID)        | Per install        | App-private storage                             |
| K per server             | Until server rotates | App-private storage, encrypted at rest        |
| Cached `ServerConnInfoPayload` | Refresh cadence | In-memory; persist briefly for cold start    |

On user-initiated logout, clear K cache + cert + clientId (forces re-pair
next time). The Ed25519 + X25519 private keys can survive logout if you
want to support same-device re-pair without re-generating.

---

## Implementation checklist

- [ ] Register app at `tower.aviato.media/developer/apps`, record `appId`
- [ ] Generate + persist Ed25519 + X25519 keypairs locally (OS keychain)
- [ ] Implement sealedbox decrypt (X25519 ECDH + HKDF + AES-GCM)
- [ ] Implement Ed25519 verify (for cert sig + server-conninfo sig)
- [ ] Pair flow: `/clients/pair/begin` → display code → poll → validate
      cert → decrypt bundle → persist K's
- [ ] Discovery flow: `sha256(serverPubKey)` → fetch row → verify sig →
      AEAD-decrypt with K → connect
- [ ] Cert renewal: signed request to `/clients/:clientId/renew` at
      ≤30 days remaining
- [ ] AEAD-decrypt failure path: prompt user to re-pair
- [ ] Revocation handling: clear local state, prompt re-pair, on
      `401 cert_revoked`
- [ ] Cert validation: verify `appId`, `clientPubKey`, `clientEncPubKey`,
      `exp`, and Ed25519 sig before trusting

---

## Error codes summary

| Code  | Where                                  | Meaning                                                  |
|-------|----------------------------------------|----------------------------------------------------------|
| 400   | `/clients/pair/begin`                  | Invalid body / `unknown_app` / `invalid_pubkey`          |
| 400   | `/clients/:clientId/renew`             | Invalid body / `invalid_client_id`                       |
| 401   | `/clients/:clientId/renew`             | `request_too_old` — `requestedAt` skew > 5 min           |
| 403   | `/clients/:clientId/renew`             | `invalid_signature` — sig didn't verify                  |
| 404   | `/clients/pair/:requestId`             | `pairing_not_found`                                      |
| 404   | `/server-conninfo/:hash`               | Server offline (no recent publish)                       |
| 404   | `/clients/:clientId/renew`             | `cert_not_available` — user needs to sign into Tower-web |
| 410   | `/clients/pair/:requestId`             | Pairing expired (5-min TTL)                              |
| 429   | All poll endpoints                     | 150-poll cap per requestId exhausted                     |
