# Aviato Identity — Server Connection Info Distribution

> **Audience:** an implementer working inside `~/projects/aviato/aviato/` who needs to add the server-side (Aviato media server) and web-side (Aviato Web) counterparts to the connection-info plumbing that's already landed in Aviato Tower (`~/projects/ato/ato.software/`).
>
> Tower is done. This doc tells you what Aviato needs to do to interop.

---

## 1. Why this exists

Native clients (Aviato Afterburner) and Aviato Web need to discover **where to connect** to a user's media server. The connection info is sensitive (host + port + cert fingerprint + auth-aux) and **dynamic** (servers move around via DDNS, IP changes, port reconfigs). Tower brokers the directory, but **Tower must never see the plaintext** — only encrypted blobs.

The shape we landed on:

```
                publish ct (1×/server, not 1×/user)
   ┌────────┐ ─────────────────────────────────────────▶ ┌────────┐
   │ Server │                                            │ Tower  │
   └────┬───┘                                            └──┬─────┘
        │ pairing-response leg: seal K to userEncPub        │  (blind to K + plaintext)
        │ ─────────────────────────────────────────────────▶│
        │                                                   │
        ▼                                                   ▼
   user vault holds K                              tower-web bundles K
   per linked server                               into sealed client-pair payloads
        │                                                   │
        │  client decrypts bundle locally, then              │
        │  GETs /server-conninfo/:hash, decrypts with K     │
        ▼                                                   │
   ┌────────┐ ◄─────────────────────────────────────────────┘
   │ Client │ (Afterburner, Aviato Web)
   └────────┘
```

Critical privacy properties:
- Tower's `SERVER_CONNINFO` partition is keyed on `sha256(serverPubKey)` — **no user reference, ever**.
- The `GET /server-conninfo/:hash` endpoint is **unauthenticated** (the payload is encrypted) — so fetch logs can't reveal user↔server linkage either.
- K travels server→user via the **pairing-response leg** (sealed to the user's X25519 vault key) and user→client via the **sealed bundle** attached to the client-pair cert. Tower never sees K in plaintext.

---

## 2. New cryptographic primitive: Aviato sealedbox

This is the single primitive used by:
- Server → user (pairing-response payload, sealed to `userEncPubKey`)
- User-browser → client app (client-pair K bundle, sealed to `clientEncPubKey`)

**Construction** (NOT NaCl-compatible; simpler, fewer deps):

```
1. Generate ephemeral X25519 keypair (epk_priv, epk_pub) per box.
2. shared = X25519(epk_priv, recipient_pub)                   // 32 raw bytes
3. key    = HKDF-SHA-256(shared, salt=ε, info="aviato-sealedbox-v1", L=32)
4. nonce  = 12 random bytes
5. ct     = AES-GCM-256(key, nonce, plaintext, aad?)
6. Output { ephPub, nonce, ct } — each base64url.
```

The recipient computes the same shared via `X25519(recipient_priv, epk_pub)` and decrypts.

**Reference implementation** (browser/Node, ~50 lines): `~/projects/ato/ato.software/packages/tower-web/src/lib/sealedbox.ts`. Uses `@noble/curves/ed25519.js` (for `x25519`), `@noble/hashes/sha2.js` + `@noble/hashes/hkdf.js`, and WebCrypto's AES-GCM. Port this verbatim to wherever your server-side TypeScript / Go / Rust lives — the cross-system contract is `info="aviato-sealedbox-v1"` and AES-GCM-256 with random 12-byte nonce.

**Schema (wire shape)** — defined as `SealedBoxSchema` in `@aviato/common/src/identity/v2/schemas.ts`:

```typescript
{ ct: base64url, ephPub: base64url, nonce: base64url }
```

---

## 3. Schema additions in `@aviato/common`

Already shipped in `~/projects/aviato/aviato/packages/common/src/identity/v2/schemas.ts`:

### Extended schemas (existing payloads now carry new fields)

- **`ClientDelegationCertPayloadSchema`** — added `clientEncPubKey` (hex 64, X25519) and `userEncPubKey` (hex 64, X25519).
- **`MasterSignedAssertionBaseSchema`** — added `userEncPubKey` (hex 64). Inherited by both `ServerLinkAssertionPayloadSchema` and `ServerSignInAssertionPayloadSchema`.

**Server-side impact:** when verifying assertions or certs, your zod schemas already pull these in. Extract `userEncPubKey` from the verified assertion and store it on your user/identity row — you'll need it to seal the K back.

### New schemas

| Schema | Purpose |
|---|---|
| `SealedBoxSchema` | `{ ct, ephPub, nonce }` |
| `ServerConnInfoPayloadSchema` | The plaintext inside `ct` — `{ v:1, publicHost, port, protocol, fingerprint?, paths?, rotationCounter, issuedAtSec }` |
| `ServerConnInfoPublishSchema` | Wire body for `POST /api/identity/server-conninfo` — `{ ct, nonce, serverPubKey (hex), sig (base64url), version }` |
| `ServerConnInfoRecordSchema` | What Tower returns from `GET /server-conninfo/:hash` |
| `PairingResponseSealedSchema` | Plaintext inside the sealed pairing reply — `{ v:1, connInfoKey (base64url 32B), issuedAtSec, serverPubKey (hex) }` |
| `PairingResponsePayloadSchema` | Wire body for `POST /api/identity/pairing/:id/response` — `{ sealed: SealedBox, sig: base64url }` |
| `PairingResponseRecordSchema` | What the browser receives — `{ payload, postedAtSec }` |
| `ClientKeyBundleServerSchema` | Per-server entry in the client-pair bundle — `{ serverPubKey (hex), connInfoKey (base64url) }` |
| `ClientKeyBundleContentsSchema` | The sealed-to-clientEncPubKey bundle — `{ v:1, issuedAtSec, servers: ClientKeyBundleServer[] }` |

Already exported from the v2 barrel (`packages/common/src/identity/v2/index.ts`).

---

## 4. Aviato media server — what to implement

### 4.1 Generate and persist K

On startup (or admin-rotated):
- `K = 32 random bytes`
- Persist alongside your server identity (encrypted at rest with admin password / TPM / OS keystore).

K rarely changes. Rotation is reserved for "admin suspects compromise" — see §6.

### 4.2 Publish connection info to Tower

Whenever connection info changes (boot, DDNS update, port reconfig, fingerprint rotation):

1. Build `ServerConnInfoPayload`:
   ```ts
   const payload: ServerConnInfoPayload = {
     v: 1,
     publicHost: 'media.example.com', // FQDN or IP
     port: 443,
     protocol: 'https',
     fingerprint: '<tls-cert-sha256-hex>', // optional, for cert pinning
     paths: { api: '/api', media: '/media' }, // optional
     rotationCounter: version,                // SAME value as wire `version`
     issuedAtSec: nowSec,
   }
   ```
2. Canonicalize via RFC 8785 JCS → `plaintext = utf8(JCS(payload))`.
3. Generate random 12-byte `nonce`.
4. Compute AEAD AAD (binds ct to its version slot):
   ```
   AAD = utf8("aviato-server-conninfo-v1") ‖
         serverPubKey-hex (64 chars) ‖
         version (8-byte big-endian unsigned)
   ```
5. `ct = AES-GCM-256(K, nonce, plaintext, aad=AAD)` → base64url.
6. Build canonical signed bytes:
   ```
   canonical = utf8(JSON.stringify({
     ct,                  // string in alphabetical-key order
     nonce,
     serverPubKey,        // hex 64 lowercase
     version,
   }))
   ```
   (Equivalent to a 4-key JCS object since alphabetical-sort + JSON.stringify produces deterministic bytes here.)
7. `sig = base64url(Ed25519(serverPrivKey, canonical))`.
8. `POST /api/identity/server-conninfo` to Tower with:
   ```json
   { "serverPubKey": "<hex 64>", "ct": "...", "nonce": "...", "sig": "...", "version": N }
   ```
   - Bearer header: your existing server-registration bearer.
   - Tower verifies sig against your registered pubkey, enforces `version > stored.version`, caps `ct ≤ 8192 chars`, sets 72h TTL.
   - On success: `200 { ok: true, version, lastUpdatedAtSec }`.
   - On stale version: `409 stale_version`.
   - On sig mismatch: `403 invalid_signature`.

**`version` rules:** strictly monotonic, server-managed. Persist your latest published version; on each republish, increment. Don't reset on server restart — use a value derived from `(boot_count * 1e6 + within_boot_counter)` or store the last-used value next to K.

**Republish cadence:** every connection-info change. Also republish at least every ~24h to keep the 72h TTL fresh and the dashboard's "online" badge accurate (Tower's `lastUpdatedAtSec` is the staleness signal). A daily heartbeat republish that just bumps `version` and re-encrypts the same `ServerConnInfoPayload` is the simplest model.

### 4.3 The pairing-response leg

After polling `GET /api/identity/pairing/:requestId` (server-link) or `GET /api/identity/server-sign-in/:requestId` (server-sign-in) and receiving `state: 'completed'` with assertion bytes:

1. Verify the assertion signature with `userPubKey` (extracted from the canonical payload).
2. Extract **`userEncPubKey`** (new field — the user's X25519 pubkey, hex 64) from the assertion payload.
3. Build the sealed reply:
   ```ts
   const sealedPlain: PairingResponseSealed = {
     v: 1,
     connInfoKey: K_base64url,        // your server's K
     issuedAtSec: nowSec,
     serverPubKey: serverPubKey_hex,  // duplicated for cross-check
   }
   const sealed = aviatoSealedBox({
     plaintext: utf8(JCS(sealedPlain)),
     recipientPub: hex2bytes(userEncPubKey),
   })
   ```
4. Sign the sealed body:
   ```
   sigMessage = utf8(serverPubKey_hex) ‖
                utf8(JSON.stringify({ ct: sealed.ct, ephPub: sealed.ephPub, nonce: sealed.nonce }))
   sig = base64url(Ed25519(serverPrivKey, sigMessage))
   ```
   (Alphabetical-key JSON.stringify on the 3-field sealed object — same canonicalization rule as conn-info publish.)
5. `POST /api/identity/pairing/:requestId/response`:
   ```json
   { "sealed": { "ct": "...", "ephPub": "...", "nonce": "..." }, "sig": "..." }
   ```
   - Bearer header: your server-registration bearer.
   - Tower preconditions: row must be in `completed` state, bearer must match `serverId`, kind must be `server-link` or `server-sign-in`.
   - On success: `201 { ok: true }`.
   - Errors: `403 not_owner`, `400 wrong_kind`, `409 not_completed`.

**Both** server-link **and** server-sign-in deliver K via this leg. server-link does the initial handoff at link time; server-sign-in re-delivers the current K on every web sign-in (rotation channel — see §6).

### 4.4 Persisting user encryption keys

When you process a server-link assertion (and on each server-sign-in), store `userEncPubKey` on your `identity_users` (or equivalent) row. Subsequent K rotations need it to seal new K's to that user via the same leg. Update on every assertion — the user can rotate their vault encryption key in the future.

### 4.5 Direct K delivery to authenticated clients

When a paired client (Afterburner / Aviato Web after their cert is verified) authenticates a session, your server's auth response should **also** carry the current K. This is the secondary delivery channel for clients whose cached K has gone stale (server rotated K while the client was offline).

Recommended placement: in the session-startup response, include a sealed envelope:
```ts
{
  aviato_conn_info_key_envelope: aviatoSealedBox({
    plaintext: utf8(JCS({
      v: 1,
      connInfoKey: K_base64url,
      issuedAtSec: nowSec,
    })),
    recipientPub: hex2bytes(clientEncPubKey), // from the cert
  })
}
```
Client decrypts with its `clientEncPriv` and updates its local K cache.

---

## 5. Aviato Web — what to implement

### 5.1 Use `client-pair`, not `server-sign-in`

Aviato Web is a *client application* that needs K for the user's linked servers. Although it looks like a "sign in to a website" flow, structurally it's the same as Afterburner — a delegation cert plus a sealed bundle of per-server K material.

UX surface: "Sign in to Aviato" → triggers a client-pair flow on Tower. Aviato Web stores its keypairs in `localStorage` (acknowledged tradeoff: cleared cache / different profile = re-pair, but acceptable for a web context).

### 5.2 Generate two keypairs at first run

```ts
// Ed25519 — used to sign session assertions against media servers
const signKeys = Ed25519.keygen()       // 32-byte priv seed + 32-byte pub
// X25519 — used to receive sealed K bundles and rotated-K envelopes
const encKeys = X25519.keygen()         // 32-byte priv + 32-byte pub
localStorage.setItem('aviatoSignPriv', base64url(signKeys.priv))
localStorage.setItem('aviatoSignPub',  base64url(signKeys.pub))
localStorage.setItem('aviatoEncPriv',  base64url(encKeys.priv))
localStorage.setItem('aviatoEncPub',   base64url(encKeys.pub))
```

### 5.3 Initiate the client-pair flow

`POST https://tower.aviato.media/api/identity/clients/pair/begin`:
```json
{
  "appId": "aviato-web",
  "clientPubKey":    "<base64url 32B Ed25519>",
  "clientEncPubKey": "<base64url 32B X25519>",
  "displayName": "Aviato Web on Firefox",
  "platform": "web"
}
```
Returns `{ requestId, code, expiresAt }`. Surface the `code` to the user (auto-link via `https://tower.aviato.media/pair?code=XXXXXXXX`).

Then poll `GET /api/identity/clients/pair/:requestId` every ~1.5s until `state === 'completed'`. On completion the response now includes:

```json
{
  "state": "completed",
  "signedCertBytes": "<base64url JCS bytes>",
  "certSignature":   "<base64url Ed25519 sig>",
  "sealedConnInfoBundle": {
    "ct": "...",
    "ephPub": "...",
    "nonce": "..."
  }
}
```

### 5.4 Decrypt the bundle

```ts
const bundleBytes = aviatoSealedBoxDecrypt({
  box: sealedConnInfoBundle,
  recipientPriv: base64urlDecode(localStorage.getItem('aviatoEncPriv')!),
})
const bundle: ClientKeyBundleContents = JSON.parse(utf8Decode(bundleBytes!))
// bundle.servers: [{ serverPubKey: hex, connInfoKey: base64url }, ...]
```

Persist the K-by-serverPubKey map in `localStorage` (or IndexedDB if you want to be neat). Each entry is needed to decrypt `SERVER_CONNINFO` rows.

### 5.5 Fetch and decrypt a server's connection info

```ts
const serverPubKeyBytes = hex2bytes(server.serverPubKey)
const hash = base64url(sha256(serverPubKeyBytes))
const row = await fetch(`https://tower.aviato.media/api/identity/server-conninfo/${hash}`)
  .then((r) => r.ok ? r.json() : null)
if (!row) {
  // 404 — server hasn't reported in 72h. Show "offline".
  return
}
// Verify Tower hasn't tampered with the row (defense in depth — Tower already verifies
// on publish, but verifying again here protects against a compromised cache layer).
const canonical = utf8(JSON.stringify({
  ct: row.ct, nonce: row.nonce, serverPubKey: row.serverPubKey, version: row.version,
}))
const sigOk = Ed25519.verify(hex2bytes(row.serverPubKey), canonical, base64urlDecode(row.sig))
if (!sigOk) throw new Error('server-conninfo sig invalid')

// Decrypt with K from the bundle:
const K = base64urlDecode(bundle.servers.find((s) => s.serverPubKey === row.serverPubKey)!.connInfoKey)
const aad = concatBytes(
  utf8("aviato-server-conninfo-v1"),
  utf8(row.serverPubKey),
  bigEndianU64(row.version),
)
const plaintext = AES_GCM_256.decrypt(K, base64urlDecode(row.nonce), base64urlDecode(row.ct), aad)
const info: ServerConnInfoPayload = JSON.parse(utf8Decode(plaintext))
// info.publicHost, info.port, info.protocol, ...
```

If AEAD decrypt fails → server has rotated K and this client has stale K. Prompt the user to re-pair (the new pair will deliver a fresh bundle).

### 5.6 Handle K rotation in-session

When Aviato Web authenticates to a media server (using its cert), the server's session response includes a sealed K envelope (§4.5). Decrypt with `aviatoEncPriv` and update the local K cache. Next `/server-conninfo/:hash` fetch will decrypt cleanly.

### 5.7 Authenticate to a media server

Using the existing `IdentitySessionAssertion` flow (cert + per-session signed challenge). No change required there — that's all pre-existing.

---

## 6. End-to-end flows

### 6.1 First server link

```
User browser (Tower-web)            Tower               Media server
       │                              │                      │
       │ approve at /pair             │                      │
       │ POST /code/<code>/complete  │                      │
       │   { signedAssertionBytes,    │                      │
       │     assertionSignature }     │                      │
       │ ────────────────────────────▶│                      │
       │                              │ GET /pairing/:id     │
       │                              │◄─────────────────────│
       │                              │  { signedAssertion } │
       │                              │ ────────────────────▶│
       │                              │                      │ verify assertion
       │                              │                      │ extract userEncPubKey
       │                              │                      │ seal K → POST
       │                              │ POST /pairing/:id/response
       │                              │◄─────────────────────│
       │ poll /pairing-response/:id   │                      │
       │ ────────────────────────────▶│                      │
       │  { payload: { sealed, sig } }│                      │
       │ ◄────────────────────────────│                      │
       │ verify sig with serverPub    │                      │
       │ decrypt sealed with encKeyPriv                      │
       │ save K to vault.servers[i].connInfoKey              │
```

### 6.2 Web sign-in (server-sign-in) with K refresh

Same shape as 6.1 but with the `server-sign-in` kind. Browser polls `/pairing-response/:requestId` after `/complete`; server delivers (possibly rotated) K. Browser updates `vault.servers[i].connInfoKey` in place.

### 6.3 Client-pair with sealed bundle

```
Client app                  Tower                       User browser
    │                         │                              │
    │ POST /clients/pair/begin│                              │
    │  { clientPubKey,        │                              │
    │    clientEncPubKey,     │                              │
    │    appId, ... }         │                              │
    │ ────────────────────────▶                              │
    │  { requestId, code }    │                              │
    │ ◄────────────────────────                              │
    │ display code            │                              │
    │                         │ /pair?code=XXXX              │
    │                         │ ────────────────────────────▶│
    │                         │                              │ approve, build cert + bundle
    │                         │ POST /code/<code>/complete   │
    │                         │  { signedCertBytes,          │
    │                         │    certSignature,            │
    │                         │    sealedConnInfoBundle }    │
    │                         │ ◄─────────────────────────────
    │ poll /clients/pair/:id  │                              │
    │ ────────────────────────▶                              │
    │  { cert, sealedBundle } │                              │
    │ ◄────────────────────────                              │
    │ decrypt bundle with     │                              │
    │ clientEncPriv → K map   │                              │
```

### 6.4 Connection fetch

```
Client                     Tower
  │ GET /server-conninfo/<hash>     (unauthenticated, 30s public cache)
  │ ────────────────────────────────▶
  │  { ct, nonce, sig, version,     │
  │    serverPubKey, lastUpdatedAtSec}
  │ ◄────────────────────────────────
  │ verify sig
  │ AEAD-decrypt ct with K (via the per-server-AAD construction)
  │ → connect to publicHost:port
```

---

## 7. Implementation checklist

### Aviato media server

- [ ] Persist a 32-byte K on disk (encrypted), generated once.
- [ ] Port the sealedbox primitive (`x25519` + `HKDF-SHA-256` + `AES-GCM-256`).
- [ ] Implement `publishConnInfo()` that builds `ServerConnInfoPayload`, encrypts with K (per-version AAD), signs canonical wire body, and POSTs to Tower. Wire into:
  - Server startup
  - DDNS / port / cert-fingerprint change handlers
  - A daily heartbeat timer
- [ ] After verifying any incoming `server-link` or `server-sign-in` assertion, extract `userEncPubKey`, seal K to it, sign, and POST to `/pairing/:requestId/response`. Apply to **both** kinds.
- [ ] Store `userEncPubKey` on the user record so future rotations can re-seal K without a new sign-in ceremony.
- [ ] Add `clientEncPubKey` storage to your `identity_clients` row (so you can send rotated-K envelopes through the session response).
- [ ] In session-startup responses to authenticated clients, include the current K sealed to `clientEncPubKey`.
- [ ] If you support admin K rotation: rotate K, re-`publishConnInfo()` with the new ct (and `version+1`), and document that all existing clients will need either a re-pair OR a fresh session to learn new K.

### Aviato Web

- [ ] Generate Ed25519 + X25519 keypairs at first run, persist in localStorage.
- [ ] Implement the client-pair flow against Tower (begin / poll / pair page surface). The "sign in" UX is a thin wrapper.
- [ ] Decrypt `sealedConnInfoBundle` on pair completion, store the K-by-serverPubKey map locally.
- [ ] Implement `getServerConnInfo(serverPubKey)`:
  1. Compute `sha256(serverPubKey).base64url`.
  2. `GET /server-conninfo/<hash>`.
  3. Verify Ed25519 sig against `serverPubKey`.
  4. AEAD-decrypt with K (using the per-version AAD).
  5. Return parsed `ServerConnInfoPayload`.
- [ ] Handle AEAD failure → prompt re-pair, OR opportunistically refresh K from the next server session response.
- [ ] On every successful media-server authentication, decode the server's session-response K envelope and update the local K cache.

### `@aviato/common` (already done in Tower's PR — pull these in)

- [ ] `userEncPubKey` field on `MasterSignedAssertionBaseSchema` (both server-link + server-sign-in assertions).
- [ ] `clientEncPubKey` + `userEncPubKey` fields on `ClientDelegationCertPayloadSchema`.
- [ ] New: `SealedBoxSchema`, `ServerConnInfoPayloadSchema`, `ServerConnInfoPublishSchema`, `ServerConnInfoRecordSchema`, `PairingResponseSealedSchema`, `PairingResponsePayloadSchema`, `PairingResponseRecordSchema`, `ClientKeyBundleServerSchema`, `ClientKeyBundleContentsSchema`.
- [ ] All exported from the v2 barrel.

---

## 8. Endpoint reference (Tower-side, all live)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/identity/server-conninfo` | server bearer | Publish encrypted conn info. Sig over canonical body verified against registered pubkey. Strict-monotonic version. ct ≤ 8 KiB. |
| `GET` | `/api/identity/server-conninfo/:hash` | none | Return the row. `:hash = sha256(serverPubKey).base64url` (43 chars). 30s public cache. |
| `POST` | `/api/identity/pairing/:requestId/response` | server bearer | Attach sealed reply. Row must be in `completed`, kind in {server-link, server-sign-in}. |
| `GET` | `/api/identity/pairing-response/:requestId` | none | 200 with `{ payload, postedAtSec }` once attached; 204 pending; 404 expired/missing. |
| `POST` | `/api/identity/clients/pair/begin` | none | Now requires `clientEncPubKey` (base64url 32B X25519). |
| `GET` | `/api/identity/clients/pair/:requestId` | requestId capability | Returns `sealedConnInfoBundle` alongside cert when completed. |
| `POST` | `/api/identity/code/:code/complete` | session | Now accepts `sealedConnInfoBundle` field for client-pair approvals. |

---

## 9. Crypto recipe summary (cross-implementation truth)

### sealedbox
```
ephPriv          : random 32 bytes (X25519 secret)
ephPub           : x25519.getPublicKey(ephPriv)               // 32 bytes
shared           : x25519.getSharedSecret(ephPriv, recipPub)  // 32 bytes
key              : hkdf(sha256, shared, salt=ε, info="aviato-sealedbox-v1", L=32)
nonce            : random 12 bytes
ct               : AES-GCM-256(key, nonce, plaintext, aad?)
output           : { ephPub, nonce, ct } base64url
```

### SERVER_CONNINFO AEAD
```
plaintext        : utf8(JCS(ServerConnInfoPayload))
nonce            : random 12 bytes
aad              : utf8("aviato-server-conninfo-v1") ‖ serverPubKey-hex ‖ u64-BE(version)
K                : 32 bytes (server-generated AES-GCM-256 key)
ct               : AES-GCM-256(K, nonce, plaintext, aad)
```

### SERVER_CONNINFO publish signature
```
message          : utf8(JSON.stringify({ ct, nonce, serverPubKey, version }))   // alphabetical keys
sig              : base64url(Ed25519(serverPrivKey, message))
```

### Pairing-response sealed body
```
plaintext        : utf8(JCS(PairingResponseSealed{ v:1, connInfoKey, issuedAtSec, serverPubKey }))
sealedbox        : aviatoSealedBox(plaintext, recipientPub=hex2bytes(userEncPubKey))
sigMessage       : utf8(serverPubKey-hex) ‖ utf8(JSON.stringify({ ct, ephPub, nonce })) // alphabetical
sig              : base64url(Ed25519(serverPrivKey, sigMessage))
wire             : { sealed: { ct, ephPub, nonce }, sig }
```

### Client-pair sealed bundle
```
plaintext        : utf8(JSON.stringify(ClientKeyBundleContents))  // any JSON ok — recipient just parses
sealed           : aviatoSealedBox(plaintext, recipientPub=hex2bytes(clientEncPubKey))
wire             : { ct, ephPub, nonce }  (forwarded by Tower as `sealedConnInfoBundle`)
```

---

## 10. References

- Tower-side reference impl:
  - `~/projects/ato/ato.software/packages/tower-web/src/lib/sealedbox.ts` — sealedbox + X25519 keygen
  - `~/projects/ato/ato.software/packages/tower-web/src/lib/pairing-response.ts` — verify + decrypt
  - `~/projects/ato/ato.software/packages/tower-api/src/lib/identity-server-conninfo-db.ts` — DDB layer
  - `~/projects/ato/ato.software/packages/tower-api/src/routes/identity-server-conninfo.ts` — endpoints
  - `~/projects/ato/ato.software/packages/tower-api/src/routes/identity-pairing.ts` — pairing-response endpoints
- Schemas (the cross-system contract):
  - `~/projects/aviato/aviato/packages/common/src/identity/v2/schemas.ts`
- Original design discussion (context, alternatives considered):
  - This decision log was developed iteratively in a Claude Code session with the Tower author; the design rejected a per-user Tower-side mailbox because it would have leaked user↔server linkage in the persistent DB, then re-validated the simpler approach where K travels via the pairing-response leg (server-link / server-sign-in) and the sealed bundle (client-pair).
