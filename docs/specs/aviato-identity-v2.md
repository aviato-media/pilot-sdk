# Aviato Identity v2 — Tower-Brokered SSO Spec

Status: design baseline confirmed 2026-05-16. Supersedes parts of `docs/aviato-identity-whitepaper.md` (the v1 whitepaper) — see §0.

This is the implementable spec for "Sign in with Aviato Identity". Two coordinated implementation plans build against it:

- `docs/specs/aviato-identity-server-plan.md` — Aviato media server + web (this repo)
- `~/projects/ato/ato.software/aviato-identity-tower-plan.md` — Tower (ato.software repo)

## 0. Differences from the v1 whitepaper

The v1 whitepaper described:

- A single Ed25519 master keypair shared across all of a user's devices.
- Cross-device sync of `user:keychain` and `user:profile` via a relay network embedded in each server.
- Key escrow as a seed-phrase-derived encrypted blob held by the central service.
- Passkey on the central service only as a *retrieval gate* for the escrowed master key.

v2 changes:

1. **Master key never leaves the vault unencrypted on any device.** Devices get their own per-device Ed25519 keys; the master key is only briefly in RAM during enrollment ceremonies to sign delegation certs.
2. **Per-client delegation certs.** Each device authenticates to servers with its own keypair + a short-TTL cert signed by the master key. Compromise of one device leaks one client cert, not the master.
3. **Vault encryption is passkey-PRF.** Random vault key (VK) wrapped per-passkey via the WebAuthn PRF extension. No seed-phrase ceremony in the common path (seed phrase remains as offline fallback).
4. **Server list lives in the Tower-hosted vault, encrypted client-side.** The relay-network keychain sync (v1 §7) is no longer the primary mechanism for cross-device server-list sync — Tower vault is. Relays MAY still exist for `server:record` distribution; that decision is out of scope for v2 and not required by this spec.
5. **Pairing-code flow added.** v1 only covered URL-based invite links; v2 adds 8-digit numeric codes + QR + deep links so TVs, consoles, and other constrained devices can sign in by hopping to a phone or laptop.
6. **Tower-Identity is one auth method among several.** v1 password and v1 invite-challenge auth keep working. v2 is additive.

What v2 keeps from v1:

- Ed25519 throughout.
- ACL is server-local; the server is the sole authority on access (v1 §5).
- Invites are required to gain access to a server (v1 §6) — no public registration.
- Tower (central service) cannot see plaintext server lists, server addresses, or which users are on which servers.
- Tower cannot impersonate users to servers.

## 1. Threat model

Adversary capabilities considered:

| Adversary | What they can do |
|---|---|
| Network attacker (passive) | Sees ciphertext traffic. Mitigated: TLS + signed payloads. |
| Network attacker (active MITM on first link) | Can substitute a master pubkey on a fresh server pairing. Mitigated: TOFU fingerprint shown on both Tower and the server's settings UI, user-visual confirms. |
| Compromised Tower web app | Can serve malicious JS during a vault-open browser session and exfiltrate the master key. Mitigated: SRI + strict CSP; native apps perform crypto natively. This is the residual risk. |
| Compromised Tower API + DB | Can read encrypted vault blobs (useless without VK), refuse service (DoS), refuse cert renewals (DoS), substitute vault blobs (rejected — AEAD tag fails). Cannot forge identity assertions or read server lists. |
| Compromised user device | Leaks that device's client private key + any cached session tokens. Other devices unaffected. User revokes the cert via Tower. |
| Lost passkey | Other passkeys (or recovery codes per v1 model) recover the vault. |
| Compromised media server | Affects only that server's content. Cannot impersonate the user to other servers. |

Explicit non-goals: hiding from Tower *that* a user exists or *how many* servers they have (Tower sees number of vault entries and pairing requests); resisting endpoint malware on a fully compromised device.

## 2. Cryptographic primitives

| Use | Algorithm |
|---|---|
| Identity signatures | Ed25519 |
| Client-key signatures | Ed25519 |
| Vault payload encryption | AES-256-GCM (12-byte IV, 16-byte tag) |
| Vault-key wrap per passkey | AES-256-GCM (12-byte IV, 16-byte tag) |
| PRF-output → wrap-key derivation | HKDF-SHA256, info = `"aviato-vault-wrap/v1"` |
| Cert + assertion canonicalization | RFC 8785 JCS (JSON Canonicalization Scheme) — JS implementations MUST use the [`canonicalize`](https://www.npmjs.com/package/canonicalize) npm package (authored by the RFC author) or a byte-equivalent implementation in another language |
| Pairing code | 8 decimal digits (cryptographically random) |

Rationale: matches existing primitives in `packages/crypto/` (Ed25519 via tweetnacl, HKDF via @noble/hashes) and Tower's existing SimpleWebAuthn integration. AES-GCM via Web Crypto API on browsers, `node:crypto` on the server.

## 3. Key & data model

### 3.1 Keys

- **M** — User master Ed25519 keypair. Pub published in vault; priv held *only* in encrypted vault on Tower.
- **VK** — Vault key, 32 random bytes. Wraps the vault payload. Each enrolled passkey wraps a copy via PRF.
- **PRF<sub>i</sub>** — Output of WebAuthn PRF extension when authenticating with passkey i. 32 bytes.
- **C<sub>n</sub>** — Per-client Ed25519 keypair generated locally on each device. Priv stored in OS secure storage (Keychain/Keystore/TPM); priv never leaves the device.

### 3.2 Vault format on Tower

Stored opaquely. Tower never decrypts. Schema (JSON, then `JSON.stringify` for transport):

```json
{
  "version": 1,
  "ciphertext": "<base64 AES-GCM ciphertext of vault payload>",
  "iv": "<base64 12 bytes>",
  "wraps": [
    {
      "credentialId": "<base64url passkey credential ID>",
      "prfSalt": "<base64 32 bytes — fixed per-Aviato salt for PRF input>",
      "wrappedKey": "<base64 AES-GCM ciphertext of VK>",
      "wrapIv": "<base64 12 bytes>"
    }
  ],
  "createdAt": <unix ms>,
  "updatedAt": <unix ms>
}
```

`prfSalt` is per-passkey-randomized to ensure PRF outputs differ even if two passkeys somehow shared backing keys. Salt is sent as the PRF `eval.first` input.

### 3.3 Vault payload (plaintext after VK-decrypt)

```json
{
  "version": 1,
  "master": {
    "privKey": "<base64 32-byte Ed25519 seed>",
    "pubKey": "<hex 32-byte Ed25519 pub>"
  },
  "servers": [
    {
      "serverId": "<server's Ed25519 pubkey, hex>",
      "baseUrl": "https://media.example.com",
      "name": "Home media server",
      "linkedAt": <unix ms>,
      "lastFingerprintVerified": <unix ms | null>
    }
  ],
  "clients": [
    {
      "clientId": "<uuidv4>",
      "deviceName": "Ben's iPhone",
      "platform": "ios" | "android" | "web" | "tvos" | "macos" | "windows" | "linux",
      "createdAt": <unix ms>,
      "currentCertExp": <unix ms>,
      "revoked": false
    }
  ]
}
```

### 3.4 Client delegation cert format

Wire format is canonicalized JSON (RFC 8785 JCS), then base64url. The signed payload:

```json
{
  "v": 1,
  "userId": "<Tower-issued opaque user uuid>",
  "userPubKey": "<hex M.pub>",
  "clientId": "<uuidv4 — matches vault.clients[].clientId>",
  "clientPubKey": "<hex Cn.pub>",
  "appId": "<app id the user paired through, e.g. app_serenity>",
  "deviceName": "Ben's iPhone",
  "scope": ["servers:*"],
  "iat": <unix sec>,
  "exp": <unix sec>
}
```

Keys appear in RFC 8785 JCS canonical order (lexicographic). The `appId` claim binds the cert to the third-party app that the user paired through; servers MAY filter sessions by `appId` if they want to. The user-approved subset of `vault.servers` is delivered to the client app **alongside** the cert in the pairing-complete response (see §4.4); it is not embedded in the cert payload.

Issued cert envelope:

```json
{
  "payload": "<base64url JCS-canonical bytes of the above>",
  "sig": "<base64url Ed25519 signature by M over payload bytes>"
}
```

TTL: **60 days**. Renewable at the **30-day** mark (matches Let's Encrypt model). If unrenewed, client must re-pair through Tower.

### 3.5 Identity session-auth assertion (client → server, per session)

```json
{
  "cert": { "payload": "...", "sig": "..." },
  "serverId": "<server pubkey hex>",
  "challenge": "<server-issued nonce, hex>",
  "ts": <unix ms>,
  "sig": "<base64url Ed25519 sig by Cn over JCS(rest of this object minus sig)>"
}
```

Server verifies in order: cert.sig against cert.userPubKey, cert not expired, sig against cert.clientPubKey, serverId matches own ID, challenge fresh and unused, ts within ±60s skew. If user has a stored revocation list (master-signed), check `clientId` not revoked.

### 3.6 Server-pairing assertion (browser → Tower → server, at link time)

Signed by **M** (not C — this is the first-link enrollment where the user accepts a server into their identity). Wire envelope, matching Tower's `{signedAssertionBytes, assertionSignature}` shape:

```json
{
  "payload": "<base64url JCS-canonical bytes of the payload below>",
  "sig":     "<base64url Ed25519 sig by M over the payload bytes>"
}
```

Payload (keys in JCS lexicographic order):

```json
{
  "kind": "server-link",
  "requestId": "<Tower pairing request id>",
  "serverPubKey": "<hex server pubkey>",
  "ts": <unix ms>,
  "userId": "<Tower user uuid>",
  "userPubKey": "<hex M.pub>",
  "v": 1
}
```

The first issued cert for the device that completes this flow is bundled with the response: `{ assertion, cert }`.

> **Cross-repo encoding contract:** Tower's `/api/identity/server-registration` accepts `serverPubKey` as **base64url** (Tower's decoder uses `Buffer.from(_, 'base64url')`), and reflects whatever encoding it stored back to the browser through the pairing context (`/api/identity/code/:code/resolve`). The server-link assertion's `serverPubKey` field is defined as **hex** by this spec (`HEX_32_BYTES` in `ServerLinkAssertionPayloadSchema`). **Tower-web is responsible for converting base64url → hex when constructing the assertion payload to sign.** If Tower-web embeds the raw base64url string instead, the Aviato server rejects the assertion with `assertion_payload_schema_invalid` before signature verification ever runs.

### 3.6a Server-sign-in assertion (browser → Tower → server, per session)

A second M-signed assertion used by the **browser-driven sign-in flow** to a server the user has already linked. Unlike `server-link`, no cert is issued and the assertion is consumed by the Aviato server exactly once to mint a session. The web frontend is not a long-lived client — there's no per-device keypair, no `vault.clients[]` entry on Tower, and no cert chain. Sign-in is one passkey tap.

Wire envelope:

```json
{
  "payload": "<base64url JCS-canonical bytes of the payload below>",
  "sig":     "<base64url Ed25519 sig by M over the payload bytes>"
}
```

Payload (keys in JCS lexicographic order):

```json
{
  "kind": "server-sign-in",
  "requestId": "<Tower pairing request id>",
  "serverPubKey": "<hex server pubkey>",
  "ts": <unix ms>,
  "userId": "<Tower user uuid>",
  "userPubKey": "<hex M.pub>",
  "v": 1
}
```

Differences from `server-link`:

- The Aviato server **brokers** the pairing (server-bearer-authed `POST /api/identity/server-sign-in/begin`); Tower enforces that `serverPubKey` matches the bearer's owning server, so a server can only initiate sign-ins for itself.
- Tower-web's `/pair` page shows the resolved server name and a single "Sign in to **\<name\>**?" consent button. There is no device-name or scope prompt.
- On approval, Tower stores the master-signed assertion against the requestId. The brokering Aviato server's poll returns `{state: 'completed', signedAssertionBytes, assertionSignature}` once.
- The Aviato server consumes the local pairing entry the moment it sees `state: completed` (before signature verification), then verifies and mints a session via `createSession`. The pairing is single-use across both Tower and Aviato.
- The `serverPubKey` encoding contract from §3.6 applies identically here.

Tower endpoint pair:

- `POST /api/identity/server-sign-in/begin` — server-bearer authed; body `{serverPubKey, serverName?}`; returns `{requestId, code, expiresAt}`.
- `GET /api/identity/server-sign-in/:requestId` — server-bearer authed; returns `{state, requestId, expiresAt, signedAssertionBytes?, assertionSignature?}`.

### 3.7 Revocation envelope (M-signed, user-initiated)

Wire envelope, matching Tower's `{signedEnvelopeBytes, envelopeSignature}` shape:

```json
{
  "payload": "<base64url JCS-canonical bytes of the payload below>",
  "sig":     "<base64url Ed25519 sig by M over the payload bytes>"
}
```

Payload (keys in JCS lexicographic order):

```json
{
  "certId": "<sha256(clientPubKey-bytes), 64 hex chars>",
  "kind": "client-revoke",
  "reason": "<optional human-readable, max 256 chars>",
  "revokedAt": "<ISO 8601 timestamp>",
  "userId": "<Tower user uuid>",
  "v": 1
}
```

`certId` is `sha256(clientPubKey)` — a pubkey-derived stable identifier so the same signed envelope can be posted to Tower's `/api/identity/revocations` CRL feed AND pushed directly to a media server. Servers match by computing `sha256` over each stored `clientPubKey` and looking for `=== payload.certId`.

Tower exposes the public feed at `GET /api/identity/revocations?since=<ts>` (no auth, signed by M so Tower can't forge). Servers can also accept revocations via authenticated push from another of the user's devices.

## 4. Flows

### 4.1 Account creation on Tower (first ever)

Registration and vault initialization are two separate ceremonies, each round-trip-validated. Tower's existing `/api/auth/register/begin|complete` handlers create the user + first passkey; vault creation is a follow-up call.

1. User opens `tower.aviato.media/signup`. Provides email.
2. Browser calls `POST /api/auth/register/begin { email }`. Server generates a fresh `prfSalt` (32 random bytes, base64url), stores it on the challenge row, and returns `{ challengeId, userId, options, prfSalt }` where `options` includes `extensions.prf.eval.first = prfSalt`. Authenticators without PRF support fail at this step; surface a clear error pointing to the seed-phrase fallback.
3. Browser calls WebAuthn `create()` with the returned options. Captures the PRF result.
4. Browser generates the master Ed25519 keypair locally. Derives the wrap-key from PRF output via HKDF. Generates VK. Encrypts the vault payload (§3.3) under VK. Wraps VK under the wrap-key.
5. Browser calls `POST /api/auth/register/complete { challengeId, credential, ed25519Pubkey: M.pub }`. Server verifies the passkey registration (SimpleWebAuthn), persists `UserRow` with `M.pub`, persists `PasskeyRow` with the stored `prfSalt + prfEnabled + v2: true`, issues a session cookie, returns `{ userId, email, recoveryCodes, prfEnabled }`.
6. Browser calls `POST /api/identity/vault/init { ciphertext, iv, wraps: [{ credentialId, prfSalt, wrappedKey, wrapIv }] }` with the session cookie. Tower persists the `VaultRow` (transactionally with the `ed25519Pubkey` write was already done at step 5).
7. Browser stores VK in memory for the session.

### 4.2 Adding another passkey

1. User signs in (4.5). Vault is open, VK in memory.
2. Browser does WebAuthn `create()` with PRF extension. Captures PRF output of the new passkey. Derives wrap-key. Wraps VK. Appends `{credentialId, prfSalt, wrappedKey, wrapIv}` to `vault.wraps`.
3. POSTs vault update + new passkey registration response to Tower.

### 4.3 Removing a passkey

1. Open vault.
2. Generate fresh VK' and IV'. Re-encrypt payload. Re-wrap to all *remaining* passkeys. Drop the removed passkey's wrap entry.
3. Push new vault + delete-passkey request to Tower.

### 4.4 Signing in to a client app (turns blank app into authed app)

Variants by device class:

- **Web/desktop**: deep link `https://tower.aviato.media/clients/pair?app=<appId>&callback=<https-url>&state=<rand>` opens in default browser. After auth, Tower posts cert + vault back to callback URL.
- **Mobile**: deep link via universal links / custom scheme into Tower's app or web fallback.
- **TV/console**: app generates client keypair, calls `POST /api/identity/clients/pair/begin` on Tower with `Cn.pub`, gets pairing code `XYZ-12345` + pollUrl. App displays code; user enters at `tower.aviato.media/pair` on phone.

Common path:

1. Client app generates Cn (Ed25519). Stores Cn.priv in secure storage.
2. Pairing flow brings user to Tower-authenticated context. Vault opens (passkey + PRF). M briefly in RAM.
3. Browser signs cert payload for Cn.pub with M. Cert returned to client app + vault.servers list.
4. Client app stores cert. Discards M (M was never on this device). Stores vault.servers cleartext locally (it's not a secret to this device — it's the user's own data on their own device).

### 4.5 Signing in to Tower itself (browser-only)

Login is **two WebAuthn ceremonies**. The first authenticates the user without knowing which user it is in advance (discoverable credential). Only after the server identifies the matched passkey can it return the real per-passkey `prfSalt`. A second silent assertion then runs PRF against the correct salt to unlock the vault.

This double-ceremony pattern is necessary because `login/begin` cannot know the userId yet — a usernameless flow has no per-user lookup until after the credential is presented. Apple iCloud Keychain uses the same shape for the same reason.

1. User visits `tower.aviato.media/login`.
2. Browser calls `POST /api/auth/login/begin {}`. Server returns `{ challengeId, options }` where `options` includes `extensions.prf.eval.first = probeSalt` (a per-challenge random salt — the PRF result against it is intentionally discarded). The probe causes the authenticator to surface its PRF UI gate just once.
3. Browser calls WebAuthn `get()` with the returned options. User picks a credential.
4. Browser calls `POST /api/auth/login/complete { challengeId, credential }`. Server verifies the assertion, resolves the user + matched passkey, issues a session cookie, and returns `{ userId, email, credentialId, prfSalt }` — the real per-passkey salt for the second ceremony.
5. Browser calls `POST /api/identity/vault/prf-challenge { credentialId }`. Server returns `{ challengeId, prfSalt, options }` where `options` has `allowCredentials: [{ id: credentialId }]` and `extensions.prf.eval.first = prfSalt` (the real salt).
6. Browser calls WebAuthn `get()` with the new options. Because `allowCredentials` pre-selects the credential, platform authenticators (Touch ID / Face ID / Windows Hello) typically complete this silently with no additional UI.
7. Browser calls `POST /api/identity/vault/prf-verify { challengeId, credential }`. Server verifies the assertion (counter, signature) and bumps the passkey row. PRF output bytes never reach the server — they stay client-side in `credential.clientExtensionResults.prf.results.first`.
8. Browser derives the wrap-key from PRF output via HKDF. Browser calls `GET /api/identity/vault`. Browser finds the wrap entry whose `credentialId` matches the just-used passkey, decrypts `wrappedKey` with the wrap-key to obtain VK, decrypts the vault payload with VK.
9. Browser stores VK in memory for the session.

### 4.6 Adding a new server to the user's identity (server-link)

Triggered from either:
- The server admin's invite link landing page in the user's browser, where they choose "Link via Aviato Tower-Identity"; or
- An already-authenticated session inside the media server's web UI, from Settings > Profile > "Link Aviato Tower-Identity" (replaces password auth for that local user — see §4.7).

1. The media server creates a *pairing request*: `POST /api/auth/identity-link/start` with `{ inviteToken | localUserId, serverId, requestedScope }`. Internally the server calls Tower's `POST /api/identity/pairing/register` with its bearer token. Returns `{ requestId, pairingCode, pollUrl, pairingUrl }` to the browser.
2. Server displays the pairing code (or auto-opens `pairingUrl` in a new tab, depending on device class).
3. User completes pairing at Tower: vault opens (per §4.5). Browser calls `GET /api/identity/code/{pairingCode}/resolve` from Tower — the unified resolve endpoint identifies the request kind (`server-link`) and returns the pairing context (`serverName`, `serverIcon`, `scope`, `requestId`). Browser signs the server-link assertion (§3.6) with M, calls `POST /api/identity/code/{pairingCode}/complete { approve: true, signedAssertionBytes, assertionSignature }`.
4. Media server, polling Tower's `GET /api/identity/pairing/{requestId}` with its bearer, receives `{ state: 'completed', signedAssertionBytes, assertionSignature }`. Server verifies the Ed25519 signature against M.pub (which it learns from the assertion payload), adds M.pub to its ACL (reusing `packages/server/src/identity/acl.ts:addPublicKey`), creates or updates the local user record, and stores `inviteToken`-derived role + library access.
5. Browser also issues a cert for the device that drove the flow (so the user is signed in to that device's app on this server going forward).
6. Browser updates vault: adds server entry. Pushes vault to Tower via `PUT /api/identity/vault` with `If-Match: <etag>`.

### 4.7 Linking a local username/password user to Tower-Identity

From inside an authenticated media-server session:

1. Settings > Profile > "Link Aviato Tower-Identity" → server creates a pairing request scoped to the *existing* local userId.
2. User completes pairing at Tower (4.6 flow).
3. Server replaces `users.passwordHash` with NULL, sets `users.publicKey = M.pub`, stores `users.towerUserId`.
4. From now on the user signs in via Tower-Identity. Existing local sessions remain valid until expiry.

### 4.8 Cert renewal

1. Background task in client app on launch + daily: check current cert age. If `now > iat + 30d` and `< exp`, attempt renewal.
2. Client signs `{kind: "cert-renewal", clientId, currentCertExp, ts}` with Cn. POSTs to `POST /api/identity/clients/{clientId}/renew` on Tower.
3. If Tower has a *pre-issued* renewal cert for this client (placed there by the user's browser during their last Tower sign-in), Tower returns it.
4. Otherwise Tower returns `202 pending` — the client will retry. The next time the user signs in to Tower in a browser, vault opens, browser iterates `vault.clients` and for any with `currentCertExp - now < 30d`, issues a fresh cert and uploads it to Tower keyed by `clientId`.
5. If `exp` passes without renewal, the client must do a full re-pair (4.4).

### 4.9 Revocation

User goes to Tower > Devices, clicks "Revoke" on a client. Browser signs the revocation envelope (§3.7) with M. Tower stores it. Servers pick it up either by polling Tower's CRL endpoint or by accepting a push from another of the user's devices (best-effort, sent through any cert-auth session).

## 5. API surface (cross-repo coordination)

Names are normative; both repos must agree.

### 5.1 Tower endpoints (ato.software side implements)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/identity/vault/init` | Session cookie | Persist the initial vault blob (ciphertext + iv + wraps[]) and set `UserRow.ed25519Pubkey` to M.pub. Called immediately after `/api/auth/register/complete`. Returns `{ etag, version, createdAt }`. 409 `vault_already_initialized` if a vault already exists. |
| `GET` | `/api/identity/vault` | Session cookie | Fetch the authenticated user's vault blob. Returns `{ ciphertext, iv, wraps, etag, version, createdAt, updatedAt }`. Also sets the `ETag` HTTP response header. |
| `PUT` | `/api/identity/vault` | Session cookie + `If-Match: <etag>` | Replace the vault blob atomically. 428 `if_match_required` if header missing. 409 `vault_conflict` with `currentEtag` if the etag doesn't match. Returns `{ etag, version, updatedAt }`. |
| `POST` | `/api/identity/vault/prf-challenge` | Session cookie | Issue a short-lived WebAuthn authentication challenge whose sole purpose is to produce a PRF output for vault unlock. Body: `{ credentialId }`. Returns `{ challengeId, prfSalt, options }` with `allowCredentials: [{ id: credentialId }]` and `extensions.prf.eval.first = prfSalt`. 422 `prf_not_supported` if the passkey has no stored salt. |
| `POST` | `/api/identity/vault/prf-verify` | Session cookie | Verify the unlock assertion. Body: `{ challengeId, credential }`. Server verifies the WebAuthn assertion (signature + counter) and returns `{ ok: true }`. PRF output bytes are read client-side and never sent to Tower. |
| `POST` | `/api/identity/server-registration` | None | Media server registers itself with Tower at startup. Body: `{ serverPubKey, displayName? }`. Returns `{ serverId, bearer }`. Idempotent on `pubkeyHash`: re-issues bearer on every call (old bearer pointer is deleted in the same transaction), so a media-server restart is always safe. |
| `POST` | `/api/identity/pairing/register` | Bearer = media-server token | Media server registers a fresh server-link pairing request. Body: `{ serverName?, serverIcon?, callbackUrl?, scope? }`. Returns `{ requestId, code, expiresAt }`. |
| `GET` | `/api/identity/pairing/{requestId}` | Bearer = media-server token | Media server polls pairing status. Returns `{ state, requestId, expiresAt }` plus `{ signedAssertionBytes, assertionSignature }` when `state === 'completed'`. States: `pending`, `claimed_by_user`, `completed`, `expired`, `denied`. Capped at 300 polls (10 min @ 2s); beyond that → 429 `rate_limited` with `retryAfterSeconds`. |
| `GET` | `/api/identity/code/{code}/resolve` | Session cookie | **Unified** browser-side code resolver. Looks up the pointer row, transitions the request to `claimed_by_user`, returns `{ kind, requestId, expiresAt, ... }` with kind-specific context: `server-link` → `{ serverName, serverIcon, scope }`; `client-pair` → `{ appId, appName, appIcon, appVerified, appDescription }`. 410 `pairing_expired`, 409 `pairing_already_completed`, 429 `rate_limited`, 404 `pairing_not_found`. |
| `POST` | `/api/identity/code/{code}/complete` | Session cookie | **Unified** browser-side completion. Body: `{ approve: boolean }` plus, when `approve: true`, either `{ signedAssertionBytes, assertionSignature }` (server-link kind) or `{ signedCertBytes, certSignature, approvedServers }` (client-pair kind). Tower stores the signed bytes opaquely and deletes the code pointer. |
| `POST` | `/api/identity/clients/pair/begin` | None | Constrained device begins a client-pair flow. Body: `{ appId, clientPubKey, deviceName?, platform?, callbackUrl? }`. Validates `appId` exists in the registry. Returns `{ requestId, code, pairingUrl, browserUrl, pollUrl, expiresAt }`. 400 `unknown_app` if appId not registered. |
| `GET` | `/api/identity/clients/pair/{requestId}` | None (requestId is the secret) | Client polls. Returns `{ state, requestId, expiresAt }` plus `{ signedCertBytes, certSignature, servers }` when `state === 'completed'`. Same 300-poll cap as server-link. |
| `POST` | `/api/identity/clients/{clientId}/renew` | None (client signs request) | Cert renewal. Body: `{ currentCert, ts, sig }` signed by Cn. Returns fresh cert if a pre-issued one is available; 202 `pending` otherwise. |
| `POST` | `/api/identity/clients/preissue` | Session cookie | Browser uploads pre-issued renewal certs after vault open. |
| `POST` | `/api/identity/revocations` | Session cookie | Browser uploads M-signed revocation envelope. |
| `GET` | `/api/identity/revocations?since=<ts>` | None | Public CRL feed. Each entry signed by M. |
| `POST` | `/api/identity/apps` | Session cookie | Create a developer app. Per-owner cap: 50 apps. 429 `app_cap_reached`. |
| `GET` | `/api/identity/apps` | Session cookie | List apps the caller owns. |
| `GET` | `/api/identity/apps/{appId}` | None | Public read. Returns only `{ appId, name, iconUrl, verified, description, websiteUrl, platforms }`. |
| `PUT` | `/api/identity/apps/{appId}` | Session cookie (owner) | Update app metadata. `verified` is not editable here. |
| `DELETE` | `/api/identity/apps/{appId}` | Session cookie (owner) | Delete app. |

**Endpoint shape note.** Earlier drafts of this spec had per-kind code endpoints (`/api/identity/pairing/code/{code}` and `/api/identity/clients/pair/code/{code}` with separate `complete` handlers). This was consolidated into the unified `/api/identity/code/{code}/{resolve,complete}` shape during Tower implementation planning — the `/pair` page does not know the kind before hitting the resolver, and unifying eliminates a fallback round-trip. The per-kind URLs do **not** exist as aliases; clients MUST call the unified path.

**PRF and passkey ceremony endpoints** (`/api/auth/register/begin|complete`, `/api/auth/login/begin|complete`, `/api/account/passkeys/add/begin|complete`, etc.) already exist — extend the existing `auth.ts` and `account.ts` to thread the PRF extension through. `register/begin` and `passkeys/add/begin` generate a fresh `prfSalt`, store it on the challenge row, and return it to the browser. `register/complete` and `passkeys/add/complete` persist `prfSalt + prfEnabled + v2: true` on the resulting `PasskeyRow`. `login/begin` includes a `probeSalt` (random, per-challenge) so the authenticator surfaces its PRF UI gate once; `login/complete` returns the matched passkey's real `prfSalt` and `credentialId` so the browser can run the silent second ceremony at `/api/identity/vault/prf-challenge` + `/prf-verify` (see §4.5).

### 5.1.1 Error envelope

All endpoints return errors as a **flat** JSON object:

```json
{ "error": "code_string", "message": "informative human-readable string", "extra1": "...", "extra2": "..." }
```

`error` is a stable string code that clients SHOULD branch on. `message` is informative for developers and MAY change between releases. Additional fields are context-specific (e.g., `currentEtag` on `vault_conflict`, `retryAfterSeconds` on `rate_limited`, `cap` and `current` on `app_cap_reached`). This matches Tower's existing convention from the v1 auth surface. No nested `error: { code, message }` shape exists anywhere in Tower's API.

### 5.2 Media-server endpoints (Aviato side implements)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/identity-link/start` | Either: valid invite token in body, *or* authenticated session for local-user-linking case | Begin a server-link pairing flow. Returns `{requestId, pairingCode, towerPairingUrl}`. Server calls Tower's `/pairing/register` under the hood. |
| `GET` | `/api/auth/identity-link/{requestId}/poll` | None (request ID is the secret) | Browser polls for completion. Server polls Tower in turn. Returns `{status, sessionToken?, certForCurrentBrowser?}` once done. |
| `POST` | `/api/auth/identity-session/begin` | None | Client requests a challenge. Body: `{cert}`. Returns `{challenge}`. |
| `POST` | `/api/auth/identity-session/complete` | None | Client submits signed assertion. Returns `{sessionToken, expiresAt}`. |
| `POST` | `/api/auth/identity/revocation/push` | Cert-auth | User's other device pushes a revocation envelope here. Server caches it. |
| `GET` | `/api/auth/identity/me` | Cert-auth | Reflect user info derived from cert. |

All MUST be `@hono/zod-openapi` (project convention).

### 5.3 Existing endpoints reused

- Media server: existing invite creation (`POST /api/invites`), invite acceptance for password path (unchanged), `acl.ts:addPublicKey` (called by the identity-link complete handler), `challenge.ts` (similar pattern reused or shared for session-auth challenges).
- Tower: existing JWKS/license endpoints unchanged. Existing passkey register/login flows extended to include PRF eval (`prfSalt` per credential stored alongside `PasskeyRow`).

## 6. Data schema additions

### 6.1 Aviato media server (new tables / column additions)

```ts
// packages/server/src/database/schema/users.ts — additions
towerUserId: text('tower_user_id'),         // nullable; opaque uuid from Tower
towerLinkedAt: integer('tower_linked_at'),  // ms
// publicKey already exists; for Tower-Identity users this stores M.pub

// new table: identity_clients
{
  clientId: text PRIMARY KEY,         // uuid from cert
  userId: text REFERENCES users(id) ON DELETE CASCADE,
  clientPubKey: text NOT NULL,
  deviceName: text,
  platform: text,
  certExpiresAt: integer NOT NULL,
  lastSeenAt: integer NOT NULL,
  revoked: integer NOT NULL DEFAULT 0,
}

// new table: identity_pairing_requests (short-lived, TTL 10 min)
{
  requestId: text PRIMARY KEY,
  towerRequestId: text NOT NULL,            // mirror of Tower-side id
  pairingCode: text NOT NULL,
  inviteToken: text,                        // null for relink flow
  localUserId: text REFERENCES users(id),   // null for invite flow
  scope: text NOT NULL,                     // JSON
  status: text NOT NULL,                    // 'pending' | 'completed' | 'expired'
  createdAt: integer NOT NULL,
  expiresAt: integer NOT NULL,
}
```

Existing tables to leave alone: `invites`, `invite_redemptions`, `sessions`, `server_identity`.

### 6.2 Tower (new fields / tables)

```
// UserRow additions
ed25519Pubkey: string (already reserved; now populated with M.pub)

// VaultRow (new)
{
  pk: USER#<userId>, sk: VAULT,
  ciphertext, iv, wraps[], updatedAt, etag
}

// PairingRequestRow (new — TTL 10 min, discriminated by kind)
{
  pk: PAIRING#<requestId>, sk: META,
  kind: 'server-link' | 'client-pair',
  state: 'pending' | 'claimed_by_user' | 'completed' | 'expired' | 'denied',
  claimedByUserId: string | null,
  pollCount: number,                // monotonic, capped at 300
  expiresAt: ISO 8601,
  ttl: <unix sec, now+600>,
  // For 'server-link': serverId, serverPubKey, serverName, serverIcon, callbackUrl, scope
  // For 'client-pair': appId, clientPubKey, deviceName, platform
  // After completion: signedAssertionBytes/signedCertBytes + corresponding signature
}

// Pointer row for 8-digit code → requestId lookup (no GSI; single-table pattern)
PairingCodePointerRow {
  pk: PAIRING_CODE#<code>, sk: META,
  code, requestId, kind,
  attemptCount: number,             // incremented on every resolve attempt
  lockedUntil: number | null,       // unix sec; set when attemptCount reaches 5
  ttl: <unix sec, now+600>
}

// Per-IP rate-limit row for failed code lookups
IpRateLimitRow {
  pk: RATE#IP#<sha256(ip)[0:16]>, sk: PAIRING_CODE,
  attemptCount, lockedUntil, ttl
}

// PreissuedCertRow (new)
{
  pk: USER#<userId>, sk: PRECERT#<clientId>,
  cert (bytes), issuedAt
}

// RevocationRow (new)
{
  pk: USER#<userId>, sk: REVOKE#<clientId>,
  envelope (bytes), receivedAt
}

// ServerRegistrationRow (new — Tower learns server pubkeys but nothing else)
{
  pk: SERVER#<serverPubKeyHex>, sk: REG,
  bearerHash, lastSeenAt, firstSeenAt
}

// PasskeyRow additions
prfSalt: string (base64, per-passkey)
```

## 7. Web UI surfaces

### 7.1 Aviato server web (packages/web)

- Sign-in page (`src/pages/SignIn.tsx` or wherever): add a "Sign in with Aviato Identity" button. Hidden unless the user has an invite token in URL or has already linked (clicking begins identity-session flow). Or: always show, but explain "requires invite". TBD during UI design.
- Invite landing (`src/pages/InviteAccept.tsx` etc.): two-path UI — "Set up username & password" vs "Link Aviato Tower-Identity". Existing keypair-from-seed-phrase flow remains as a third option for power users.
- Settings > Profile pane (new): "Link Aviato Tower-Identity" CTA; once linked shows linked status, Tower-issued email, master pubkey fingerprint. "Unlink" CTA falls back to "Set new password" gate before allowing unlink (to avoid lockout).
- Settings > Devices pane (new): per-user list of `identity_clients` rows. Each shows deviceName, platform, lastSeenAt, certExpiresAt, "Revoke this device" (local-only revocation: removes from this server's `identity_clients`, future auths from that clientId fail).

### 7.2 Tower web (ato.software/packages/tower-web)

- `/pair` page: enters 8-digit code → fetches pairing context → opens vault → signs assertion → completes.
- `/clients/pair` page: client-pair variant.
- Dashboard > Devices: list `clients[]` from vault; revoke action.
- Dashboard > Servers: list `servers[]` from vault; "Forget this server" action (just removes from vault — does not revoke server-side, that requires user to ask admin).
- Existing dashboard, passkey-mgmt, recovery-codes pages: extend passkey-add and passkey-delete to also update vault `wraps`.

## 8. Cross-repo coordination order

The two implementations have one strict dependency: the media server's `/api/auth/identity-link/start` calls Tower's `/api/identity/pairing/register`. Build order:

1. **Tower first**: ship vault + pairing-register/poll + server-registration endpoints behind a feature flag.
2. **Aviato side**: build server endpoints that drive Tower's pairing flow + web UI for invite-fork and settings.
3. **Tower web**: ship `/pair` page concurrently with step 2.
4. **End-to-end**: test the full server-link flow in a dev environment.
5. **Client-pair flow** comes after the server-link flow is solid.
6. **Renewal + revocation** are last (they don't block the initial v2 launch — first round of certs will be valid 60 days without any renewal infra).

The exact division of labor and per-task ordering is in the two implementation plan files.

## 10. Third-party apps & consent

The client-pair flow (4.4 / 5.1 `/api/identity/clients/pair/*`) is used by both first-party Aviato apps and third-party apps. Both behave identically on the wire; the only difference is what Tower shows the user on the consent screen.

**App registration.** Every app declares an `appId` (slug, public, no secret) by registering at Tower's `/developer/apps` page. Registration captures: name, slug, icon, description, website, platforms, callback URLs (for the redirect-based variant of the flow). No client secret is issued — the protocol does not need one (the user's passkey + the user's master key + the client keypair together cover every signature).

**Verified vs unverified.** Apps in good standing can request verification (domain control proof + light review). Verified apps render with a verified badge on the consent screen; unverified apps render with a yellow "Unverified app" badge. Both can pair.

**Consent screen.** When the user enters a pairing code on `/pair`, Tower fetches the app metadata for `requestId.appId` and shows: app name + icon + verified badge, then the user's server list with a per-server checkbox so the user can untick servers they would rather the app not see. The completed assertion includes only the *checked* subset of servers in its `vault.servers`-equivalent response.

**Cert claims.** The cert payload (§3.4) gains an `appId` claim so servers and apps can audit which app a given client cert was paired through. Servers MAY filter sessions by app id if they want to (out of scope for v2 launch).

**Public developer guide:** `docs/public/developer/client-applications.mdx` is the canonical public protocol reference. Anything materially documented there is a stable contract; changes require a versioned wire-format bump and announcement.

**SDK plans:** `@aviato-media/tower-sdk` for TypeScript first, then Swift + Kotlin. Out of scope for v2 launch; the guide is the contract until SDKs ship.

**Tower additions** (extends the Tower plan §3 "files to touch"):

- New table `AppRow` keyed by `app_<slug>`: name, ownerUserId, iconUrl, description, websiteUrl, platforms[], callbackUrls[], verified (bool), createdAt.
- New table `AppOwnershipRow`: who can edit an app's metadata.
- `/api/identity/apps` CRUD endpoints under Tower's authenticated dashboard.
- `/api/identity/apps/{appId}` public read endpoint (returns name, icon, verified — no secret data).
- The pairing-code consent page on Tower-web reads app metadata from this public endpoint at render time.

## 11. Open questions deferred for implementation

- Exactly how the server-registration bearer token is bootstrapped on a fresh Aviato install (probably during `tower-client.ts` license activation — extend `activate()` to also register the server-pubkey).
- Whether to render the master-pubkey fingerprint as base32 short-form (~6 chars) or as a checksum-friendly word list. Recommend base32 short for visual compare.
- Whether to require email verification on Tower account creation before allowing pairing (Tower already has this from §3.1 of its existing auth flow — defer to that).
- v1 relay-network coexistence: v2 does not require relays, but the existing `server-record.ts` mechanism stays. Decide later whether to deprecate it.
- Specific WebAuthn PRF browser-support gating: if PRF unavailable on the user's authenticator, what is the fallback? Recommend: refuse v2 enrollment with that authenticator and surface a clear error pointing to seed-phrase recovery for fallback.
- Cert format: this spec uses JCS+JSON for transparency. If we want it more compact later (CBOR / COSE_Sign1), swap before public launch — internal format only.
