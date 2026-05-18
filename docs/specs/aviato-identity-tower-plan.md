# Aviato Identity v2 — Tower Implementation Plan

Implementation plan for the Tower side (this repo, ato.software). The full design spec lives in the Aviato repo at `~/projects/aviato/aviato/docs/specs/aviato-identity-v2.md` — read it first; it defines the cryptographic primitives, vault format, cert format, threat model, and full API surface (§5). This file enumerates the tasks, files, and order of work for THIS repo only. The media-server side is tracked in `~/projects/aviato/aviato/docs/specs/aviato-identity-server-plan.md`.

This plan was written by an Aviato-side session and handed off. The companion specs and the v1 whitepaper (`docs/aviato-identity-whitepaper.md` in the Aviato repo) provide context. The Tower implementation is independent of the Aviato side — you can build all of these endpoints + UI without the Aviato server being involved, using a mock media-server registration call.

## What Tower does in v2

Tower acts as a **broker** and **encrypted-blob escrow** for Aviato Identity. Specifically:

1. Holds an opaque ciphertext "vault" per user (Tower never decrypts).
2. Authenticates users with passkeys + WebAuthn PRF extension, where the PRF output is the client-side wrapping key for the vault key.
3. Brokers pairing flows: a media server posts a pairing request → user enters code on `tower.aviato.media/pair` → user's browser opens vault, signs an assertion with master key M (held only in the just-decrypted vault), Tower relays signed assertion to the requesting media server.
4. Brokers client-app pairing: a TV/phone app posts a sign-in request → user enters code on Tower → browser signs a per-client delegation cert with M → Tower returns cert + vault.servers to the app.
5. Stores per-user "pre-issued" renewal certs that browser sessions deposit, and serves them to clients when they request renewal.
6. Publishes a master-key-signed CRL of revoked client certs (`/api/identity/revocations`).

Tower **cannot**:

- Decrypt vault payloads.
- Forge a server-link assertion or cert (no master priv).
- Read which media servers a user has linked (server list lives encrypted in vault).
- Substitute a different master pubkey (vault AEAD tag fails).

Residual: Tower's web app could theoretically serve malicious JS during a vault-open browser session and exfiltrate M. Mitigate with SRI + strict CSP. Native apps avoid this entirely by performing crypto in trusted native code.

## Existing infrastructure to reuse

Tower already has substantial passkey + identity scaffolding:

- `packages/tower-api/src/routes/auth.ts` — `/api/auth/register/begin|complete`, `/login/begin|complete`, `/recovery/begin|complete`, `/logout`. Extend these to thread the PRF extension through.
- `packages/tower-api/src/routes/account.ts` — `/api/account/passkeys/add/begin|complete`, list/rename/delete. Extend `add` to capture `prfSalt`.
- `packages/tower-api/src/lib/webauthn.ts` — SimpleWebAuthn wrappers. PRF extension support requires `@simplewebauthn/server` ≥ 9.x; verify version, upgrade if needed.
- `packages/tower-api/src/lib/db.ts` — UserRow already has `ed25519Pubkey: string | null` with a TODO marker for delegation; PasskeyRow has TODOs for `encryptedKeyBundle` and `exportedToServers`. These TODOs are this work.
- `packages/tower-api/src/lib/jwt.ts` — EdDSA JWT signing; not needed for vault flow but kept for license JWTs.
- `packages/infra/infra/tower.ts` — DynamoDB single-table layout. New PKs follow the existing convention (`USER#<id>` etc.).
- `packages/tower-web/` — Next.js (or whatever framework — check) app with existing passkey UI at `/login`, `/register`, `/recovery`, `/dashboard/passkeys`. Extend.

## Acceptance criteria

1. Existing users can opt-in to upgrade their account to v2 by registering a new passkey with PRF — without losing their existing passkeys or recovery codes.
2. New users go through v2 registration as the default (passkey + PRF + initial vault).
3. A media server can register itself, request a server-link pairing, surface a code to its user, and receive a signed assertion when the user completes the flow on Tower.
4. A constrained client (no browser of its own) can request a client-pair, surface a code, and receive a delegation cert + the user's vault.servers list when the user completes the flow.
5. Clients can renew their certs without redoing the passkey flow, provided the user has signed in to Tower within the past 30 days.
6. Users can revoke a client from Tower's dashboard; the revocation appears in the public CRL feed signed by M.
7. Tower's API contracts match §5.1 of the spec exactly (the Aviato side is built to those names).

## Files to touch / create

### New (tower-api)

- `packages/tower-api/src/routes/identity-vault.ts` — `/api/identity/vault/init`, `GET /api/identity/vault`, `PUT /api/identity/vault`. Optimistic concurrency via etag/If-Match.
- `packages/tower-api/src/routes/identity-pairing.ts` — server-link pairing endpoints. See spec §5.1 rows for `/pairing/register`, `/pairing/{id}`, `/pairing/code/{code}`, `/pairing/code/{code}/complete`.
- `packages/tower-api/src/routes/identity-clients.ts` — client-pair endpoints + cert renewal + pre-issued cert upload. See spec §5.1.
- `packages/tower-api/src/routes/identity-revocations.ts` — `POST` (auth'd, accepts envelope) and `GET ?since=` (public CRL).
- `packages/tower-api/src/routes/identity-server-registration.ts` — `/api/identity/server-registration`.
- `packages/tower-api/src/lib/identity-vault-db.ts` — DynamoDB CRUD for VaultRow, PairingRequestRow, PreissuedCertRow, RevocationRow, ServerRegistrationRow.
- `packages/tower-api/src/lib/identity-cert.ts` — cert envelope verification helper (verify Ed25519 sig over JCS payload). Same logic mirrored in `@aviato/crypto` on the Aviato side — keep canonical impl + test vectors in a shared place if practical.
- `packages/tower-api/src/lib/identity-codes.ts` — generate 8-digit pairing codes with rate-limiting; secure RNG; index by code.

### Modified (tower-api)

- `packages/tower-api/src/lib/db.ts` — add `getVault`, `putVault`, `createPairingRequest`, `getPairingRequestByCode`, `getPairingRequest`, `completePairingRequest`, `putPreissuedCert`, `consumePreissuedCert`, `putRevocation`, `listRevocationsSince`, `putServerRegistration`, `getServerRegistration`. Populate `UserRow.ed25519Pubkey` on vault init.
- `packages/tower-api/src/lib/webauthn.ts` — pass through `prf` extension in registration and authentication options (`@simplewebauthn/server` supports this in recent versions). Capture `prfSalt` from caller; verifier reflects PRF success.
- `packages/tower-api/src/routes/auth.ts` — extend register/login complete to optionally accept a `vault` blob (for first-passkey registration), persist via vault-db, return `prfSalt` on subsequent logins.
- `packages/tower-api/src/routes/account.ts` — extend passkey-add to capture and persist `prfSalt` and updated vault wraps.
- `packages/infra/infra/tower.ts` — no new tables needed (single-table reuse), but verify TTL field is enabled on the items that need it (pairing requests).

### New (tower-web)

- `packages/tower-web/src/app/pair/page.tsx` (or framework equivalent) — enter 8-digit code, fetch pairing context, open vault, sign + complete.
- `packages/tower-web/src/app/clients/pair/page.tsx` — equivalent for client-pair flow.
- `packages/tower-web/src/app/dashboard/devices/page.tsx` — list `vault.clients[]`, revoke.
- `packages/tower-web/src/app/dashboard/servers/page.tsx` — list `vault.servers[]`, "forget".
- `packages/tower-web/src/lib/vault.ts` — vault crypto helpers (WebCrypto). `createVault`, `openVault`, `addPasskeyToVault`, `removePasskeyFromVault`, `signServerLinkAssertion`, `signClientCert`, `signRevocation`.
- `packages/tower-web/src/lib/prf.ts` — PRF helpers wrapping `@simplewebauthn/browser`. Build options with `prf.eval.first = prfSalt`; extract PRF output from `authentication.clientExtensionResults`.

### Modified (tower-web)

- `packages/tower-web/src/lib/webauthn.ts` — wrap existing calls to pass PRF inputs.
- `packages/tower-web/src/app/register/page.tsx` — after `register/complete`, build vault and POST to `/api/identity/vault/init`.
- `packages/tower-web/src/app/login/page.tsx` — after `login/complete`, open vault (decrypt with PRF), keep VK in memory for the session, fire any pending pre-issuance.
- `packages/tower-web/src/app/dashboard/passkeys/page.tsx` — add: when adding a passkey, also add to vault wraps; when deleting, rotate VK + remove from wraps.

## Phased build order

### Phase 1: Vault foundation

- DynamoDB helpers for VaultRow (`putVault`, `getVault`).
- `/api/identity/vault/init`, `/api/identity/vault` (GET/PUT) routes.
- Vault-crypto helpers in `tower-web/src/lib/vault.ts`.
- Modify register flow to init vault. New v2 users created end-to-end.
- Migration consideration for existing users: leave them unvaulted; on next login, prompt to register a v2 passkey to upgrade. Out of scope to auto-migrate.

### Phase 2: Server registration + pairing

- `/api/identity/server-registration` (idempotent; returns bearer keyed to serverPubKey).
- `/api/identity/pairing/register` (server-auth) + `/api/identity/pairing/{requestId}` (poll).
- `/api/identity/pairing/code/{code}` (user-auth) + `/api/identity/pairing/code/{code}/complete`.
- `tower-web/src/app/pair/page.tsx` — code entry + vault open + sign + submit.

### Phase 3: Client pairing + app registry

This phase covers both first-party and third-party clients. The flow is the same; only the consent screen differs based on app metadata.

- `/api/identity/clients/pair/begin` and `/{requestId}` poll (no auth — the requestId/pubKey IS the secret). Body MUST include `appId`. Validate that `appId` exists in the app registry; reject with `unknown_app` if not.
- `/api/identity/clients/pair/code/{code}` and `/complete` (user-auth). Complete request includes the user-edited list of approved servers (per-server checkboxes from the consent UI). Only those servers appear in the response delivered to the client app.
- New app registry tables and endpoints (see spec §10):
  - `AppRow` (pk `APP#<slug>`, sk `META`): name, ownerUserId, iconUrl, description, websiteUrl, platforms, callbackUrls, verified flag.
  - `/api/identity/apps` (auth) — CRUD by app owner.
  - `/api/identity/apps/{appId}` (no auth) — public read; returns name + icon + verified + description + website + platforms only. Used by the consent screen and by future SDK app-info lookups. Does NOT return ownerUserId or callbackUrls.
- `tower-web/src/app/pair/page.tsx` — the existing pairing entry page; for client-pair codes it renders the app consent UI: name + icon + verified badge + a per-server checkbox list pulled from the user's vault.servers.
- `tower-web/src/app/developer/apps/page.tsx` — developer dashboard: list, create, edit apps. Self-serve. No payment, no rate limit besides a sensible per-owner cap (50?).
- `tower-web/src/app/developer/apps/[appId]/page.tsx` — edit a single app's metadata + see callback URLs + request verification.
- Tower-side cert issuance MUST include the `appId` claim (spec §3.4). The browser is responsible for setting it from the consent flow.

The third-party developer-facing docs for this flow live in the Aviato repo at `docs/public/developer/client-applications.mdx`. That document is the canonical public contract for the wire format; do not diverge from it without updating both sides.

### Phase 4: Renewal & pre-issuance

- `/api/identity/clients/preissue` (user-auth, browser uploads pre-signed certs).
- `/api/identity/clients/{clientId}/renew` (no auth, client signs request).
- Browser background task in `tower-web` after login: iterate `vault.clients`, issue fresh certs for any with `currentCertExp - now < 30d`, upload via `preissue`.

### Phase 5: Revocation & CRL

- `/api/identity/revocations` POST (user-auth) and GET (public, signed-only).
- `dashboard/devices/page.tsx` revoke action: sign envelope, upload, then re-rotate VK + remove the device row from `vault.clients`.

### Phase 6: Polish

- SRI hashes on all `tower-web` script tags. Strict CSP. (Critical for the residual threat — mitigates Tower-web JS supply-chain compromise.)
- Multi-passkey UX in dashboard.
- v1-account upgrade path.
- Docs (in this repo's docs, wherever Tower's user docs live).

## Cross-repo touchpoints

What Tower exposes for the Aviato side (must ship in this order):

1. **Phase 1** unblocks nothing on the Aviato side directly, but is a prerequisite for everything else.
2. **Phase 2** unblocks the Aviato side's Phase 3 (server-link via invite). The Aviato side's `tower-client-identity.ts` will call these endpoints.
3. **Phase 3** unblocks the Aviato Apple/native apps (and any future TV apps). The web's "Sign in with Aviato Identity" inside the media server uses Phase 2, not Phase 3.
4. **Phase 4** is consumed by all client apps once they exist.
5. **Phase 5** is consumed by all servers (Aviato side's Phase 7).

## API contract notes (Aviato side is built to these)

- All endpoint names match spec §5.1 exactly. Diverging will break the Aviato side.
- Field names use camelCase consistently.
- Errors use `{ error: { code: "...", message: "..." } }` shape, matching existing Tower-API style.
- Pairing codes are 8 decimal digits formatted as `XXXX-XXXX` in display, plain digits on the wire.
- Vault `etag` is a server-generated opaque string; the Aviato side does not care about its format. Used for optimistic concurrency on `PUT /vault`.
- Server-link assertion bytes are the canonicalized JSON per RFC 8785 JCS. Verification is over the *exact* canonical bytes Tower received from the browser — do NOT re-canonicalize on the server side, just pass through to the media server.

## Test plan

| Scope | Tool |
|---|---|
| Vault crypto in `tower-web/src/lib/vault.ts` | Vitest or equivalent; deterministic vectors |
| Cert + envelope verification | Server-side test against fixtures |
| DynamoDB helpers | Local DDB or mock |
| End-to-end pairing | Manual using a stub media-server in this repo for testing |
| WebAuthn PRF | Real browser test using a virtual authenticator (Chromium DevTools or `@simplewebauthn/browser` test harness) |

## What NOT to do

- Do NOT modify Aviato media-server code. That's the parallel session's territory.
- Do NOT store vault payloads in any decryptable form on Tower. The blob is opaque.
- Do NOT log vault contents, even at debug level.
- Do NOT extend the marketplace schema or any plugin-related code; this feature is unrelated to plugins. (Per the Aviato CLAUDE.md, manifest changes require cross-repo sync — but this is NOT a manifest change.)
- Do NOT silently transform the assertion JSON before forwarding to the media server. Re-canonicalization will break the signature.
- Do NOT issue any kind of identity assertion server-side — every assertion is signed by either M (in user's browser) or Cn (in user's client app).
