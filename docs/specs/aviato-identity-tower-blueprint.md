# Aviato Identity v2 — Tower Implementation Blueprint

Synthesized from the original plan (`aviato-identity-tower-plan.md`) plus codebase exploration. This document is the concrete buildable spec; the plan is the high-level intent. Where they disagree, this blueprint wins (and the disagreement is called out below).

## Key decisions made during planning

### Cryptography

1. **AEAD**: AES-GCM-256 via WebCrypto. 96-bit nonce per encrypt. Ciphertext stored as raw GCM output (plaintext + 16-byte tag).
2. **PRF wrapping key derivation**: PRF bytes (32) → HKDF-SHA-256 → 256-bit AES-GCM key. No AES-KW.
   - HKDF info: `'aviato-vault-wrapping-key-v1'`
   - HKDF salt: all-zero 32 bytes (domain separation via info string)
3. **Etag**: random 16-byte base64url, regenerated on every successful write. Not a hash of ciphertext.
4. **Vault canonicalization** (internal to Tower-web): hand-rolled deterministic JSON (sort keys, no whitespace). Migrate to RFC 8785 JCS in Phase 6.
5. **Assertion + cert canonicalization** (cross-system contract): real RFC 8785 JCS. The browser canonicalizes; Tower stores the bytes verbatim and forwards them unchanged. Pulling in a vetted JCS implementation (e.g., `canonicalize`) is required for Phases 2–3.
6. **Vault stored shape**: wraps live at the **top level** of the VaultRow, alongside (not inside) the encrypted body. Tower returns them in the GET response so the browser can pick the right wrap based on the credentialId it just authenticated with. Putting wraps inside the AEAD body would be circular (you'd need VK to read the wrap that produces VK). Matches spec §3.3.
7. **Cert payload**: full claims per spec §3.4 (`v, userId, userPubKey, clientId, clientPubKey, appId, deviceName, scope, iat, exp`). The user-approved server list is **not** in the cert — it's delivered alongside the cert in the pairing-complete response. Tower briefly sees the approved server list during the 10-minute pairing window; the row TTLs out automatically and is not retained.

### PRF login flow (the unusual part)

`login/begin` can't pass a per-user PRF salt because the user isn't known yet (usernameless / discoverable credential). The clean resolution is a **two-ceremony login**:

1. `login/begin`: server includes `extensions.prf.eval.first = <probe-salt>` (random per-challenge). User's authenticator runs PRF against the wrong salt; output is discarded.
2. `login/complete`: server returns `{ userId, email, credentialId, prfSalt }` (the matched passkey's real salt).
3. Browser POSTs `/api/identity/vault/prf-challenge` with the credentialId; server issues a new WebAuthn challenge with `extensions.prf.eval.first = realSalt` and `allowCredentials: [{ id: credentialId }]`.
4. Browser calls `startAuthentication` again — silent on platform authenticators because the credential is pre-selected.
5. Browser POSTs `/api/identity/vault/prf-verify`; server verifies the assertion (bumps counter), returns nothing. PRF output stays browser-side.
6. Browser extracts PRF output → HKDF → wrapping key → decrypts vault.

This adds one extra silent assertion on login but is the standard pattern (Apple iCloud Keychain uses it). Single-ceremony login is not feasible without revealing the userId before authentication.

### Vault key (VK) in memory

- Strictly in-memory in a `useRef` inside `VaultProvider` mounted at `dashboard/layout.tsx`.
- No `sessionStorage`. Tab close = vault locked. Refresh = unlock again (silent PRF ceremony).
- Second tab = locked state, requires re-authentication. Out of scope to share VK across tabs.

### Endpoint naming — DEVIATION FROM PLAN §5.1

The plan says endpoint names must match spec §5.1 exactly. The blueprint proposes **two consolidations** that diverge:

1. **Unified `GET /api/identity/code/:code/resolve`** (replaces `/pairing/code/:code` and `/clients/pair/code/:code`). Returns `{ kind, request }` with kind-specific context.
2. **Unified `POST /api/identity/code/:code/complete`** (replaces `/pairing/code/:code/complete` and `/clients/pair/code/:code/complete`). Branches on the code's stored kind.

**Why**: the `/pair` page doesn't know in advance which kind a code is. With separate endpoints it has to try one and fall back to the other, doubling round-trips. Unified is one round-trip + one handler.

**Risk**: the Aviato side may already be built against the per-kind names. If so, two options:
- Keep the per-kind URLs as aliases that forward to the unified handler internally (cheap, both work).
- Update the Aviato-side spec to match unified names (cleaner long-term).

This decision needs cross-repo sync before Phase 2 lands.

### Data model

**New row types** (all in single-table, no GSI, sentinel/pointer pattern):

```
VaultRow                  PK=USER#<id>            SK=VAULT
  fields: ciphertext, iv, wraps[], etag, version, createdAt, updatedAt
  wraps[] entries: { credentialId, prfSalt, wrappedKey, wrapIv }
  wraps are TOP-LEVEL (not inside the AEAD body)
PasskeyRow (extended)     +prfSalt, +prfEnabled, +v2
ChallengeRow (extended)   +prfSalt (optional)
                          +type union extended with 'vault-prf'

ServerRegistrationRow     PK=SERVER_REG#<hash>    SK=META
ServerBearerPointerRow    PK=SERVER_BEARER#<hash> SK=META

ServerLinkPairingRow      PK=PAIRING#<id>         SK=META   (kind='server-link')
ClientPairPairingRow      PK=PAIRING#<id>         SK=META   (kind='client-pair')
PairingCodePointerRow     PK=PAIRING_CODE#<code>  SK=META   (carries kind+attemptCount+lockedUntil)
IpRateLimitRow            PK=RATE#IP#<hash16>     SK=PAIRING_CODE

AppRow                    PK=APP#<slug>           SK=META
UserAppPointerRow         PK=USER#<id>            SK=APP#<slug>

PreissuedCertRow          PK=USER#<id>            SK=PREISSUED#<clientId>   (Phase 4)
RevocationRow             PK=REVOCATIONS          SK=<iso>#<userId>#<certId> (Phase 5, single-partition for CRL range query)
```

All TTL via the existing `ttl` attribute. No infra change required — strictly additive.

### Rate limiting (Phases 2+)

- **Per-code**: `attemptCount` field on the pointer row itself, incremented via `UpdateItem ADD`. At 5 attempts, set `lockedUntil = now + 600`.
- **Per-IP**: `RATE#IP#<sha256(ip)[0:16]>` row, same pattern. Only incremented on **failed** lookups (legitimate user entering their own code is free).
- **Poll counter**: `pollCount < 300` condition on `GET /pairing/:requestId` (10 min at 2s polls — matches the 10-minute pairing TTL documented in the public developer guide). Beyond that → `429 rate_limited` with `retryAfterSeconds: 600`.
- **Pairing TTL**: 10 minutes on both `PairingRequestRow` and `PairingCodePointerRow`. Matches the published contract in `docs/public/developer/client-applications.mdx`.

### Server registration

- `POST /api/identity/server-registration` is **idempotent on pubkeyHash** AND **re-issues bearer on every call**. Old bearer pointer is deleted in the same TransactWrite. Makes media-server restarts safe — no out-of-band ceremony needed.
- Bearer is opaque random 32 bytes (base64url). Stored as `bearerHash = sha256hex(raw bytes)`. Raw bearer returned only once at registration.
- `requireServerBearer` middleware modeled on `requireActivationToken`. Two GetItems (bearer pointer → registration row); both single-row reads at known keys.

### CORS

Three groups for `/api/identity/*`:

- **Browser-facing** (cookie auth): `corsConfig` on `/vault*`, `/code/*`, `/clients/pair/code/*`, `/apps`, `/apps/*`.
- **Server-to-Tower** (bearer auth from media server backends, not browsers): NO CORS on `/server-registration`, `/pairing/register`, `/pairing/:id`.
- **Native client apps** (no browser): NO CORS on `/clients/pair/begin`, `/clients/pair/:id`.

### Error envelope

Tower's existing flat shape: `{ error: "code_string", message?: "informative", ...extras }`. The plan's nested shape is wrong — keep the flat shape and update the cross-repo contract. **Every new error code carries an informative `message` for client app developers.**

New errors (Phase 1):
- `vault_not_found` (404), `vault_conflict` (409, `currentEtag`), `vault_already_initialized` (409)
- `prf_not_supported` (422), `invalid_vault_format` (400), `if_match_required` (428)

New errors (Phases 2–3):
- `pairing_not_found` (404), `pairing_expired` (410), `pairing_already_completed` (409), `pairing_denied` (409)
- `invalid_code` (400), `rate_limited` (429, `retryAfterSeconds`)
- `unknown_app` (400, `appId`), `app_slug_taken` (409, `slug`), `app_cap_reached` (429, `cap`, `current`)
- `server_registration_required` (401), `invalid_signature` (400), `invalid_pubkey` (400)

Add helpers to `errors.ts`: `preconditionRequired(428)`, `unprocessable(422)`. Fix `app.ts` status union cast to include 422 and 428.

### Staging stack

- Stage names: `production` and `staging`. Developer ephemeral stages (anything else) get no Tower deployment.
- Change in `sst.config.ts`: gate Tower import on `$app.stage === 'production' || $app.stage === 'staging'`.
- Domain: `staging-tower.aviato.media` (auto-derived from `$app.stage`).
- DDNS infra stays production-only.
- DynamoDB table, ACM cert, R53 record — SST auto-namespaces per stage.
- Secrets are per-stage; provision staging secrets manually one-time.
- WebAuthn RP_ID resolves to the staging domain; staging credentials cannot be replayed against prod (different RP_ID).

### Tower-web new infrastructure

- **`src/lib/prf.ts`**: `buildPrfInputs`, `extractPrfOutput`, `derivePrfWrappingKey`.
- **`src/lib/vault.ts`**: `encryptVault`, `decryptVault`, `createVault`, `openVault`, `addPasskeyToVault`, `removePasskeyFromVault`. `VaultPayload` type. Per-passkey VK wraps in `payload.keys`; vault body encrypted under VK once.
- **`src/lib/vault-context.tsx`**: `VaultProvider`, `useVault`. VK in `useRef`, payload+etag in `useState`. Mounted in dashboard layout.
- **`src/lib/toast.tsx`**: minimal `ToastProvider` + `useToast`. Bottom-right overlay, no external library.
- **`src/lib/api.ts`** modified: `ApiCallOptions` with `headers` threaded through every method (for `If-Match`).
- **`src/lib/webauthn.ts`** modified: return raw credential alongside server result so PRF output can be extracted.

## File-by-file change map

### New files (tower-api)

- `src/routes/identity-vault.ts` — vault init/get/put, prf-challenge, prf-verify
- `src/routes/identity-pairing.ts` — server-link routes + unified code resolve/complete
- `src/routes/identity-clients.ts` — client-pair begin/poll (Phase 3); Phase 4 renewal/preissue lands here later
- `src/routes/identity-apps.ts` — app registry CRUD
- `src/routes/identity-server-registration.ts` — POST /server-registration
- `src/routes/identity-revocations.ts` — Phase 5
- `src/lib/identity-vault-db.ts` — all DDB CRUD for identity rows
- `src/lib/identity-codes.ts` — 8-digit code generator + rate limiting
- `src/lib/identity-cert.ts` — base64url validation, signature format checks

### Modified files (tower-api)

- `src/lib/db.ts` — new key constructors; extend `PasskeyRow` and `ChallengeRow`; `VaultRow` interface
- `src/lib/webauthn.ts` — PRF extension threading on options + verification results
- `src/lib/passkey-builder.ts` — accept prfSalt/prfEnabled/v2
- `src/lib/middleware.ts` — `requireServerBearer`
- `src/lib/errors.ts` — `preconditionRequired`, `unprocessable`
- `src/routes/auth.ts` — PRF threading through register/login
- `src/routes/account.ts` — PRF threading through passkeys/add
- `src/app.ts` — mount new routes; CORS groups; fix status cast

### New files (tower-web)

- `src/lib/prf.ts`, `src/lib/vault.ts`, `src/lib/vault-context.tsx`, `src/lib/toast.tsx`
- `src/app/pair/page.tsx` — unified pair page (server-link + client-pair branches)
- `src/app/dashboard/devices/page.tsx` — Phase 5
- `src/app/dashboard/servers/page.tsx` — Phase 5
- `src/app/developer/layout.tsx`
- `src/app/developer/apps/page.tsx`
- `src/app/developer/apps/[appId]/page.tsx`

### Modified files (tower-web)

- `src/lib/api.ts` — per-call headers
- `src/lib/webauthn.ts` — surface raw credential
- `src/lib/types.ts` — `PairingResolveResponse`, `AppDto`, `AppPublicDto`
- `src/app/dashboard/layout.tsx` — wrap providers; new nav entries
- `src/app/register/page.tsx` — createVault + vault/init
- `src/app/login/page.tsx` — two-ceremony PRF unlock
- `src/app/dashboard/passkeys/page.tsx` — vault re-wrap on add/delete

### Modified files (infra)

- `sst.config.ts` — gate Tower import on production||staging
- `infra/tower.ts` — parameterize TOWER_DOMAIN; staging env vars; `isProduction` constant; lift hard-coded prices to per-stage

## Phased build sequence (each step keeps main green)

### Phase 0 (cross-cutting prerequisites)
1. Lift `isProd` gate; add staging stage; deploy empty staging stack and verify DNS/cert.
2. Add `preconditionRequired` + `unprocessable` to `errors.ts`; widen `app.ts` status cast.
3. Add `ApiCallOptions` to `src/lib/api.ts` (no consumers yet).
4. Add toast primitive (`src/lib/toast.tsx`) and mount in dashboard layout (no consumers).

### Phase 1 (vault foundation)
1. Type-foundation pass in `db.ts` (no behavior change): `VaultRow`, extended `PasskeyRow`, extended `ChallengeRow`.
2. Extend `webauthn.ts` wrappers to thread PRF extension; augment verify return types.
3. Update `passkey-builder.ts` to accept new fields.
4. Create `identity-vault-db.ts` with vault CRUD.
5. Create `identity-vault.ts` route with all five endpoints. Mount in `app.ts` with CORS.
6. Thread PRF through `auth.ts` (register/login begin/complete).
7. Thread PRF through `account.ts` (passkeys/add).
8. Implement `prf.ts` + `vault.ts` in tower-web.
9. Implement `VaultProvider`; wrap dashboard layout.
10. Wire `register/page.tsx` to createVault + vault/init.
11. Wire `login/page.tsx` to two-ceremony PRF unlock.

**Phase 1 gate**: manual test on Chrome + iOS Safari. Confirm two-ceremony login is silent on iOS, register→login→vault unlock works end-to-end.

### Phase 2 (server-link pairing)
1. Code generator + rate limiting (`identity-codes.ts`) with unit tests.
2. `ServerRegistrationRow` + bearer pointer row CRUD in `identity-vault-db.ts`.
3. `POST /server-registration` route + `requireServerBearer` middleware.
4. Server-link pairing CRUD + routes (`identity-pairing.ts`).
5. **Cross-repo sync**: confirm endpoint-name deviation with Aviato side before merging.
6. `/pair` page with code entry + server-link consent.
7. Stub `/dashboard/servers/` and `/dashboard/devices/` with "Coming soon" so nav links resolve.

### Phase 3 (client-pair + app registry)
1. App registry rows + routes (`identity-apps.ts`).
2. `ClientPairPairingRow` + client-pair routes (`identity-clients.ts`).
3. Extend resolve endpoint to fetch app metadata for client-pair codes.
4. Extend `/pair` page with client-pair consent (app card + per-server checkboxes from `vault.servers`).
5. Developer dashboard pages (list, create, edit).
6. Add "Developer / My Apps" to dashboard nav.

### Phase 4 (renewal + pre-issuance)
1. `PreissuedCertRow` CRUD.
2. `POST /clients/preissue` (user-auth, uploads pre-signed certs).
3. `POST /clients/:clientId/renew` (no auth, client signs renew request).
4. Browser background task on login: iterate `vault.clients`, pre-issue certs for any nearing expiry.

### Phase 5 (revocation + CRL)
1. `RevocationRow` (single-partition `REVOCATIONS` for cheap range queries).
2. `POST /revocations` (user-auth, signed envelope).
3. `GET /revocations?since=` (public, returns master-key-signed envelope).
4. `dashboard/devices/page.tsx` revoke action: sign envelope → upload → re-rotate VK → remove vault.clients entry.
5. `dashboard/servers/page.tsx` forget action.

### Phase 6 (polish)
1. CSP headers via CloudFront response-headers policy (Next.js static export precludes `headers()` in `next.config.ts`).
2. Post-export SRI injection step in the build (script tag hashes).
3. Multi-passkey UX in dashboard.
4. v1 → v2 account upgrade prompt on next login.
5. Migrate vault canonicalization from hand-rolled to proper JCS.
6. User-facing docs.

## Risks to manually verify

- **PRF availability on iOS Safari** (Phase 1 gate): two-ceremony silent re-assertion. If iOS prompts twice, UX needs to gracefully merge into a single visible auth.
- **`ConditionalCheckFailedException` handling on `PUT /vault`**: must return 409 with `currentEtag`, not a raw 500. Test with two concurrent PUTs.
- **CORS preflight failures**: easy to forget; test browser fetch to `/api/identity/vault` from `tower.aviato.media` in actual browser.
- **`evalByCredential` vs `eval.first`**: ensure the right salt is used on the second ceremony.
- **vault.servers blind disclosure**: confirm Tower never receives the server list — only the signed cert blob containing approved IDs.
- **Race condition in `claimed_by_user` transition**: two-tab simultaneous code entry must produce a clean conflict for the loser, not break the winner.
- **DNS for staging-tower**: ACM cert validation hangs if `aviato.media` zone is in a different account.

## Resolved decisions

1. **Endpoints**: ship unified `/api/identity/code/:code/resolve` and `/api/identity/code/:code/complete` only. The Aviato-side spec (`~/projects/aviato/aviato/docs/specs/aviato-identity-v2.md` §5.1 and `docs/public/developer/client-applications.mdx`) must be updated to match before Phase 2 ships. No per-kind aliases.
2. **CSP/SRI**: deferred to Phase 6. Document the residual JS-compromise threat in user-facing docs alongside the Phase 1 release.
