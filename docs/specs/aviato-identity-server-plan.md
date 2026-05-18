# Aviato Identity v2 — Server + Web Implementation Plan

Implementation plan for the Aviato media server side. Source of truth for design: `aviato-identity-v2.md` (read first). This file enumerates the concrete tasks, files, and order of work for THIS repo only. Tower's side is tracked separately in `~/projects/ato/ato.software/aviato-identity-tower-plan.md`.

## Acceptance criteria

1. A user with a valid invite token can choose "Link Aviato Tower-Identity" on the invite landing page, complete the Tower pairing flow on their phone (8-digit code path) or in the same browser (deep-link path), and end up signed in to the media server as a new local user with `publicKey = M.pub`.
2. A user who pairs a client app (TV / mobile / desktop) at Tower receives a delegation cert + their server list, can talk to *each* server in their vault directly via `/api/auth/identity-session/*`, and gets a session token from each — without Tower being online at session-auth time.
3. An existing local username/password user can go to Settings > Profile and link their account to a Tower-Identity; afterwards their password is cleared, and login uses the cert flow.
4. The same user can have multiple clients (multiple `identity_clients` rows). Each is independently authenticatable. Revoking one in Settings > Devices invalidates only that one. Server keeps working when Tower is offline (for already-authed clients).
5. All new routes use `@hono/zod-openapi`. All schemas live in `packages/common` if used by both server and web, or in the relevant client module if web-only. Wire-level schemas defined once and reused (`feedback_zod_openapi_share_wire_schemas`).
6. Tests cover: invite + Tower-Identity happy path, link-to-existing-user, cert validity/expiry, replay protection on session challenges, cross-server session auth using same cert, revocation, Tower-offline tolerance for already-authed sessions.

## Files to touch / create

### New (server)

- `packages/server/src/identity/tower-identity/` (new directory)
  - `pairing.ts` — server-side pairing-request lifecycle: create, poll Tower, complete, persist `identity_pairing_requests` rows.
  - `assertions.ts` — verify server-link assertion (§3.6) and session-auth assertion (§3.5) from spec. Re-uses `@aviato/crypto` for Ed25519 verify.
  - `cert.ts` — verify cert envelope, parse claims, check expiry, expose `verifyCertChain(certEnvelope, expectedUserPubKey?)`.
  - `clients.ts` — CRUD on `identity_clients` table; lastSeenAt updates; local revocation.
  - `tower-client-identity.ts` — HTTP client for Tower's identity endpoints. Extends `packages/server/src/license/tower-client.ts` with identity-specific calls (`/api/identity/pairing/register`, `/api/identity/pairing/{id}`, `/api/identity/server-registration`).
- `packages/server/src/api/identity-link.ts` — Hono route module for `/api/auth/identity-link/*`. Mirrors structure of existing `invites.ts`.
- `packages/server/src/api/identity-session.ts` — Hono route module for `/api/auth/identity-session/*` and `/api/auth/identity/me`.
- `packages/server/drizzle/sqlite/000X_identity_v2.sql` — generated migration adding `tower_user_id`, `tower_linked_at` columns and `identity_clients`, `identity_pairing_requests` tables.
- `packages/server/src/database/schema/identity-clients.ts` — Drizzle schema.
- `packages/server/src/database/schema/identity-pairing-requests.ts` — Drizzle schema.
- `packages/common/src/identity/v2/index.ts` — shared Zod schemas: `ClientDelegationCertSchema`, `IdentityAssertionSchema`, `ServerLinkAssertionSchema`, `RevocationEnvelopeSchema`. Used by both server and web.

### Modified (server)

- `packages/server/src/database/schema/users.ts` — add `towerUserId`, `towerLinkedAt`.
- `packages/server/src/index.ts` — mount new route modules.
- `packages/server/src/license/tower-client.ts` — extend `activate()` to also call Tower's `/api/identity/server-registration` and stash bearer; export helper to fetch it.
- `packages/server/src/license/tower-config.ts` — add `TOWER_IDENTITY_REGISTRATION_BEARER_FILE` path under data dir.
- `packages/server/src/auth/users.ts` — add `linkTowerIdentity(localUserId, masterPubKey, towerUserId)` helper that nulls passwordHash + sets publicKey/towerUserId. Add `unlinkTowerIdentity()` symmetric helper that requires a new password.
- `packages/server/src/identity/acl.ts` — small extension: `addPublicKeyWithTowerLink({publicKey, towerUserId, inviteToken, displayName, ...})` consolidating the new code path so callers in `identity-link.ts` don't have to know about both ACL and users tables.
- `packages/server/src/identity/challenge.ts` — generalize for session-auth nonces (currently invite-only). Either reuse with a discriminator or add a parallel `session-challenge.ts`. Prefer reuse if no schema collision.

### New (web)

- `packages/web/src/components/settings/panes/AviatoIdentityPane.tsx` (or extend existing Profile pane) — link/unlink UI, fingerprint display.
- `packages/web/src/components/settings/panes/DevicesPane.tsx` — list `identity_clients`, revoke.
- `packages/web/src/lib/identity/tower-link.ts` — client helpers: start pairing, poll status, open Tower URL.
- `packages/web/src/pages/InviteAccept.tsx` — modify to add Tower-Identity option (existing path stays as Option A).

### Modified (web)

- `packages/web/src/components/settings/panes/index.ts` (or wherever settings panes are registered) — register the new panes.
- `packages/web/messages/en.json` and `messages/ja.json` — copy for the new UI surfaces. (Project convention requires both — see `M packages/web/messages/ja.json` already in the git status, so Japanese is actively maintained.)

## Phased build order

Phase numbers map directly to work units. Each phase should land in its own PR (or worktree branch — never merge into dev without explicit approval, per CLAUDE.md and memory).

### Phase 1: Foundations (no Tower contact yet)

Deliverable: schemas + crypto helpers + db migrations exist and have unit tests. No HTTP yet.

- Create `packages/common/src/identity/v2/` Zod schemas.
- Generate Drizzle migration adding the two new tables + two columns. Use `bun run db:generate:sqlite` from `packages/server/`. Verify journal timestamp ordering (see CLAUDE.md "Database Migrations").
- Implement `cert.ts`, `assertions.ts` (pure functions over the schemas). Bun-test coverage: valid cert, expired cert, wrong-key sig, malformed payload, replay nonce, ts skew.
- Implement `clients.ts` CRUD + tests.

### Phase 2: Tower server-registration

Deliverable: server can register itself with Tower at startup and obtain a bearer for pairing calls. Requires Tower's `/api/identity/server-registration` to exist (cross-repo dep).

- Extend `tower-client.ts` with `registerIdentityServer(serverKeypair)`. Persist bearer under data dir.
- Wire into existing license `activate()` flow (or run as a separate boot step — TBD; activate is cleaner since it already runs on first start).
- Test against Tower's dev stub (Tower-side plan ships a mock).

### Phase 3: Server-link (invite path)

Deliverable: a user with an invite can sign in via Tower-Identity. End-to-end with Tower dev environment.

- Implement `tower-client-identity.ts` calls for `/pairing/register` and `/pairing/{id}` polling.
- Implement `identity/tower-identity/pairing.ts`.
- Implement `/api/auth/identity-link/start`, `/api/auth/identity-link/{requestId}/poll`.
- On completion: verify server-link assertion → call `acl.ts` to create user → store cert in `identity_clients` for the current browser-driving client (a "web/v2" pseudo-client) → create session token → return to browser.
- Web: modify `InviteAccept.tsx` to expose "Link Aviato Tower-Identity" option. On click: hit `/start`, display pairing code + QR, poll, on success store session and redirect to home.
- Integration tests using a fakeTower (in-process mock implementing the relevant endpoints — see Tower plan for the shape).

### Phase 4: Cert-auth session flow

Deliverable: a client app (web or simulated) can present a cert + signed challenge and get a session.

- Implement `/api/auth/identity-session/begin` and `/complete`.
- Generalize `challenge.ts` for session nonces (single-use, 5-min TTL, in-memory map).
- Wire session-creation through existing `auth/sessions.ts` so the resulting tokens behave like all other sessions.
- Integration test: simulate a client with a known cert hitting the endpoint and getting a session.

### Phase 5: Link-existing-user flow

Deliverable: user with a password account can link to Tower-Identity from Settings.

- Add `Profile` / `AviatoIdentityPane` UI.
- Add server route `/api/auth/identity-link/start` to accept an already-authed session (no invite) and a different code path that calls `linkTowerIdentity()` on completion instead of creating a new user.
- Confirm dialog: "This replaces your password with Aviato Tower-Identity. You can unlink later by setting a new password."

### Phase 6: Devices pane + local revocation

Deliverable: user can see all clients that have authed against this server and revoke each.

- Build `DevicesPane.tsx`.
- Server endpoints to list `identity_clients` for current user, mark `revoked = 1`.
- Session-auth complete should refuse to issue a session for a revoked clientId.

### Phase 7: Renewal & remote revocation (lower priority)

- Cert renewal is opaque to the server (server only sees the new cert when a client uses it). No server work strictly needed. But: when a session-auth `cert.iat` is much newer than the last seen cert for that clientId, log it as renewal and update `certExpiresAt` in `identity_clients`.
- `POST /api/auth/identity/revocation/push` accepts M-signed revocation envelopes pushed from the user's other devices.
- Optional: server polls Tower's `/api/identity/revocations` CRL daily. Defer if Tower's CRL ships late.

### Phase 8: Polish & docs

- Update `docs/public/configuration.mdx` for any new env vars (probably `AVIATO_TOWER_URL` already covers it; double-check). Project convention requires this whenever config changes (CLAUDE.md).
- Update README / dev docs.
- Verify migration journal timestamps still ascending after merging from main.

## Cross-repo touchpoints (what Tower must ship first)

Tower's side must ship in this order to unblock this side:

1. `POST /api/identity/server-registration` — needed for Phase 2.
2. `POST /api/identity/pairing/register` + `GET /api/identity/pairing/{requestId}` + `GET /api/identity/pairing/code/{code}` + `POST /api/identity/pairing/code/{code}/complete` — needed for Phase 3.
3. The `/pair` web page on Tower — needed for Phase 3 user-facing.
4. Client-pair endpoints — needed for any native-app pairing testing (Phase 6+, the Apple app side).
5. Renewal endpoints — Phase 7.

A useful unblock pattern: build a `packages/server/src/license/__mocks__/tower-mock-identity.ts` that stubs all the Tower identity endpoints for integration tests, so we can finish phases 1–5 even before Tower's real endpoints are live in dev.

## Test plan

| Scope | Tool |
|---|---|
| Crypto helpers (cert, assertion, revocation) | Bun test, deterministic vectors |
| Server-link happy path | Bun test, in-process fakeTower |
| Cert-auth session | Bun test, in-process |
| End-to-end with real Tower dev env | Manual + scripted curl in `scripts/e2e-tower-identity.sh` (not in CI) |
| Web flows | Vitest for component logic + manual browser test using the dev server (CLAUDE.md "test the UI in a browser") |
| Migration ordering | `scripts/check-migration-order.sh` already gates this in CI |

## Conventions to honor

- No semicolons, type-only imports, simple-import-sort (CLAUDE.md "Code Style").
- `bun run lint` only when linting the whole package; `bunx eslint <file>` from the package dir for individual files (CLAUDE.md "Linting Specific Files").
- Never merge worktree into `dev` without explicit approval (CLAUDE.md "Git Worktrees" + memory `feedback_no_merge_without_consent`).
- No hardcoded media-type branching anywhere we touch the auth flow (not really relevant here, but applies if we end up touching anything in `packages/web/src/lib/`).
- Plugin SDK package must stay isolated; nothing in this work crosses into `~/projects/aviato/plugin-sdk` (memory `feedback_plugin_sdk_isolation`).
- All new server routes MUST use `@hono/zod-openapi` (CLAUDE.md "API Routes" + memory `feedback_zod_openapi`).
- Wire schemas defined ONCE in the client module; route file imports + adds `.openapi('Name')` (memory `feedback_zod_openapi_share_wire_schemas`).

## What NOT to do

- Do NOT change the v1 invite/challenge flow. Tower-Identity is additive (decided 2026-05-15).
- Do NOT delete or refactor the existing relay-based `server-record.ts` mechanism — v2 spec says coexistence is fine for now.
- Do NOT update the Tower repo from this side. The Tower implementation is a parallel session in `~/projects/ato/ato.software/`.
- Do NOT bundle this with the marketplace-schema sync requirement — Aviato Identity is not a manifest field. (Mentioning explicitly so the `feedback_ato_software_schema_sync` reflex doesn't trigger spurious cross-repo edits.)
