# Agent prompt: refactor `aviato` to consume the new pilot SDKs

Copy-paste this prompt into a Claude Code session running in `~/projects/aviato/aviato`. Adjust the install-strategy section if you publish the pilot packages to a registry before starting.

---

## Mission

Replace `aviato/aviato/packages/client-sdk`, the server-side identity v2 modules in `packages/server`, and the v2 schemas in `packages/common` with imports from the new pilot SDKs that live at `~/projects/aviato/pilot-sdk`. Keep every existing test passing. Do not change protocol bytes.

## Why this exists

We just stood up `~/projects/aviato/pilot-sdk` — a monorepo containing the cross-system crypto, schemas, and protocol logic that this codebase, the Tower codebase, and any third-party Aviato-protocol consumer all share. Today those primitives are vendored separately in three repos and they drift. The refactor consolidates this repo onto the shared SDKs.

The pilot-sdk repo is **done and fully tested** (60/60 tests pass, typecheck clean, lint clean). Treat its public surface as authoritative.

## What lives in `~/projects/aviato/pilot-sdk` (cheat sheet)

| Package | Path | Use it for |
|---|---|---|
| `@aviato-media/pilot-core` | `packages/core` | Crypto primitives (sealedbox, Ed25519, X25519, AES-GCM, HKDF, JCS, base64url/hex), all Zod schemas (cert, assertions, conn-info, pairing, vault, revocation), cert build/verify, assertion build/verify, conn-info AEAD seal/open + publish-sig, pairing-response leg, client-pair bundle, revocation envelope. Subpath exports: `/crypto`, `/schemas`, `/cert`, `/assertions`, `/conn-info`, `/revocation`. |
| `@aviato-media/pilot-client-sdk` | `packages/client-sdk` | `AviatoPilotClient` orchestrator (subscribe pattern, connection cache, hydrate, parallel init, cert renewal), `IdentityStorage` interface + `LocalStorageBackend` / `MemoryStorageBackend`, `TowerClient`, `serverCertAuth`, `resolveServerConnInfo`. Universal — no React deps. |
| `@aviato-media/pilot-client-react` | `packages/client-react` | `<PilotProvider>`, `usePilotConnections`, `usePilotConnection`, `usePilotIdentity`, `usePairing`, `useSignInToServer`, `useSignOut`, `useAviatoPilotClient`. Backed by `useSyncExternalStore`. Also re-exports the client SDK surface for ergonomics. |
| `@aviato-media/pilot-server-sdk` | `packages/server-sdk` | `PairingService`, `TowerClient`, `verifyServerLinkAssertion`, `verifyServerSignInAssertion`, `verifyAndPersist`, `beginChallenge`/`completeChallenge` (cert-auth), `ConnInfoPublisher`, `sealSessionConnInfoEnvelope`, plus persistence-agnostic store interfaces (`PairingRequestStore`, `IdentityClientStore`, `IdentityUserStore`, `SessionChallengeStore`) and in-memory test impls. |
| `@aviato-media/pilot-tower-sdk` | `packages/tower-sdk` | Tower-side only — **DO NOT touch in this task** (the Tower repo gets its own refactor). |

## Scope of this refactor

**In scope (this task):**
1. `aviato/packages/server/src/identity/v2/*` and `aviato/packages/server/src/identity/tower-identity/*` → consume `@aviato-media/pilot-server-sdk` + `@aviato-media/pilot-core`.
2. `aviato/packages/server/src/api/identity-link.ts` and `identity-session.ts` → keep the Hono routes; have them delegate to pilot-server-sdk functions.
3. `aviato/packages/client-sdk` → **delete the package entirely**. Its consumers move to `@aviato-media/pilot-client-react`.
4. `aviato/packages/web` (the React frontend) → migrate from `AviatoIdentityClient` to `@aviato-media/pilot-client-react` hooks.
5. `aviato/packages/common/src/identity/v2/*` (Zod schemas) → delete and re-export from `@aviato-media/pilot-core/schemas`. Anywhere in this repo that imports from `@aviato/common` for those schemas should switch to importing from `@aviato-media/pilot-core` directly.

**Out of scope (do not touch):**
- The pilot-sdk repo itself (`~/projects/aviato/pilot-sdk`). If there is a problem, we need to discuss the necessary changes to the pilot-sdk before implementation begins.
- The Tower repo (`~/projects/ato/ato.software`). It gets its own refactor pass; do not change anything there.
- The wire protocol. If you find yourself wanting to change a JCS ordering, an AAD prefix, a HKDF info string, a schema field name — **stop**. The pilot-sdk owns those bytes now and a change there has to be coordinated cross-repo. Match the existing bytes exactly.

## Install strategy

### CRITICAL: build pilot-sdk before installing in this repo

The pilot-sdk packages export `dist/index.js` (production-style — compiled TypeScript). They are **not** consumed from source. Bundlers that don't transpile `.ts` files inside `node_modules` (Next.js / Turbopack, some Vite configs, esbuild without `loader.ts`) refuse the source-as-`main` shape, so pilot-sdk publishes a precompiled `dist/` per package.

**Before** running `bun install` in `~/projects/aviato/aviato`:

```sh
cd ~/projects/aviato/pilot-sdk
bun install              # if you haven't already
bun run build            # produces dist/ in every package
```

This emits `dist/index.js` + `dist/index.d.ts` in `packages/core`, `packages/client-sdk`, `packages/client-react`, `packages/server-sdk`. After that, the file: deps in Aviato's `package.json` resolve cleanly.

### When pilot-sdk's deps change, force-reinstall in this repo

Bun's `file:` deps **do not automatically re-resolve transitive dependencies** when the linked package's `package.json` changes. If pilot-sdk added a new dep (e.g. `@scure/base`, `canonicalize`), your local Aviato install still has the old transitive set and bundlers will report `Module not found: Can't resolve '@scure/base'` or similar at build time.

After any `pilot-sdk/packages/*/package.json` dependency change, run from the aviato repo root:

```sh
rm -rf node_modules bun.lock
bun install
```

(Or `bun install --force` if you'd rather keep the lock. The destructive route is more reliable when chasing a resolution bug.)

Then restart any dev servers to clear bundler caches.

This is a standard file:-dep gotcha; the same step applies to any other consumer of pilot-sdk (Tower repo). The cleaner long-term fix is npm-publishing pilot-sdk, at which point standard semver + lockfile resolution handles transitive changes automatically.

### Active-development workflow (editing pilot-sdk and Aviato simultaneously)

If you're iterating on pilot-sdk source while testing changes in Aviato:

```sh
# Terminal 1: rebuild pilot-sdk dist on every change
cd ~/projects/aviato/pilot-sdk
bun run dev              # turbo runs `tsc --watch` in each package
```

Each pilot-sdk package has a `dev` script that watches `src/` and emits to `dist/`. Aviato-side dev servers pick up the new `dist` on next compile — no consumer-side bundler config change needed.

### File deps

The pilot-sdk packages are not (yet) published to npm. For local development, add them as file deps in each consuming package's `package.json`:

```json
{
  "dependencies": {
    "@aviato-media/pilot-core": "file:../../../pilot-sdk/packages/core",
    "@aviato-media/pilot-client-react": "file:../../../pilot-sdk/packages/client-react",
    "@aviato-media/pilot-server-sdk": "file:../../../pilot-sdk/packages/server-sdk"
  }
}
```

Adjust the `../` count for the actual depth of each consuming package. After editing, run `bun install` at the aviato repo root. If you hit symlink resolution issues with Bun's file deps across sibling repos, fall back to `bun link` — run `bun link` inside each pilot-sdk package, then `bun link <name>` inside each aviato consumer.

Confirm with the user before publishing to npm or any private registry — that's a one-way action.

## Step-by-step plan

### Phase 0: Foundations

1. Read `~/projects/aviato/pilot-sdk/README.md` and skim each package's `src/index.ts` to understand the public surface.
2. Inventory what `aviato/packages/client-sdk`, `aviato/packages/common/src/identity/v2`, and `aviato/packages/server/src/identity` currently export and where they're imported from across the repo.
3. Decide your import-path mapping: write a short note listing "this old import → this new import" for the dozen most common cases. Use this as your guide while refactoring.

### Phase 1: Server-side refactor

1. **Schemas first.** Replace internal imports of `@aviato/common`'s v2 schemas with `@aviato-media/pilot-core` imports. The schema *shapes* are identical (we ported them faithfully). Keep `@aviato/common` exporting them via a re-export shim if other workspace packages still import from there, or update those callers directly.
2. **Crypto + verifiers.** Replace direct `@aviato/crypto` usages in identity code paths with `@aviato-media/pilot-core` equivalents. The function names match (`ed25519Verify`, `verifyClientCert`, `verifyPairingAssertion`, `sealServerConnInfo`, `buildPairingResponse`, etc.).
3. **Pairing flow.** Replace `aviato/packages/server/src/identity/tower-identity/pairing.ts` and `tower-client-identity.ts` with thin glue around `PairingService` and `TowerClient` from `@aviato-media/pilot-server-sdk`. Wire up Drizzle-backed implementations of `PairingRequestStore`, `IdentityClientStore`, `IdentityUserStore`, `SessionChallengeStore` (the SDK is persistence-agnostic; in-memory impls ship for tests, but production needs Drizzle).
4. **Cert-auth handshake.** In `src/api/identity-session.ts`, replace inline verify/challenge logic with calls to `beginChallenge()` and `completeChallenge()` from the SDK. The route handlers stay; they just become thin adapters that map the SDK's tagged results (`{ ok, status, error }`) to Hono responses.
5. **Conn-info publishing.** Wire `ConnInfoPublisher` from the SDK into wherever the server currently builds + posts the ServerConnInfo body. Keep your existing strict-monotonic version persistence — the SDK takes `version` as a parameter, the host owns durability.
6. **K → user delivery.** When you process a completed pairing assertion, use `pairingService.respondWithK({ requestId, connInfoKey, userEncPubKey })` instead of the bespoke sealedbox code.
7. **In-session K refresh envelope.** Use `sealSessionConnInfoEnvelope` to build the envelope on session completion.

### Phase 2: Common package cleanup

1. Delete `aviato/packages/common/src/identity/v2/schemas.ts` and other v2 schema files.
2. Either delete `packages/common/src/identity/v2/index.ts` and update callers, OR keep the barrel as a re-export of `@aviato-media/pilot-core` for backwards compatibility (your call based on call-site count — pick whichever yields fewer changed files).

### Phase 3: Client-side refactor

1. **Delete `aviato/packages/client-sdk` entirely.** Its functionality is in `@aviato-media/pilot-client-sdk` + `@aviato-media/pilot-client-react`. Remove the package from `bun.lock`, from `aviato/package.json` workspaces (it should be covered by the `packages/*` glob — verify nothing references it explicitly), and from any consumer's dependencies.
2. **Migrate `aviato/packages/web`** (or wherever the Aviato Web React app lives) to use `@aviato-media/pilot-client-react`. Concrete changes:
   - Wrap your app tree in `<PilotProvider client={pilotClient}>`. Construct one `AviatoPilotClient` instance at module init.
   - Replace any direct `AviatoIdentityClient` usage with the hooks: `usePilotConnections()`, `usePilotConnection(serverPubKey)`, `usePilotIdentity()`, `usePairing()`, `useSignInToServer()`, `useSignOut()`.
   - **Connection status API changed.** It used to be a flat `{ serverPubKey, status: 'online', token, baseUrl, ... }`. It's now a discriminated union: `{ serverPubKey, status: { state: 'online', baseUrl, sessionToken, expiresAt } }`. Update destructures accordingly: `conn.status.state === 'online' && conn.status.sessionToken`.
   - `AviatoIdentityClient.startPair()` is now `AviatoPilotClient.beginPair()`. Returns a `PairingHandle` with `await()`, `cancel()`, and `ephemeral`. The `usePairing()` hook drives this flow for you — prefer the hook unless you need raw control.
   - `pollPair({ requestId, ephemeral })` now takes the `EphemeralPairState` object (which `beginPair()` returns on the handle). The shape changed slightly — `clientKeypair` + `clientEncKeypair` are the two keypairs (previously called `signingPriv` + `encryptionPriv` in the old SDK).
   - `subscribe(listener)` listeners now receive the full frozen snapshot `ReadonlyArray<ServerConnection>` on every change, not just the delta. The React hooks already memoize correctly via `useSyncExternalStore`.

### Phase 4: Verification

1. `bun install` clean at the aviato repo root.
2. `bun run typecheck` across the whole repo.
3. `bun run lint` across the whole repo (use `bunx eslint <file>` from a package dir for single-file iteration).
4. `bun run test` across the whole repo. Existing identity tests must still pass. If any test was verifying *exact* old type shapes (e.g. `expect(conn.token).toBe(...)`), update the assertions to the new shape (`conn.status.state === 'online' && conn.status.sessionToken`).
5. Run the dev environment and manually exercise: invite-link server-link, web sign-in, settings → devices pane, client-pair flow if reachable from the web UI.

## Conventions to honor

These are non-negotiable per `CLAUDE.md` and prior feedback in this repo:

- **No semicolons**, type-only imports, simple-import-sort (CLAUDE.md "Code Style").
- **`bun run lint` only when linting the whole package**; `bunx eslint <file>` from the package dir for single files (CLAUDE.md "Linting Specific Files").
- **Never merge a worktree into `dev` without explicit user approval** (memory `feedback_no_merge_without_consent`).
- **All new server routes MUST use `@hono/zod-openapi`** (CLAUDE.md "API Routes" + memory `feedback_zod_openapi`). The existing identity-link and identity-session routes already do; preserve that.
- **Wire schemas defined ONCE in the client module**; route file imports + adds `.openapi('Name')` (memory `feedback_zod_openapi_share_wire_schemas`). With the pilot-sdk move, the "client module" for schemas is now `@aviato-media/pilot-core/schemas` — import directly and add `.openapi('Name')` where the route definition needs it.
- **Integration tests for migrations must hit a real database, not mocks** (memory `feedback_integration_tests_real_db` — paraphrased).
- **Plugin SDK stays isolated** (memory `feedback_plugin_sdk_isolation`) — this refactor must not pull anything from `~/projects/aviato/plugin-sdk` or touch it.

## CRITICAL: SDK API takes Uint8Array, not hex strings

The pilot SDKs went through a structural refactor to eliminate encoding ambiguity at the type level. **Every pubkey input to the SDK is `Uint8Array` (raw 32 bytes), not a hex string.** The SDK hex-encodes internally for the JCS-canonicalized wire payloads. Schemas still validate hex strings on the wire, but no caller ever constructs or parses one.

If you have a hex string from a Zod-validated wire payload and need bytes, use `pubkeyFromHex(hex)` from `@aviato-media/pilot-core`. If you have base64url, use `pubkeyFromBase64Url(b64u)`. Both throw on malformed input.

Concrete API differences (server-side):

```ts
// OLD (don't use):
new PairingService(tower, store, { serverPubKeyHex: '...', serverPrivKey, ... })
verifyServerLinkAssertion({ expectedServerPubKeyHex: '...', ... })
beginChallenge({ serverPubKeyHex: '...', ... })

// NEW (correct):
new PairingService(tower, store, { serverPubKey: bytes, serverPrivKey, ... })
verifyServerLinkAssertion({ expectedServerPubKey: bytes, ... })
beginChallenge({ serverPubKey: bytes, ... })
```

Same on the client side:

```ts
// OLD:
await client.signInToServer({ serverPubKeyHex: 'a...0' })

// NEW:
await client.signInToServer({ serverPubKey: pubkeyFromHex('a...0') })
```

Affected APIs (every `*PubKeyHex: string` → `*PubKey: Uint8Array`):

- `PairingService` constructor config: `serverPubKey`
- `ConnInfoPublisher` constructor config: `serverPubKey`
- `verifyServerLinkAssertion`, `verifyServerSignInAssertion`, `verifyAndPersist`: `expectedServerPubKey`, `expectedUserPubKey`
- `beginChallenge`, `completeChallenge`: `serverPubKey`
- `sealSessionConnInfoEnvelope`: `clientEncPubKey`
- `AviatoPilotClient.signInToServer`: `serverPubKey`
- `serverCertAuth`, `resolveServerConnInfo`, `deriveServerConnInfoHash`: `serverPubKey`
- All pilot-core verifiers and builders: `*PubKey` (bytes)

**Source-to-bytes conversion:** wire payloads (cert payloads, vault entries, assertion payloads) store pubkeys as hex strings (Zod schemas enforce HEX_32). When you read a pubkey from one of these and want to call an SDK function, convert with `pubkeyFromHex(value)`.

```ts
// User row hex → SDK verifier:
import { pubkeyFromHex } from '@aviato-media/pilot-core'

const userRow = await db.users.findUnique({ where: { id } })
const verified = verifyServerLinkAssertion({
  envelope,
  expectedRequestId,
  expectedServerPubKey: serverPubKeyBytes,  // your server's identity, kept as bytes
})
// Inside the verifier, the SDK hex-encodes before comparing to the wire payload.
```

The "Unnamed server" / `payload_shape_invalid` failure modes from any prior pass are now structurally impossible — passing a wrong-encoded string is a TypeScript error, not a runtime mystery.

## SDK shape updates (since the first draft of this prompt)

The pilot-sdk picked up four API refinements based on feedback from an earlier refactor attempt. If you're starting fresh, use these shapes directly — they remove workarounds the previous pass had to invent:

1. **`PairingService.start({ kind, ... })`** now accepts `kind: 'server-link' | 'server-sign-in'` (defaults to `'server-link'`). Use the SDK for both flows — no need to drop to raw `TowerClient.pairingRegister`. For `kind: 'server-sign-in'`, the `inviteToken`/`localUserId` xor validation is skipped (those fields are optional; the host's prior session-auth proves the user identity).
2. **`AviatoPilotClient` constructor accepts `towerWebUrl?: string`** (defaults to `towerBaseUrl`). The `PairingHandle` returned by `beginPair()` now carries `pairingUrl: string` built from that. Use `handle.pairingUrl` directly — do not reconstruct the URL manually.
3. **`IdentityClientRow.revoked: boolean`** replaced the old `revokedAt: string | null`. The SDK never reads timestamps from the row; hosts that want audit timestamps store them in their own schema. `IdentityClientStore.revoke(clientId)` lost its `atIso` argument.
4. **`serverCertAuth<TBody>` is generic**. The return type is `ServerCertAuthResult<TBody>` with `body: TBody` carrying the full parsed `/identity-session/complete` response. `AviatoPilotClient.signInToServer<TBody>()` threads the same generic — the returned object is `ServerConnection & { body?: TBody }`. Use this for app-specific extras (profiles, feature flags, server caps) rather than bypassing the SDK helper.

Example usage of the generic body:

```ts
interface AviatoSessionBody {
  token: string
  expiresAt: string
  profiles: Array<{ id: string, name: string }>
}
const conn = await client.signInToServer<AviatoSessionBody>({ serverPubKeyHex })
if (conn.status.state === 'online') {
  setProfiles(conn.body?.profiles ?? [])
}
```

## API differences summary (the things most likely to bite you)

| Old (aviato/client-sdk) | New (pilot-client-sdk / -react) |
|---|---|
| `AviatoIdentityClient` | `AviatoPilotClient` |
| `client.startPair()` | `client.beginPair()` returns `PairingHandle` with `await()` |
| `client.pollPair({ requestId, ephemeral })` ephemeral shape `{ signingPriv, encryptionPriv }` | `client.pollPair({ ephemeral })` where ephemeral is `{ requestId, clientKeypair: { publicKey, privateKey }, clientEncKeypair: { publicKey, privateKey } }` |
| `ServerConnection.token`, `.baseUrl` flat fields | `ServerConnection.status.sessionToken`, `.status.baseUrl` inside the `'online'` variant of a discriminated union |
| `ServerConnectionStatus = 'idle' \| 'connecting' \| 'online' \| 'offline' \| 'error'` string | `ServerConnectionStatus = { state: 'idle' } \| { state: 'online', baseUrl, sessionToken, expiresAt } \| { state: 'error', error } \| ...` discriminated union |
| `client.subscribe(listener)` listener gets a single connection | `client.subscribe(listener)` listener gets `ReadonlyArray<ServerConnection>` snapshot of all |
| Manual `${towerWebUrl}/pair?code=${code}` URL construction | `handle.pairingUrl` (set `towerWebUrl` at construction if it differs from `towerBaseUrl`) |
| `serverCertAuth` returned `{ token, expiresAt, refreshedConnInfoKey }` only | `serverCertAuth<TBody>` is generic; result includes `body: TBody` with the full response |
| `client.signInToServer()` returned only `ServerConnection` | `client.signInToServer<TBody>()` returns `ServerConnection & { body?: TBody }` — typed app-extras |
| `PairingService.start()` was server-link only | `PairingService.start({ kind: 'server-link' \| 'server-sign-in' })` — defaults to `server-link` |
| `IdentityClientStore.revoke(clientId, atIso)` and rows had `revokedAt: string \| null` | `IdentityClientStore.revoke(clientId)`; rows have `revoked: boolean`. Store audit timestamps in your own schema |
| `client.clear()` | `client.signOut()` (alias `clear()` kept for transition) |
| Direct vendored `crypto.ts` functions (`aviatoSealedBoxEncrypt`, `jcs`, etc.) | Import from `@aviato-media/pilot-core` |
| Direct vendored Zod schemas | Import from `@aviato-media/pilot-core` (or `@aviato-media/pilot-core/schemas`) |
| Server: bespoke `verifySessionAssertion`, `verifyCert` in `identity/v2` | `@aviato-media/pilot-core`'s `verifySessionAssertion`, `verifyClientCert` |
| Server: bespoke `pairing.ts` in `identity/tower-identity` | `@aviato-media/pilot-server-sdk`'s `PairingService` |

## What NOT to do

- Do not modify the pilot-sdk source (`~/projects/aviato/pilot-sdk`). It's frozen for this task. If you find a bug or missing API, stop and report it back — do not edit it from this side.
- Do not change protocol bytes (JCS field orders, AAD prefixes, HKDF info strings, schema field names). If the byte format needs to change, the change belongs in pilot-sdk first, then both repos in lockstep.
- Do not republish or change versions of the pilot-sdk packages. Use them as file: deps locally.
- Do not skip pre-commit hooks (`--no-verify`) or signing flags. If a hook fails, fix the underlying issue.
- Do not merge any worktree into `dev` without explicit user approval, even if everything passes.
- Do not amend or force-push commits — create new commits for each fix.
- Do not delete `aviato/packages/plugin-sdk` or anything in `~/projects/aviato/plugin-sdk`.
- Do not touch the Tower codebase (`~/projects/ato/ato.software`) in this task.

## Done criteria

You're done when **all of the following** are true:

- [ ] `aviato/packages/client-sdk/` directory no longer exists.
- [ ] No file in this repo imports from `@aviato-media/client-sdk` (the old name) or from `./packages/client-sdk` relative paths.
- [ ] No file in this repo contains a vendored `aviatoSealedBox*`, JCS impl, or duplicate of any pilot-core schema. Everything routes through `@aviato-media/pilot-core`.
- [ ] `aviato/packages/server/src/identity/v2/` and `aviato/packages/server/src/identity/tower-identity/` are gone or reduced to thin Drizzle adapter glue + route bindings. The verification, signing, sealing, and HTTP-to-Tower logic comes from `@aviato-media/pilot-server-sdk`.
- [ ] `aviato/packages/web` uses `<PilotProvider>` + hooks from `@aviato-media/pilot-client-react`. No direct `AviatoIdentityClient` references remain.
- [ ] `bun run typecheck` passes across the whole repo.
- [ ] `bun run test` passes across the whole repo. (If any test had to be updated for the new connection-status shape, that's expected — note it in the PR description.)
- [ ] `bun run lint` reports zero errors (warnings on intentional non-null assertions are acceptable, but should be the same set as before this refactor + any unavoidable new ones).
- [ ] Manual smoke test of server-link flow + web sign-in succeeds in the dev environment.
- [ ] You stop and ask before doing anything destructive that wasn't pre-authorized here (publishing, force-pushing, merging into `dev`, etc.).

## Reporting

When you finish, report:
1. **Files deleted** (count + the top-level directories that went away).
2. **Files modified** (count, grouped by package).
3. **Test count** before vs after.
4. **Any API gap you hit** in the pilot-sdk packages — anything where you wished the SDK exposed something it doesn't. Don't paper over with vendored re-implementations; flag it for a follow-up pilot-sdk PR.
5. **Manual smoke-test results** for server-link, web sign-in, client-pair (if reachable).

If you hit a blocker that can't be resolved without modifying the pilot-sdk or the Tower codebase, stop and surface it. Don't work around it.
