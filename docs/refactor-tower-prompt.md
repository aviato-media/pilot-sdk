# Agent prompt: refactor `ato.software` (Tower) to consume the pilot SDKs

Copy-paste this prompt into a Claude Code session running in `~/projects/ato/ato.software`. Adjust the install-strategy section if you publish the pilot packages to a registry before starting.

---

## Mission

Replace the hand-rolled crypto, vault, and PRF code in `tower-web/src/lib/` with imports from `@aviato-media/pilot-tower-sdk` + `@aviato-media/pilot-core`, and replace the vendored Zod schemas Tower currently uses for request/response validation with imports from `@aviato-media/pilot-core`. Keep every existing test passing. Do not change protocol bytes.

## Why this exists

We just stood up `~/projects/aviato/pilot-sdk` — a monorepo containing the cross-system crypto, schemas, and protocol logic that Tower, the Aviato media-server codebase, and any third-party Aviato-protocol consumer all share. Until now those primitives lived independently in three repos and drifted. This refactor consolidates Tower onto the shared SDKs so the byte-level wire contract has a single source of truth.

The pilot-sdk repo is **done and fully tested** (60/60 tests pass, typecheck clean, lint clean). Treat its public surface as authoritative — the implementations were ported faithfully from the canonical references that already exist in `tower-web/src/lib/sealedbox.ts`, `vault.ts`, etc.

## What lives in `~/projects/aviato/pilot-sdk` (cheat sheet)

| Package | Path | Use it for |
|---|---|---|
| `@aviato-media/pilot-core` | `packages/core` | Crypto primitives (sealedbox, Ed25519, X25519, AES-GCM, HKDF, JCS, base64url/hex), all Zod schemas (cert, assertions, conn-info, pairing, vault, revocation), cert build/verify, assertion build/verify, conn-info AEAD seal/open + publish-sig, pairing-response leg, client-pair bundle, revocation envelope. Subpath exports: `/crypto`, `/schemas`, `/cert`, `/assertions`, `/conn-info`, `/revocation`. |
| `@aviato-media/pilot-tower-sdk` | `packages/tower-sdk` | **The package most of this refactor uses.** Vault create/open/wrap/unwrap, multi-passkey add/remove, PRF helpers (`buildPrfInputs`, `extractPrfOutput`, `derivePrfWrappingKey`, `generatePrfSalt`), master-key assertion builders (`approveServerLink`, `approveServerSignIn`), client-pair cert + sealed bundle builders (`buildClientPairCert`, `buildClientPairBundle`), pairing-response opener (`claimConnInfoKey`), conn-info fetch+verify+decrypt for UI previews. Pure crypto + assertion building — zero HTTP. Tower-web wires its own fetch calls to Tower-api. |
| `@aviato-media/pilot-client-sdk` | `packages/client-sdk` | Client-side orchestrator — **not used by Tower itself**, but the Aviato media-server side will consume this; relevant only if you're cross-referencing types. |
| `@aviato-media/pilot-client-react` | `packages/client-react` | React bindings for the client SDK — **not used by Tower**. |
| `@aviato-media/pilot-server-sdk` | `packages/server-sdk` | Media-server SDK — **not used by Tower**. The Aviato repo gets its own refactor against this. |

## Scope of this refactor

**In scope (this task):**
1. `tower-web/src/lib/sealedbox.ts` → delete. All callers switch to `@aviato-media/pilot-core`'s `aviatoSealedBoxEncrypt` / `aviatoSealedBoxDecrypt` / `aviatoSealedBoxDecryptJson`.
2. `tower-web/src/lib/pairing-response.ts` → delete. Callers switch to `@aviato-media/pilot-tower-sdk`'s `claimConnInfoKey`.
3. `tower-web/src/lib/vault.ts` → delete. Callers switch to `@aviato-media/pilot-tower-sdk`'s `createVault`, `openVault`, `addPasskeyToVault`, `removePasskeyFromVault`, `replaceVaultPayload`, `encryptVault`, `decryptVault`, `wrapVaultKey`, `unwrapVaultKey`, `generateVaultKey`.
4. `tower-web/src/lib/prf.ts` → delete. Callers switch to `@aviato-media/pilot-tower-sdk`'s `buildPrfInputs`, `extractPrfOutput`, `derivePrfWrappingKey`, `generatePrfSalt`.
5. `tower-web/src/lib/vault-context.tsx` → **keep**, but refactor its internal calls to use `@aviato-media/pilot-tower-sdk` underneath. The `VaultProvider` / `useVault` React API for the rest of Tower-web stays unchanged.
6. The `/pair` page's assertion-signing flow → use `@aviato-media/pilot-tower-sdk`'s `approveServerLink` / `approveServerSignIn` to build the M-signed envelope instead of any inline JCS+Ed25519 code.
7. The `/pair` page's client-pair consent flow → use `@aviato-media/pilot-tower-sdk`'s `buildClientPairCert` + `buildClientPairBundle` instead of inline cert/sealed-bundle code.
8. `tower-api/src/routes/identity-*.ts` → replace any vendored Zod schemas used for `@hono/zod-openapi` request/response validation with imports from `@aviato-media/pilot-core/schemas`. Add `.openapi('Name')` at the route binding site rather than at schema definition (the SDK schemas are plain Zod; the route file owns its OpenAPI naming).
9. `tower-api/src/routes/identity-server-conninfo.ts` → replace the manual Ed25519 publish-sig verification with `@aviato-media/pilot-core`'s `verifyConnInfoRecordSig` (or `ed25519Verify` over the canonical bytes produced by `buildConnInfoCanonical`).
10. Anywhere a Tower file currently re-implements `aviatoSealedBox*`, JCS, base64url, hex, HKDF, or any pilot-core primitive — replace with the SDK function.

**Out of scope (do not touch):**
- The pilot-sdk repo itself (`~/projects/aviato/pilot-sdk`). If there is a problem with the SDK, stop and discuss the necessary changes with the user before implementation begins. Do not edit pilot-sdk from this side.
- The Aviato media-server repo (`~/projects/aviato/aviato`). It gets its own refactor pass; do not change anything there.
- Tower's WebAuthn integration (SimpleWebAuthn calls in `tower-api/src/lib/webauthn.ts` and elsewhere). The PRF *helpers* in pilot-tower-sdk produce the inputs / parse the outputs, but the actual `navigator.credentials.create()` / `.get()` calls and SimpleWebAuthn server-side verification stay in Tower.
- Tower's DynamoDB layer (`tower-api/src/lib/*-db.ts`). The pilot SDKs are persistence-agnostic; the DDB CRUD stays.
- Tower's Stripe, license-key, DDNS, email, app-registry code — unrelated to identity protocol crypto.
- The wire protocol itself. If you find yourself wanting to change a JCS ordering, an AAD prefix, a HKDF info string (`"aviato-sealedbox-v1"`, `"aviato-vault-wrap/v1"`, `"aviato-server-conninfo-v1"`), or a schema field name — **stop**. The pilot-sdk owns those bytes and a change there has to be coordinated cross-repo. Match the existing bytes exactly.

## Install strategy

### CRITICAL: build pilot-sdk before installing in this repo

The pilot-sdk packages export `dist/index.js` (production-style — compiled TypeScript). They are **not** consumed from source. Next.js / Turbopack and most other bundlers refuse to handle `.ts` files inside `node_modules`, so the source-as-`main` shape that some monorepos use does not work here.

**Before** running `bun install` in `~/projects/ato/ato.software`:

```sh
cd ~/projects/aviato/pilot-sdk
bun install              # if you haven't already
bun run build            # produces dist/ in every package
```

This emits `dist/index.js` + `dist/index.d.ts` in `packages/core`, `packages/tower-sdk`, etc. After that, the file: deps in Tower's `package.json` resolve cleanly:

### When pilot-sdk's deps change, force-reinstall in this repo

Bun's `file:` deps **do not automatically re-resolve transitive dependencies** when the linked package's `package.json` changes. If pilot-sdk added a new dep (e.g. `@scure/base`, `canonicalize`), your local Tower install still has the old transitive set and Turbopack will report `Module not found: Can't resolve '@scure/base'` or similar at build time.

After any `pilot-sdk/packages/*/package.json` dependency change, run from the ato.software root:

```sh
rm -rf node_modules bun.lock
bun install
```

(Or `bun install --force` if you'd rather keep the lock. The destructive route is more reliable when chasing a resolution bug.)

Then restart the Next.js dev server to clear Turbopack's module-graph cache:

```sh
# kill the running `bun run dev:tower` and restart it
```

This is a standard file:-dep gotcha; the same step applies to any other consumer of pilot-sdk (Aviato repo). The cleaner long-term fix is npm-publishing pilot-sdk, at which point standard semver + lockfile resolution handles transitive changes automatically.

### Active-development workflow (editing pilot-sdk and Tower simultaneously)

If you're iterating on pilot-sdk source while testing changes in Tower:

```sh
# Terminal 1: rebuild pilot-sdk dist on every change
cd ~/projects/aviato/pilot-sdk
bun run dev              # turbo runs `tsc --watch` in each package
```

Each pilot-sdk package has a `dev` script that watches `src/` and emits to `dist/`. Tower-web (Next.js) picks up the new `dist` on next compile — no Tower config change needed.

### File deps

The pilot-sdk packages are not (yet) published to npm. For local development, add them as file deps in each consuming package's `package.json`:

```json
{
  "dependencies": {
    "@aviato-media/pilot-core": "file:../../../aviato/pilot-sdk/packages/core",
    "@aviato-media/pilot-tower-sdk": "file:../../../aviato/pilot-sdk/packages/tower-sdk"
  }
}
```

Adjust the `../` count for the actual depth from each consuming package (`tower-web` and `tower-api` are both at `packages/<name>` so the path above is correct). After editing, run `bun install` at the ato.software repo root. If you hit symlink resolution issues with Bun's file deps across sibling repos, fall back to `bun link` — run `bun link` inside each pilot-sdk package, then `bun link <name>` inside each ato.software consumer.

Confirm with the user before publishing to npm or any private registry — that's a one-way action.

## Step-by-step plan

### Phase 0: Foundations

1. Read `~/projects/aviato/pilot-sdk/README.md` and skim `packages/tower-sdk/src/index.ts` + `packages/core/src/index.ts` to understand the public surface.
2. Inventory current callers of `tower-web/src/lib/{sealedbox,pairing-response,vault,prf}.ts` across the Tower-web codebase. Note which components / pages / hooks depend on each.
3. Inventory which Zod schemas Tower-api currently vendors locally (search `routes/identity-*.ts` and `lib/` for `z.object`, `SealedBoxSchema`, `ServerConnInfo*`, `PairingResponse*`, etc.).
4. Read this repo's own `CLAUDE.md` and any memory entries for conventions and prior feedback (no semicolons, simple-import-sort, hooks rules, etc.).
5. Decide your import-path mapping: write a short note listing "this old import → this new import" for the dozen most common cases.

### Phase 1: tower-web crypto deletion + pilot-sdk adoption

1. **PRF first.** Replace `import { ... } from '@/lib/prf'` (and equivalent paths) with `from '@aviato-media/pilot-tower-sdk'`. The function names match exactly: `buildPrfInputs`, `extractPrfOutput`, `derivePrfWrappingKey`, `generatePrfSalt`. Delete `tower-web/src/lib/prf.ts`.
2. **Sealedbox.** Replace `from '@/lib/sealedbox'` with `from '@aviato-media/pilot-core'`. Function names match: `aviatoSealedBoxEncrypt`, `aviatoSealedBoxDecrypt`, `aviatoSealedBoxDecryptJson`. Delete `tower-web/src/lib/sealedbox.ts`.
3. **Vault.** Replace `from '@/lib/vault'` with `from '@aviato-media/pilot-tower-sdk'`. Function names match: `createVault`, `openVault`, `addPasskeyToVault`, `removePasskeyFromVault`, `replaceVaultPayload`, `encryptVault`, `decryptVault`, `wrapVaultKey`, `unwrapVaultKey`, `generateVaultKey`, `bytesToB64u`. Delete `tower-web/src/lib/vault.ts`.
4. **Pairing-response.** Replace `from '@/lib/pairing-response'` with `from '@aviato-media/pilot-tower-sdk'`. The browser-side handler is now `claimConnInfoKey({ record, userEncPrivKey, expectedServerPubKeyHex })`. Delete `tower-web/src/lib/pairing-response.ts`.
5. **Vault context.** Refactor `tower-web/src/lib/vault-context.tsx` so its internal calls (`createVault`, `openVault`, `addPasskeyToVault`, etc.) come from `@aviato-media/pilot-tower-sdk`. The public API (`VaultProvider`, `useVault`) does not change — consumers don't notice. Verify the `VaultPayload` shape matches what pilot-core's `VaultPayloadSchema` defines; if Tower stored anything Tower-specific in the payload, surface that to the user before changing the schema.

### Phase 2: tower-web assertion + client-pair builders

1. The `/pair` page's "approve server-link" / "approve server-sign-in" code path → replace any inline JCS+Ed25519 signing of the assertion with `approveServerLink({ requestId, serverPubKeyHex, userId, userPubKeyHex, userEncPubKeyHex, masterPrivKey })` (or `approveServerSignIn`). The output `{ assertionSignature, signedAssertionBytes }` is what gets POSTed to `/api/identity/code/:code/complete`.
2. The `/pair` page's "approve client-pair" code path → replace inline cert construction with `buildClientPairCert({ appId, clientId, clientPubKeyHex, clientEncPubKeyHex, deviceName, scope, userId, userPubKeyHex, userEncPubKeyHex, masterPrivKey })` and the sealed bundle with `buildClientPairBundle({ clientEncPubKey, servers })`. The `servers` argument should be the user-ticked subset of `vault.servers` for this app.
3. If Tower-web also fetches + previews a paired server's connection info on the dashboard (e.g. "online" / "offline" badge next to each server in /dashboard/servers), replace the fetch+verify+decrypt code with `resolveConnInfo({ record, connInfoKey })` from pilot-tower-sdk. (The fetch URL builder `deriveConnInfoHash(serverPubKeyHex)` is also exported.)

### Phase 3: tower-api schema + signature verification

1. **Schemas.** In every `tower-api/src/routes/identity-*.ts`, replace local Zod definitions of `SealedBoxSchema`, `ServerConnInfoPayloadSchema`, `ServerConnInfoPublishSchema`, `ServerConnInfoRecordSchema`, `PairingRegisterRequestSchema`, `PairingRegisterResponseSchema`, `PairingCodeResolveResponseSchema`, `PairingResponseSealedSchema`, `PairingResponsePayloadSchema`, `PairingResponseRecordSchema`, `ClientKeyBundleServerSchema`, `ClientKeyBundleContentsSchema`, `ClientDelegationCertPayloadSchema`, `ClientDelegationCertEnvelopeSchema`, `MasterSignedAssertionEnvelopeSchema`, `VaultBlobSchema`, `PairedClientRowSchema`, `PairedClientViewSchema`, `PairedClientListResponseSchema`, etc. with imports from `@aviato-media/pilot-core/schemas`. Add `.openapi('Name')` at the route binding site (not at the schema definition).

   **CRITICAL — the `displayName` drift bug:** The `POST /api/identity/pairing/register` and `GET /api/identity/code/:code/resolve` routes MUST import `PairingRegisterRequestSchema` and `PairingCodeResolveResponseSchema` from `@aviato-media/pilot-core`. Both include `displayName` and `serverIcon` as optional fields — pilot-server-sdk sends those in the register body when the host has configured them. If Tower-api re-defines these schemas locally and omits `displayName`, Hono's zod-openapi validation strips the field and Tower-web renders "Unnamed server" on `/pair`. **Do not redefine these schemas locally.**

   The persistence layer (`tower-api/src/lib/identity-pairing-db.ts`) must also persist `displayName` and `serverIcon` from the validated request body — the route handler is responsible for passing them through to the DDB row write, and the resolve handler must read them back. End-to-end:

   ```
   pilot-server-sdk → POST /pairing/register { displayName, serverIcon, ... }
        → tower-api validates with PairingRegisterRequestSchema (canonical)
        → tower-api persists displayName + serverIcon to DDB pairing row
        → Tower-web GET /code/:code/resolve
        → tower-api returns PairingCodeResolveResponse including displayName + serverIcon
        → Tower-web renders "<displayName>" on /pair consent screen
   ```

   Each arrow is a place where the field can drop. Trace it end-to-end if "Unnamed server" recurs.
2. **Conn-info publish signature.** `tower-api/src/routes/identity-server-conninfo.ts` currently does a manual `ed25519.verify(...)` over `JSON.stringify({ct, nonce, serverPubKey, version})`. Replace with `verifyConnInfoRecordSig(record)` from `@aviato-media/pilot-core` (the SDK builds the canonical bytes identically and verifies). Same goes for any other identity-related Ed25519 verification — use the SDK helper rather than inlining.
3. **Sealedbox / sealed bodies.** Tower-api does not decrypt sealedboxes (Tower is blind to K and to vault payloads). If Tower-api has any code that *constructs* a sealedbox (it shouldn't, in normal flow), replace it with `aviatoSealedBoxEncrypt` from `@aviato-media/pilot-core`.
4. **Cert validation utilities.** `tower-api/src/lib/identity-cert.ts` (if it does shape checks like base64url length validation) can be deleted in favor of the Zod schemas it was hand-rolling around. If it does signature checks, those should also route through `verifyClientCert` from `@aviato-media/pilot-core`. Tower itself shouldn't be cert-verifying for normal flows — that's the media server's job — but if there's any place where it does, route through the SDK.

### Phase 4: Verification

1. `bun install` clean at the ato.software repo root.
2. `bun run typecheck` across the whole repo (`turbo run typecheck`).
3. `bun run lint` across the whole repo. Use `bunx eslint <file>` from a package dir for single-file iteration.
4. `bun run test` across the whole repo. Existing Tower tests must still pass. If any test was asserting against a vendored type that's now imported from the SDK, the assertion should still work (the SDK types are structurally identical) — just update import paths.
5. Run the staging stack (`bun run dev:tower` or whichever script your `package.json` ships) and manually exercise:
   - Register a fresh Tower account → vault is created via SDK.
   - Add a second passkey → wrap is added via SDK.
   - Server-link a fresh media server end-to-end → assertion built via SDK, sealed K opens correctly via SDK.
   - Client-pair an app from `/pair` → cert + sealed bundle build via SDK.
   - GET `/api/identity/server-conninfo/:hash` and confirm a paired client can decrypt it (cross-stack — easiest to verify with `aviato/aviato`'s integration tests once that side's refactor lands; for this PR, manual decrypt via a script using pilot-tower-sdk is sufficient).

## Conventions to honor

Check the Tower repo's own `CLAUDE.md` and any memory entries first — they take precedence. The following are conventions I know about from the broader Aviato ecosystem; verify each is current for this repo:

- **No semicolons**, type-only imports, simple-import-sort (eslint-joy default).
- **`bun run lint` only when linting the whole package**; `bunx eslint <file>` from the package dir for single files.
- **Never merge a worktree into `main` (or whatever Tower's default branch is) without explicit user approval.**
- **All Hono routes use `@hono/zod-openapi`** with `.openapi('Name')` at the route binding site.
- **Wire schemas defined once** — with this refactor, "once" now means in `@aviato-media/pilot-core`. Local route files import + add `.openapi('Name')`.
- **Tower-web is Next.js** — preserve App Router patterns, Server Component vs Client Component boundaries, `'use client'` directives, etc. Don't accidentally turn a Server Component into a Client one by adding a hook import.
- **Tower-api is AWS Lambda + DynamoDB** — preserve cold-start sensitivity. Don't add heavy imports at module top level if a route doesn't need them; tree-shake-friendly subpath imports (`@aviato-media/pilot-core/schemas`) help here.
- **Husky pre-commit hooks** must not be skipped (`--no-verify`).

## CRITICAL: SDK API takes Uint8Array, not hex strings

The pilot SDKs went through a structural refactor to eliminate encoding ambiguity at the type level. **Every pubkey input to the SDK is `Uint8Array` (raw 32 bytes), not a hex string.** The SDK hex-encodes internally for the JCS-canonicalized wire payloads. Schemas still validate hex strings on the wire (HEX_32 regex), but no caller ever constructs or parses one.

This means: **encoding mismatches between Tower-api and Tower-web are now impossible to express in the type system.** If you have a hex string from a Zod-validated wire payload and need bytes, use `pubkeyFromHex(hex)` from `@aviato-media/pilot-core`. If you have base64url (legacy URL fragment, etc.), use `pubkeyFromBase64Url(b64u)`. Both throw on malformed input.

Concrete API differences from any earlier draft of this prompt:

```ts
// OLD (don't use):
approveServerLink({ serverPubKeyHex: '...', userPubKeyHex: '...', userEncPubKeyHex: '...', masterPrivKey })

// NEW (correct):
approveServerLink({ serverPubKey: bytes, userPubKey: bytes, userEncPubKey: bytes, masterPrivKey })
```

Same shape applies to:

| Function | Old field(s) | New field(s) |
|---|---|---|
| `approveServerLink`, `approveServerSignIn` | `serverPubKeyHex`, `userPubKeyHex`, `userEncPubKeyHex` | `serverPubKey`, `userPubKey`, `userEncPubKey` (all `Uint8Array`) |
| `buildClientPairCert` | `clientPubKeyHex`, `clientEncPubKeyHex`, `userPubKeyHex`, `userEncPubKeyHex` | `clientPubKey`, `clientEncPubKey`, `userPubKey`, `userEncPubKey` |
| `buildClientPairBundle` | `servers[].serverPubKey: hex string`, `servers[].connInfoKey: base64url string` | `servers[].serverPubKey: Uint8Array`, `servers[].connInfoKey: Uint8Array \| null` |
| `claimConnInfoKey` | `expectedServerPubKeyHex` | `expectedServerPubKey: Uint8Array` |
| `deriveConnInfoHash` | `serverPubKeyHex: string` | `serverPubKey: Uint8Array` |
| `sealServerConnInfo` (pilot-core) | `serverPubKey: string` | `serverPubKey: Uint8Array` |
| `buildPairingResponse` / `openPairingResponse` (pilot-core) | `serverPubKeyHex`, `expectedServerPubKeyHex` | `serverPubKey`, `expectedServerPubKey` |
| `buildSessionAssertion` / `verifySessionAssertion` (pilot-core) | `serverPubKeyHex` | `serverPubKey: Uint8Array` |
| `verifyClientCert` (pilot-core) | `opts.expectedUserPubKeyHex` | `opts.expectedUserPubKey: Uint8Array` |
| `verifyPairingAssertion` (pilot-core) | `expectedServerPubKeyHex`, `expectedUserPubKeyHex` | `expectedServerPubKey`, `expectedUserPubKey` |
| `verifyRevocation` (pilot-core) | `opts.expectedUserPubKeyHex` | `opts.expectedUserPubKey: Uint8Array` |

**Source-to-bytes conversion:** Vault entries and wire payloads store pubkeys as hex strings (the Zod schemas enforce HEX_32). When you read a pubkey from one of these and want to call an SDK function, convert with `pubkeyFromHex(value)` — this returns `Uint8Array` and throws if `value` isn't 64 lowercase hex chars.

```ts
import { pubkeyFromHex } from '@aviato-media/pilot-core'

// Vault entry → SDK call:
const opened = await openVault({ blob, credentialId, prfWrappingKey })
if (opened.ok) {
  const entry = opened.payload.servers[0]!
  const conn = await claimConnInfoKey({
    expectedServerPubKey: pubkeyFromHex(entry.serverPubKey),
    record,
    userEncPrivKey: pubkeyFromBase64Url(opened.payload.userEncPrivKey),
  })
}

// Tower-api resolve response → assertion:
const ctx = PairingCodeResolveResponseSchema.parse(await resolveResponse.json())
const env = approveServerLink({
  masterPrivKey,
  requestId: ctx.requestId,
  serverPubKey: pubkeyFromHex(ctx.serverPubKey!),
  userEncPubKey: pubkeyFromHex(opened.payload.userEncPubKey),
  userId,
  userPubKey: pubkeyFromHex(opened.payload.masterPubKey),
})
```

The `serverPubKey` "Unnamed server" / `payload_shape_invalid` failure modes from earlier passes are now structurally impossible — there's no way to call `approveServerLink` with a base64url-encoded pubkey because the type signature requires `Uint8Array`.

## SDK shape updates (since the first draft of this prompt)

The pilot-sdk picked up four additions based on feedback from an earlier Tower refactor attempt. If you're starting fresh, use these directly — they remove workarounds the previous pass had to invent:

1. **`VaultServerEntrySchema.connInfoKey` is now nullable** (`BASE64URL | null`). The pairing-response leg is asynchronous; between "server-link approved" and "Tower received sealed K from media server" there's a legitimate pending window. Write the vault entry with `connInfoKey: null` immediately on approval — Tower-web UI should render it as "Connecting…". When the background poll delivers K, update the entry in place with the real value. Do **not** defer the write; that's a UX regression.
2. **`buildClientPairBundle` filters null `connInfoKey` entries automatically.** Pass the user's `vault.servers` list directly (after the user-tick subset filter); pending entries are silently dropped from the sealed bundle. The client app gets only servers with usable K. The user can re-pair the app later to pull in the now-completed entries.
3. **Paired-clients schemas live in `@aviato-media/pilot-core`.** Use `PairedClientViewSchema`, `PairedClientListResponseSchema`, and `PairedClientRowSchema` for the `GET /api/identity/clients` route — do NOT redefine these locally in `tower-web` or `tower-api`. The schemas already model `appName`/`appIcon`/`appVerified` (resolved via app registry) and `serverCount` (how many of the user's servers this app has access to).
4. **`PairedClientStore` interface lives in `@aviato-media/pilot-tower-sdk`.** Methods: `upsert`, `get`, `listByUser`, `revoke`, `markSeen`. Implement against DynamoDB in `tower-api/src/lib/identity-paired-clients-db.ts`. The SDK ships `MemoryPairedClientStore` for tests and a `toPairedClientView(row, appMeta?)` helper that strips internal fields and computes `serverCount` — use it in your `GET /api/identity/clients` handler to format response rows.

Example wiring:

```ts
// tower-api: GET /api/identity/clients
import { toPairedClientView, type PairedClientStore } from '@aviato-media/pilot-tower-sdk'
import { PairedClientListResponseSchema } from '@aviato-media/pilot-core'

async function listClients (userId: string, appRegistry: AppRegistry, store: PairedClientStore) {
  const rows = await store.listByUser(userId)
  const clients = await Promise.all(rows.map(async (row) => {
    const meta = await appRegistry.get(row.appId)
    return toPairedClientView(row, meta)
  }))
  return PairedClientListResponseSchema.parse({ clients })
}
```

Tower-api still owns the actual DDB table creation and the `paired_clients` row writes on `POST /api/identity/code/:code/complete` for client-pair approvals. The SDK provides the wire contract, the interface to implement, and the helper to format responses — Tower owns persistence.

### Cert pre-issuance: a second endpoint exposes the full row shape

The `GET /api/identity/clients` endpoint returns `PairedClientViewSchema` shape — deliberately stripped of `clientPubKey` / `clientEncPubKey` / `scope` / `servers` because that's a UI list and the cert pubs aren't relevant to the display layer.

**For cert pre-issuance, Tower-web needs the full row** (the cert pubs feed into `buildClientPairCert` to mint the renewal). Pre-issue runs client-side because it requires `masterPrivKey` from the open vault — Tower-api can't pre-issue without M.priv. So Tower-api exposes a second session-auth'd endpoint that returns the full row data, scoped to the requesting user's own clients:

```ts
// tower-api: GET /api/identity/clients/details
import { PairedClientDetailListResponseSchema } from '@aviato-media/pilot-core'
import type { PairedClientStore } from '@aviato-media/pilot-tower-sdk'

async function listClientDetails (userId: string, store: PairedClientStore) {
  const rows = await store.listByUser(userId)
  return PairedClientDetailListResponseSchema.parse({ clients: rows })
}
```

And Tower-web's pre-issue loop:

```ts
// tower-web: cert pre-issuance flow
import { PairedClientDetailListResponseSchema, pubkeyFromHex } from '@aviato-media/pilot-core'
import { buildClientPairCert } from '@aviato-media/pilot-tower-sdk'

const resp = await api.get('/api/identity/clients/details')
const { clients } = PairedClientDetailListResponseSchema.parse(resp)
const withinWindowMs = 14 * 86400 * 1000

for (const c of clients) {
  if (c.revoked) continue
  if (Date.parse(c.certExpiresAt) - Date.now() > withinWindowMs) continue
  // The SDK takes Uint8Array. pubkeyFromHex throws if the wire value
  // is anything other than canonical 64-char lowercase hex.
  const renewed = buildClientPairCert({
    appId: c.appId,
    clientEncPubKey: pubkeyFromHex(c.clientEncPubKey),
    clientId: c.clientId,
    clientPubKey: pubkeyFromHex(c.clientPubKey),
    deviceName: c.deviceName,
    masterPrivKey,
    scope: c.scope,
    userEncPubKey,
    userId,
    userPubKey,
  })
  // POST renewed back to tower-api for persistence...
}
```

**Two endpoints, distinct concerns:**

| Endpoint | Wire schema | Returned shape | Caller |
|---|---|---|---|
| `GET /api/identity/clients` | `PairedClientListResponseSchema` | `PairedClientView[]` (no cert pubs) | UI device list, audit log, user-facing dashboard |
| `GET /api/identity/clients/details` | `PairedClientDetailListResponseSchema` | `PairedClientRow[]` (full row inc. cert pubs) | Cert pre-issuance, vault-side renewal flows |

Both endpoints are session-auth'd and scoped to the caller's own clients. The cert pubs aren't secrets relative to the user (they appear in every cert that user has signed) so exposing them to the session-authenticated owner is safe.

## API differences to be aware of

The pilot SDKs were ported byte-faithfully from the Tower-web reference implementations, so the function signatures should look extremely familiar. Notable shifts:

| Old (`tower-web/src/lib/...`) | New (`@aviato-media/pilot-tower-sdk` or `pilot-core`) |
|---|---|
| `from '@/lib/sealedbox'` | `from '@aviato-media/pilot-core'` |
| `from '@/lib/vault'` | `from '@aviato-media/pilot-tower-sdk'` |
| `from '@/lib/prf'` | `from '@aviato-media/pilot-tower-sdk'` |
| `from '@/lib/pairing-response'` | `from '@aviato-media/pilot-tower-sdk'`; function renamed from whatever Tower called it to `claimConnInfoKey({ record, userEncPrivKey, expectedServerPubKeyHex })` |
| Inline JCS+Ed25519 for assertion signing | `approveServerLink(...)` / `approveServerSignIn(...)` returning `{ signedAssertionBytes, assertionSignature }` |
| Inline cert + sealed bundle for client-pair | `buildClientPairCert(...)` + `buildClientPairBundle(...)` |
| `VaultPayload` type local to tower-web | `import type { VaultPayload } from '@aviato-media/pilot-core'` — pilot-core's schema is canonical; if Tower's local type had extra fields, surface this before changing |
| Inline `ed25519.verify(...)` on conn-info publish body | `verifyConnInfoRecordSig(record)` |

If a function in pilot-tower-sdk looks like it returns a slightly different shape than your inlined code did — read the SDK source carefully before adapting your call site. The shapes were chosen to match the canonical references, but small naming differences exist (e.g. `wrappedKey` vs `wrap`).

## What NOT to do

- Do not modify the pilot-sdk source (`~/projects/aviato/pilot-sdk`). It's frozen for this task. If you find a bug or missing API, stop and report it back — do not edit it from this side.
- Do not change protocol bytes (JCS field orders, AAD prefixes, HKDF info strings, schema field names). If the byte format needs to change, the change belongs in pilot-sdk first, then both repos in lockstep.
- Do not change Tower's external API contract (URL paths, HTTP method/status conventions, error envelope shapes) — those are owned by Tower, and breaking them breaks every paired media server. The schemas being imported from pilot-core do not change the wire shape; they are the same shape.
- Do not republish or change versions of the pilot-sdk packages. Use them as file: deps locally.
- Do not skip pre-commit hooks (`--no-verify`) or signing flags. If a hook fails, fix the underlying issue.
- Do not merge any worktree into the default branch without explicit user approval, even if everything passes.
- Do not amend or force-push commits — create new commits for each fix.
- Do not touch the Aviato media-server repo (`~/projects/aviato/aviato`) or the pilot-sdk repo in this task.
- Do not refactor unrelated systems (Stripe billing, app registry CRUD, license-key issuance, DDNS, email) — even if they share files with identity routes. Surgical edits only.
- Do not turn a Tower-web Server Component into a Client Component by accidentally importing pilot-tower-sdk (which uses browser crypto). The SDK is browser-first; only call its functions from Client Components or browser-runtime contexts. Verify the `'use client'` boundary stays correct.

## Done criteria

You're done when **all of the following** are true:

- [ ] `tower-web/src/lib/sealedbox.ts`, `vault.ts`, `prf.ts`, `pairing-response.ts` no longer exist.
- [ ] No file in this repo contains an inline `aviatoSealedBox*` implementation, JCS implementation, HKDF wrapping-key derivation, or duplicate of any pilot-core schema.
- [ ] `tower-web/src/lib/vault-context.tsx` exists and works, but every crypto call inside it goes through `@aviato-media/pilot-tower-sdk`.
- [ ] `tower-api/src/routes/identity-*.ts` import their request/response schemas from `@aviato-media/pilot-core/schemas` (with `.openapi('Name')` added at the route binding site).
- [ ] Conn-info publish-signature verification on `POST /api/identity/server-conninfo` uses `verifyConnInfoRecordSig` from `@aviato-media/pilot-core`.
- [ ] `bun run typecheck` passes across the whole repo.
- [ ] `bun run test` passes across the whole repo.
- [ ] `bun run lint` reports zero errors (warnings on intentional non-null assertions are acceptable; should be the same set as before this refactor + any unavoidable new ones).
- [ ] Manual smoke test passes for: register → add passkey → server-link a media server → approve client-pair → GET server-conninfo and decrypt.
- [ ] You stop and ask before doing anything destructive that wasn't pre-authorized here (publishing, force-pushing, merging into default branch, etc.).

## Reporting

When you finish, report:
1. **Files deleted** (count + the top-level directories that went away).
2. **Files modified** (count, grouped by package: tower-web vs tower-api).
3. **Test count** before vs after.
4. **Any API gap you hit** in the pilot-sdk packages — anything where you wished the SDK exposed something it doesn't. Don't paper over with vendored re-implementations; flag it for a follow-up pilot-sdk PR.
5. **Any byte-format divergence you discovered** between Tower's previous implementation and the SDK's port. The SDK's tests pass against the canonical references, but if Tower had been quietly relying on a subtly different behavior (e.g. a particular base64url padding handling, a different HKDF salt), surface it before continuing — that's a protocol-level issue that needs coordinated resolution.
6. **Manual smoke-test results** for register → passkey-add → server-link → client-pair → conn-info fetch.

If you hit a blocker that can't be resolved without modifying the pilot-sdk or the Aviato media-server codebase, stop and surface it. Don't work around it.
