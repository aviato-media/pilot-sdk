# Tower update prompt: apply the latest pilot-sdk changes

Copy-paste into a Claude Code session running in `~/projects/ato/ato.software`. This is a **follow-up** to the initial refactor — the previous prompt is done. This patch covers only the pilot-sdk API changes that landed after the first integration pass, plus the canonical wire-schema additions for the routes Tower owns.

---

## Mission

Two structural changes to apply:

1. **The pilot-sdk public API for pubkeys went from `string` (hex) to `Uint8Array` (raw bytes) everywhere.** Update every call site in this repo. TypeScript pinpoints them.
2. **Tower-api must import the canonical request/response Zod schemas from `@aviato-media/pilot-core` for the pairing routes**, not redefine them locally. This eliminates the silent-drift class of bug (the `displayName` and base64url-`serverPubKey` symptoms from the prior pass).

Do not change the wire protocol; only the in-memory SDK call shapes and where Tower-api gets its schemas from.

## Why this matters

Two real bugs from the prior pass drove these changes:

- **`payload_shape_invalid` / "Unnamed server":** Tower-web read `serverPubKey` from the resolve response as a string, passed it directly to `approveServerLink({ serverPubKeyHex })`. The string was base64url where the SDK expected hex; the assertion validated locally but the media server's verifier rejected it. The SDK now takes `Uint8Array` so the wrong encoding can't be expressed in the type system. The DB-side fix is using the canonical `PairingCodeResolveResponseSchema` (HEX_32 on `serverPubKey`) so Tower-api can't emit a malformed value either.
- **"Unnamed server" displayed even with `displayName` set in `PairingHostConfig`:** Tower-api's locally-defined request/response schemas omitted the field. The canonical schemas in `pilot-core` include it.

The structural fix is in pilot-sdk; this update just wires Tower up to it.

## Setup

```sh
cd ~/projects/aviato/pilot-sdk
bun install
bun run build       # refreshes dist/ for every package

cd ~/projects/ato/ato.software
bun install         # picks up new types via file: deps
bun run typecheck   # work-list — every error is a call site to update
```

## Change 1 — pilot-sdk API takes Uint8Array

**Every `xxxPubKeyHex: string` argument became `xxxPubKey: Uint8Array`.** Same field semantics, different encoding at the API boundary.

| Tower-side surface | Old | New |
|---|---|---|
| `approveServerLink`, `approveServerSignIn` | `serverPubKeyHex`, `userPubKeyHex`, `userEncPubKeyHex` | `serverPubKey`, `userPubKey`, `userEncPubKey` (all `Uint8Array`) |
| `buildClientPairCert` | `clientPubKeyHex`, `clientEncPubKeyHex`, `userPubKeyHex`, `userEncPubKeyHex` | `clientPubKey`, `clientEncPubKey`, `userPubKey`, `userEncPubKey` |
| `buildClientPairBundle` | `servers[].serverPubKey: hex`, `servers[].connInfoKey: base64url string \| null` | `servers[].serverPubKey: Uint8Array`, `servers[].connInfoKey: Uint8Array \| null` |
| `claimConnInfoKey` | `expectedServerPubKeyHex` | `expectedServerPubKey: Uint8Array` |
| `deriveConnInfoHash` | `(serverPubKeyHex: string): string` | `(serverPubKey: Uint8Array): string` |
| `verifyConnInfoRecordSig`, pilot-core helpers Tower-api uses | various `*PubKey: hex` arguments | take `Uint8Array` |

## Conversion patterns

When converting between bytes and hex strings already in your codebase:

```ts
import { pubkeyFromHex, pubkeyFromBase64Url, hexEncode } from '@aviato-media/pilot-core'

// (A) From a Zod-validated wire payload — DDB row, /resolve response, vault payload.
//     Wire form is HEX_32; convert with pubkeyFromHex to feed SDK calls.
const ctx = PairingCodeResolveResponseSchema.parse(await fetchResolve())
const assertionEnv = approveServerLink({
  masterPrivKey,           // bytes from vault
  requestId: ctx.requestId,
  serverPubKey: pubkeyFromHex(ctx.serverPubKey!),  // hex → bytes at the SDK boundary
  userEncPubKey,           // bytes from vault
  userId,
  userPubKey,              // bytes from vault
})

// (B) Vault payload pubkeys — VaultPayloadSchema validates hex; decode on open.
const opened = await openVault({ blob, credentialId, prfWrappingKey })
if (opened.ok) {
  const masterPrivKey = pubkeyFromBase64Url(opened.payload.masterPrivKey)
  const userPubKey   = pubkeyFromHex(opened.payload.masterPubKey)
  const userEncPubKey = pubkeyFromHex(opened.payload.userEncPubKey)
  // pass bytes to all SDK calls; cache in a ref while the vault is open
}

// (C) For wire/DB writes — the schema is hex; convert from bytes:
const ddbRow = { ..., public_key: hexEncode(serverPubKeyBytes) }
```

`pubkeyFromHex` throws if input isn't 64 lowercase hex; `pubkeyFromBase64Url` throws if decoded length isn't 32 bytes. Surface encoding bugs at the conversion site.

## Change 2 — canonical schemas for pairing routes

Tower-api MUST import these from `@aviato-media/pilot-core` and use them via `@hono/zod-openapi` for the corresponding routes. Do NOT redefine them locally; that's how `displayName` quietly disappeared last time.

```ts
import {
  PairingRegisterRequestSchema,   // POST /api/identity/pairing/register request body
  PairingCodeResolveResponseSchema, // GET /api/identity/code/:code/resolve response body
  ServerConnInfoPublishSchema,    // POST /api/identity/server-conninfo request body
  ServerConnInfoRecordSchema,     // GET /api/identity/server-conninfo/:hash response body
  PairingResponsePayloadSchema,   // POST /api/identity/pairing/:id/response request body
  PairingResponseRecordSchema,    // GET /api/identity/pairing-response/:requestId response body
  ClientPairBeginResponseSchema,  // POST /api/identity/clients/pair/begin response body
  ClientPairPollResponseSchema,   // GET /api/identity/clients/pair/:requestId response body
  PairedClientListResponseSchema, // GET /api/identity/clients response body
  // ... and all other schemas you import for routes
} from '@aviato-media/pilot-core'

// At the route binding site, add OpenAPI names locally:
const route = createRoute({
  request: { body: { content: { 'application/json': {
    schema: PairingRegisterRequestSchema.openapi('PairingRegisterRequest'),
  }}}},
  responses: { 200: { content: { 'application/json': {
    schema: PairingRegisterResponseSchema.openapi('PairingRegisterResponse'),
  }}, description: 'OK' }},
})
```

Audit `tower-api/src/routes/identity-*.ts` for any local `z.object({...})` definitions covering pairing requests/responses; replace with the canonical schema imports.

## Tower-web changes from the bytes-API switch

- Where Tower-web read `ctx.serverPubKey` (hex string from the validated resolve response) and passed to `approveServerLink({ serverPubKeyHex: ctx.serverPubKey })`, change to `approveServerLink({ serverPubKey: pubkeyFromHex(ctx.serverPubKey!), ... })`.
- Vault opens return `VaultPayload` (hex strings inside). Convert with `pubkeyFromHex(...)` / `pubkeyFromBase64Url(...)` when handing values to SDK calls.
- `buildClientPairBundle({ servers })` now takes `Uint8Array` for both `serverPubKey` and `connInfoKey` per entry. The vault stores `connInfoKey` as base64url and `serverPubKey` as hex per the schema; convert at the boundary:
  ```ts
  buildClientPairBundle({
    clientEncPubKey: pubkeyFromHex(appClientEncPubHex),
    servers: vault.payload.servers.map((s) => ({
      serverPubKey: pubkeyFromHex(s.serverPubKey),
      connInfoKey: s.connInfoKey === null ? null : pubkeyFromBase64Url(s.connInfoKey),
    })),
  })
  ```

## Mass-update procedure

1. `bun run typecheck` → write down the list. Every error is a call site.
2. For each: convert string → bytes via `pubkeyFromHex` / `pubkeyFromBase64Url`, or pass bytes directly if the source already had them.
3. For `tower-api/src/routes/identity-*.ts`: replace any local request/response schemas covering the pairing routes with imports from `@aviato-media/pilot-core`.
4. `bun run typecheck` until clean.
5. `bun run test` — adapt assertions that read encoded values from results.
6. `bun run lint`.
7. Manual smoke test of the full server-link flow: from the media server starting a pairing → user approves on `/pair` (verifying the server name renders correctly — that's the displayName fix) → assertion verifies on the media server → K delivered.

## Persisted data + wire format unchanged

- DDB pairing/conn-info/vault rows still hex.
- Wire JSON bodies still hex.
- Only Tower's TypeScript at SDK call sites changes shape.
- The displayName fix is a Tower-api schema fix, not a wire format change.

## What NOT to do

- Do not modify the pilot-sdk source. Stop + report if you find an SDK gap.
- Do not introduce new hex-string-typed pubkey arguments in any new Tower code. Type them `Uint8Array`.
- Do not redefine in Tower any schemas that pilot-core now exports. The whole point of importing them is single-source-of-truth.
- Do not change Tower-api's external URL paths, status codes, or error envelope shape.
- Do not skip pre-commit hooks (`--no-verify`).
- Do not merge worktree → default branch without explicit user approval.
- Do not touch the Aviato media-server repo or the pilot-sdk repo.
- Do not turn a Tower-web Server Component into a Client Component by accidentally importing pilot-tower-sdk (which uses browser crypto) at module scope. Verify the `'use client'` boundary stays correct.

## Done criteria

- [ ] `bun run typecheck` clean.
- [ ] `bun run test` clean.
- [ ] `bun run lint` reports zero errors.
- [ ] No file in this repo contains `xxxPubKeyHex` field-names from the pilot SDKs. Greppable:
  ```sh
  grep -rn 'serverPubKeyHex\|userPubKeyHex\|userEncPubKeyHex\|clientPubKeyHex\|clientEncPubKeyHex\|expectedServerPubKeyHex\|expectedUserPubKeyHex' packages/
  ```
- [ ] No file in this repo redefines a Zod schema that's already exported from `@aviato-media/pilot-core`:
  ```sh
  grep -rn 'PairingRegisterRequest\|PairingCodeResolveResponse\|ServerConnInfoPublish\|ServerConnInfoRecord\|PairingResponsePayload\|PairingResponseRecord\|PairedClientView\|PairedClientListResponse' packages/ | grep -v 'pilot-core' | grep 'z.object\|z.discriminatedUnion'
  ```
  → no hits.
- [ ] Manual smoke test passes end-to-end: register fresh Tower account → server-link a media server → verify `displayName` appears correctly on the `/pair` consent screen → cert auth completes against the media server → K delivered.

## Reporting

When done, report:
1. Files modified (count, by package).
2. Anywhere you weren't sure whether a value's source was hex or bytes — surface for audit.
3. Tower-api routes whose schemas you replaced with pilot-core imports (list).
4. Any pilot-sdk gap you hit.
5. Smoke-test result, especially that `displayName` renders.
