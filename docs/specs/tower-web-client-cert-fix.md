# Tower-web fix: client-pair cert payload shape

**Status:** open. **Repo:** ato.software (this one). **Scope:** `packages/tower-web/` only. **Companion to:** `tower-web-server-link-assertion-fix.md` (same class of bug, different payload).

## Symptom

The Aviato media server's web frontend (`aviato-web` appId) completes a client-pair through Tower, receives `signedCertBytes` + `certSignature`, and immediately hands the cert to the local Aviato server via `POST /api/auth/identity-session/begin`. The Aviato server rejects with HTTP 400 and one of `cert_payload_schema_invalid` / `cert_payload_not_canonical` / `cert_sig_invalid` — depending on which mismatch fires first.

## Root cause

`packages/tower-web/src/app/pair/page.tsx` `approveClientPair` (around line 419) builds and signs a cert payload whose shape does not match the Aviato server's `ClientDelegationCertPayloadSchema`.

### What Tower-web currently signs

```ts
const payload = {
  appId: input.resolved.appId,
  clientPubKey: input.resolved.clientPubKey,    // base64url, from Tower
  expiresAt,                                    // ISO 8601 string
  issuedAt,                                     // ISO 8601 string
  kind: 'client-cert' as const,
  requestId: input.resolved.requestId,
  serverIds: input.approvedServerIds,
  userId: input.userId,
}
```

### What the Aviato server expects

`packages/common/src/identity/v2/schemas.ts` in `~/projects/aviato/aviato/`:

```ts
export const ClientDelegationCertPayloadSchema = z.object({
  appId: z.string().min(1),
  clientId: z.uuid(),                      // UUID v4
  clientPubKey: HEX_32_BYTES,              // /^[0-9a-f]{64}$/
  deviceName: z.string().min(1),
  exp: z.number().int(),                   // unix seconds
  iat: z.number().int(),                   // unix seconds
  scope: z.array(z.string()),
  userId: z.string().min(1),
  userPubKey: HEX_32_BYTES,                // master pubkey, hex
  v: z.literal(1),
})
```

### Concrete deltas

| Field | Tower-web | Aviato schema | Notes |
|---|---|---|---|
| `userPubKey` | omitted | required | **Critical.** Aviato server verifies the cert signature against this field. Without it: no key to verify against. |
| `clientId` | omitted | required (UUID v4) | Aviato server's `identity_clients` table uses this as primary key; without it the `upsertClient`/`isClientRevoked` paths break too. |
| `deviceName` | omitted | required, non-empty | Shown in Settings → Devices to the user. |
| `scope` | omitted (sends `serverIds` instead) | required (`string[]`) | Use `['servers:*']` for now to match what the spec example shows. |
| `v` | omitted | required literal `1` | Version pin. |
| `iat` | omitted (sends `issuedAt` ISO instead) | required number (unix seconds) | |
| `exp` | omitted (sends `expiresAt` ISO instead) | required number (unix seconds) | |
| `clientPubKey` encoding | base64url | hex (64 chars) | Cross-repo encoding contract — same one called out for `serverPubKey` in the server-link assertion fix. |
| Extra fields sent: `kind`, `requestId`, `serverIds`, `expiresAt`, `issuedAt` | sent | NOT in schema | Strict parse will fail. |

Once the schema check fails, the user can never sign in via Aviato Identity on the web (every fresh pair produces a cert the server rejects).

## Fix

Two edits in `packages/tower-web/`:

### 1. Ensure `base64urlToHex` helper exists

Already needed by the server-link fix. If not yet present, add to wherever the base64url helpers live (search `base64urlEncode`):

```ts
export function base64urlToHex (s: string): string {
  return bytesToHex(base64urlDecode(s))
}
```

### 2. Rewrite the client-pair cert payload in `approveClientPair`

`packages/tower-web/src/app/pair/page.tsx` — replace lines ~428-439:

```ts
const nowSec = Math.floor(Date.now() / 1000)
const ONE_YEAR_SEC = 60 * 60 * 24 * 365
const payload = {
  appId: input.resolved.appId,
  clientId: crypto.randomUUID(),
  clientPubKey: base64urlToHex(input.resolved.clientPubKey),
  deviceName: input.deviceName ?? 'Aviato Web',
  exp: nowSec + ONE_YEAR_SEC,
  iat: nowSec,
  scope: ['servers:*'],
  userId: input.userId,
  userPubKey: base64urlToHex(input.masterKeyPub),
  v: 1 as const,
}
```

Notes:
- `clientId` is a new UUID generated client-side. The cert is the only place this id exists; Aviato servers store it in `identity_clients` on first session-auth. Persist it in the vault entry too (the existing `clients` array push in `approveClientPair` should record this clientId).
- `deviceName` is a string the user sees in their device list. The current `deviceName` parameter coming into `approveClientPair` (from the resolve response) is fine; default to `'Aviato Web'` only if absent.
- `iat`/`exp` are unix seconds (not ms), matching the spec.
- Drop `kind`, `requestId`, `serverIds`, `expiresAt`, `issuedAt` from the signed payload. They are not part of the Aviato server's verified contract.
- The existing vault-update code at lines ~452+ should now use `clientId: payload.clientId` (instead of `clientId: input.resolved.clientPubKey` which was a stand-in).

### Why this works

JCS canonicalization sorts keys alphabetically at serialization time, so the property order in the source is illustrative — what matters is that the JS object has exactly these keys with these types. The signing helper (`signWithMasterKey`) is unchanged; it canonicalizes and signs, and the server's `verifyCert` re-canonicalizes the same bytes and verifies against `payload.userPubKey`.

## Verifying the fix

After applying:

1. Restart Tower-web.
2. From a fresh Aviato browser session (clear IndexedDB store `aviato-identity` if you've cached a broken cert), hit the Aviato login page → click "Sign in with Aviato Identity".
3. Complete the pairing on Tower.
4. The Aviato server's `POST /api/auth/identity-session/begin` should return 200 with a `challenge`. Watch the network tab in the browser — if it returns 400 with `cert_payload_schema_invalid`, the schema is still mismatched.

If verification still fails with a different error after the schema fix:

- `cert_payload_not_canonical` → `canonicalize()` in Tower-web vs `jcs()` in `@aviato/crypto` are not byte-identical. The most likely cause is a stray field or a number/string ambiguity (e.g. `v: '1'` vs `v: 1`). Open the network response and compare the decoded `signedCertBytes` against what `jcs(payload)` produces on the server.
- `cert_sig_invalid` → `masterKeyPub` is being converted to hex from a different encoding than `masterKeyPriv` actually corresponds to. Walk the keypair-import code in `lib/master-key.ts` and make sure both halves come from the same encoded source.

## Out of scope

- Tower's relay code (`packages/tower-api/`) is correct — it stores and forwards `signedCertBytes` verbatim.
- Tower-web's `signWithMasterKey` helper is correct.
- The browser-side IndexedDB storage on the Aviato side persists `cert + clientPubKey + privKey` as-is; once the cert verifies, the cert-auth handshake (`/begin` + `/complete`) reads the same `clientPubKey` field out of the cert and uses it to verify the client signature, so getting the cert shape right unblocks the whole flow.
