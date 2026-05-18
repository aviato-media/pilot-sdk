# Tower-web fix: server-link assertion payload shape

**Status:** open. **Repo:** ato.software (this one). **Scope:** `packages/tower-web/` only.

## Symptom

An Aviato media server completes a server-link pairing through Tower, polls Tower's `/api/identity/pairing/{requestId}`, gets back `state: 'completed'` with `signedAssertionBytes` + `assertionSignature`, parses + verifies the envelope, and rejects with HTTP 400 and `error: 'assertion_payload_schema_invalid'`.

## Root cause

Tower-web's `approveServerLink` in `packages/tower-web/src/app/pair/page.tsx` signs an assertion payload whose **shape does not match the Aviato server's `ServerLinkAssertionPayloadSchema`**. The signing helper (`signWithMasterKey`) is correct — the bug is purely the JS object being signed.

### What Tower-web currently signs

`packages/tower-web/src/app/pair/page.tsx` around line 371:

```ts
const payload = {
  expiresAt: input.resolved.expiresAt,
  issuedAt: new Date().toISOString(),
  kind: 'server-link' as const,
  requestId: input.resolved.requestId,
  scope: input.resolved.scope,
  serverPubKey: input.resolved.serverPubKey,  // base64url, as returned by Tower
  userId: input.userId,
}
```

### What the Aviato server expects

`packages/common/src/identity/v2/schemas.ts` in the Aviato repo (`~/projects/aviato/aviato/`):

```ts
export const ServerLinkAssertionPayloadSchema = z.object({
  kind: z.literal('server-link'),
  requestId: z.string().min(1),
  serverPubKey: HEX_32_BYTES,    // /^[0-9a-f]{64}$/
  ts: z.number().int(),
  userId: z.string().min(1),
  userPubKey: HEX_32_BYTES,
  v: z.literal(1),
})
```

### Concrete deltas

| Field | Tower-web | Aviato schema | Notes |
|---|---|---|---|
| `userPubKey` | omitted | required | **Critical.** The Aviato server verifies the signature against this field, so without it there's no key to verify against. |
| `ts` | omitted (uses `issuedAt` instead) | required (number, unix ms) | Used for ±10 min skew check. |
| `v` | omitted | required literal `1` | Version pin. |
| `serverPubKey` encoding | base64url (from Tower's resolve response) | hex (64 chars) | The cross-repo encoding contract called out in the Aviato v2 spec §3.6. |
| `expiresAt`, `issuedAt`, `scope` | sent | not in schema | Not part of the signed contract. Either drop them or get them added to the schema first. |

The schema rejects on first `safeParse` because `userPubKey`, `ts`, and `v` are missing AND `serverPubKey` fails the hex regex. That's the `assertion_payload_schema_invalid` error.

## Fix

Two edits in `packages/tower-web/`:

### 1. Add a `base64urlToHex` helper

Wherever Tower-web's base64url helpers live (search `base64urlEncode` / `base64urlDecode` to find the file — most likely `packages/tower-web/src/lib/encoding.ts` or similar). Add:

```ts
export function base64urlToHex (s: string): string {
  const bytes = base64urlDecode(s)
  let hex = ''
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0')
  }
  return hex
}
```

(If a `bytesToHex` helper already exists, compose `bytesToHex(base64urlDecode(s))` instead.)

### 2. Rewrite the assertion payload in `approveServerLink`

`packages/tower-web/src/app/pair/page.tsx` — replace the payload construction (currently lines 371–379) with:

```ts
const payload = {
  kind: 'server-link' as const,
  requestId: input.resolved.requestId,
  serverPubKey: base64urlToHex(input.resolved.serverPubKey),
  ts: Date.now(),
  userId: input.userId,
  userPubKey: base64urlToHex(input.masterKeyPub),
  v: 1 as const,
}
```

The function already has `input.masterKeyPub` (base64url) in scope — it's passed in by the caller. The signing helper at the bottom of the function (`signWithMasterKey({ payload, masterKeyPriv, masterKeyPub })`) is unchanged.

### Why this works

- JCS canonicalization sorts keys alphabetically at serialization time, so the property order in the source doesn't matter. Listed alphabetical above for readability.
- `masterKeyPub` is already in scope as base64url; `serverPubKey` arrives base64url from Tower's `/code/:code/resolve` response. Both are 32-byte Ed25519 pubkeys, so converting to 64-char hex is lossless.
- The Aviato server's verifier (`verifyServerLinkAssertionEnvelope` in `~/projects/aviato/aviato/packages/server/src/identity/v2/assertions.ts`) calls `jcs(payload)` and compares to the signed bytes — as long as Tower-web's `canonicalize()` and the server's `jcs()` produce identical bytes for the same JS object (both follow RFC 8785), verification will succeed.

## Out of scope

- Tower's relay code (`packages/tower-api/`) is correct — it stores and forwards the bytes verbatim.
- Tower-web's `signWithMasterKey` helper is correct.
- The `expiresAt`/`issuedAt`/`scope` fields can be added back into the signed contract later if needed, but that requires extending the Aviato schema first AND re-signing. Skip for now.

## Verifying the fix

Once applied, retry a server-link pairing from the Aviato server UI (`http://localhost:3000` → invite link → "Sign in with Aviato Identity", or Settings → Profile → "Link Aviato Identity"). The Aviato server's `/api/auth/identity-link/{requestId}/poll` should return `state: 'completed'` with a `sessionToken` instead of 400.

If verification still fails with a different error code:
- `assertion_payload_not_canonical` → `canonicalize()` in Tower-web vs `jcs()` in `@aviato/crypto` are not producing byte-identical output. Add fixtures from `~/projects/aviato/aviato/packages/crypto/__tests__/jcs.test.ts` to Tower-web's canonicalizer tests to find the divergence.
- `assertion_sig_invalid` → the masterKeyPub bytes don't actually correspond to the masterKeyPriv that signed. Check that `importPrivateKey(masterKeyPriv, masterKeyPub)` in `tower-web/src/lib/master-key.ts` is using the same hex/base64url conversion.
- `assertion_wrong_server` → the conversion from `resolved.serverPubKey` to hex is producing a different value than the Aviato server's own `getServerPublicKeyHex()`. Verify Tower's `/code/:code/resolve` is returning the pubkey it received during `/api/identity/server-registration` verbatim.
