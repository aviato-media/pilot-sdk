# Aviato update prompt: apply the latest pilot-sdk changes

Copy-paste into a Claude Code session running in `~/projects/aviato/aviato`. This is a **follow-up** to the initial refactor — the previous prompt is done. This patch covers only the pilot-sdk API changes that landed after the first integration pass.

---

## Mission

The pilot-sdk public API for pubkeys went from `string` (hex) to `Uint8Array` (raw bytes) everywhere. Update every call site in this repo to pass bytes instead of hex strings. TypeScript will pinpoint every spot. Do not change the wire protocol or persisted schemas.

## Why this matters

The previous integration pass discovered an encoding-mismatch failure mode: a caller passing a base64url-encoded `serverPubKey` where the SDK expected hex, producing a `payload_shape_invalid` error far from the actual fault. The fix wasn't more runtime validation — it was structural: the SDK now takes raw bytes (`Uint8Array`) for pubkey inputs, hex-encodes internally for the JCS-signed wire payloads, and validates strict shapes via Zod on the wire boundary. Encoding mismatches are now impossible to express in the type system; passing a wrong string is a TypeScript error, not a runtime mystery.

## Setup

```sh
cd ~/projects/aviato/pilot-sdk
bun install
bun run build       # refreshes dist/ for every package

cd ~/projects/aviato/aviato
bun install         # picks up the new types via file: deps
bun run typecheck   # this is your work-list — every error points at a call site to update
```

## The API change in one sentence

**Every `xxxPubKeyHex: string` argument became `xxxPubKey: Uint8Array`.** Same field semantics, different encoding at the API boundary.

| Function | Old | New |
|---|---|---|
| `PairingService` constructor | `config.serverPubKeyHex: string` | `config.serverPubKey: Uint8Array` |
| `ConnInfoPublisher` constructor | `config.serverPubKeyHex` | `config.serverPubKey: Uint8Array` |
| `verifyServerLinkAssertion`, `verifyServerSignInAssertion`, `verifyAndPersist` | `expectedServerPubKeyHex`, `expectedUserPubKeyHex` | `expectedServerPubKey`, `expectedUserPubKey` (both `Uint8Array`) |
| `beginChallenge`, `completeChallenge` | `serverPubKeyHex` | `serverPubKey: Uint8Array` |
| `sealSessionConnInfoEnvelope` | `clientEncPubKeyHex` | `clientEncPubKey: Uint8Array` |
| `AviatoPilotClient.signInToServer` | `{ serverPubKeyHex }` | `{ serverPubKey: Uint8Array }` |
| `serverCertAuth` | `serverPubKeyHex` | `serverPubKey: Uint8Array` |
| `resolveServerConnInfo` | `serverPubKeyHex` | `serverPubKey: Uint8Array` |
| `deriveServerConnInfoHash` | `(serverPubKeyHex: string): string` | `(serverPubKey: Uint8Array): string` |
| `useSignInToServer().signIn` (pilot-client-react) | `(serverPubKey: string)` | `(serverPubKey: Uint8Array)` |
| `verifyClientCert` | `opts.expectedUserPubKeyHex` | `opts.expectedUserPubKey: Uint8Array` |
| `verifyPairingAssertion` | `expectedServerPubKeyHex`, `expectedUserPubKeyHex` | `expectedServerPubKey`, `expectedUserPubKey` |
| `verifyRevocation` | `opts.expectedUserPubKeyHex` | `opts.expectedUserPubKey: Uint8Array` |
| pilot-core: `sealServerConnInfo`, `buildPairingResponse`, `openPairingResponse`, `buildSessionAssertion`, `verifySessionAssertion` | various `*PubKeyHex` | various `*PubKey: Uint8Array` |
| **Removed** | `deriveClientIdFromPub` | (delete imports — was dead code) |

## Conversion patterns

When you need to convert between bytes and the existing hex-encoded strings already in your codebase:

```ts
import { pubkeyFromHex, pubkeyFromBase64Url, hexEncode } from '@aviato-media/pilot-core'

// (A) From a Zod-validated wire payload (cert, assertion, vault entry, db column):
//     the hex string is canonical (HEX_32 regex). Convert to bytes for SDK calls.
const serverPubKey = pubkeyFromHex(serverRow.public_key)
await verifier({ expectedServerPubKey: serverPubKey, ... })

// (B) Your server's own identity (read from disk/env at boot):
//     Decide once at boot. Persist as hex (existing schema); cache as bytes in memory.
const serverPubKey = pubkeyFromHex(env.SERVER_PUB_KEY_HEX)  // 32 bytes
const serverPrivKey = pubkeyFromHex(env.SERVER_PRIV_KEY_HEX) // 32 bytes
// Pass bytes everywhere downstream:
const pairing = new PairingService(tower, store, {
  serverId,
  serverPubKey,   // bytes
  serverPrivKey,  // bytes
  ...
})

// (C) Going back to hex for storage / wire / log output:
const userPubKeyHex = hexEncode(verifiedPayload.userPubKeyBytes)
await db.users.upsert({ where: { id }, data: { public_key: userPubKeyHex } })
```

`pubkeyFromHex` throws if the input isn't 64 lowercase hex chars; `pubkeyFromBase64Url` throws if the decoded length isn't 32 bytes. Both surface encoding bugs at the conversion site, not three function calls deeper.

## Mass-update procedure

1. `bun run typecheck` → write down the list of errors. Each one is a call site to update.
2. For each call site:
   - If the old code had `xxxPubKeyHex: someHexString`, rename the field to `xxxPubKey` and wrap the value: `xxxPubKey: pubkeyFromHex(someHexString)`.
   - If the source of the value is already bytes (a generated keypair, a `randomAesKey()` return), drop the `hexEncode(...)` wrapper and pass the bytes directly.
3. For `deriveServerConnInfoHash(hex)` → `deriveServerConnInfoHash(bytes)`. Same fix.
4. Delete any import of `deriveClientIdFromPub` — it was removed (dead helper).
5. `bun run typecheck` until clean.
6. `bun run test` — adapt assertions that read encoded pubkeys back from results. The wire payload types still contain hex strings, but caller-facing types are bytes.
7. `bun run lint` — only formatting changes if anything.

## Persisted data and wire format are unchanged

- Your Drizzle schemas keep `public_key` columns as hex strings (matching `HEX_32`).
- The pairing assertion JSON sent to Tower still has hex strings inside (the SDK encodes for you).
- Cert payloads, vault entries, conn-info records, paired-client rows — all still hex on the wire.
- **Only the in-memory TypeScript API at SDK call sites changes.**

## What NOT to do

- Do not modify the pilot-sdk source (`~/projects/aviato/pilot-sdk`). If you find a missing helper or an API gap, stop and report — do not work around it.
- Do not introduce new hex-string-typed pubkey arguments anywhere new in this codebase. If you need to pass a pubkey to a function you're writing, type it `Uint8Array`.
- Do not change wire-protocol bytes (JCS field order, AAD prefixes, HKDF info strings, schema field names).
- Do not delete any pilot-sdk consumer this update isn't explicitly about (Drizzle adapters, route handlers, Hono routing, etc.).
- Do not merge any worktree into the default branch without explicit user approval.

## Done criteria

- [ ] `bun run typecheck` clean.
- [ ] `bun run test` clean — count of passing tests should be the same as before this update (or more, if you added regression tests).
- [ ] `bun run lint` clean (errors only — warnings on intentional `!` non-null assertions are fine).
- [ ] No file in this repo contains `xxxPubKeyHex` field names from the pilot SDKs. Greppable check:
  ```sh
  grep -rn 'serverPubKeyHex\|userPubKeyHex\|userEncPubKeyHex\|clientPubKeyHex\|clientEncPubKeyHex\|expectedServerPubKeyHex\|expectedUserPubKeyHex' packages/
  ```
  Should return zero hits within identity code paths.
- [ ] Smoke test of server-link flow + web sign-in still works in the dev environment.

## Reporting

When done, report:
1. Files modified (count + grouped by package).
2. Anywhere you weren't sure whether the source value was hex or bytes — surface so we can audit.
3. Any pilot-sdk gap you hit (a function that should take bytes but still wants a string, or vice versa).
4. Smoke-test result.
