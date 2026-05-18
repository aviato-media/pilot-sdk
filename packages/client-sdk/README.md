# @aviato-media/pilot-client-sdk

Universal client SDK for the Aviato Pilot License — a privacy-preserving multi-server identity protocol. This package lets a third-party app pair with a user's Aviato Tower, receive a delegation cert, and authenticate against the user's media servers using only the keys it holds locally. Aviato Tower never sees the bytes that flow between client and media server.

The SDK is framework-agnostic. React bindings live in `@aviato-media/pilot-client-react`.

---

## Install

```sh
npm install @aviato-media/pilot-client-sdk @aviato-media/pilot-core
# or
bun add @aviato-media/pilot-client-sdk @aviato-media/pilot-core
```

`@aviato-media/pilot-core` is a peer dependency — install it alongside.

---

## Quickstart

```ts
import {
  AviatoPilotClient,
  SubtleCryptoKeyStorageBackend,
  isSubtleCryptoStorageSupported,
  LocalStorageBackend,
} from '@aviato-media/pilot-client-sdk'

// 1. Pick a storage backend. Prefer the secure one when available.
const storage = (await isSubtleCryptoStorageSupported())
  ? new SubtleCryptoKeyStorageBackend()
  : new LocalStorageBackend()

const client = new AviatoPilotClient({
  appId: 'com.example.myapp',           // registered on https://tower.aviato.media/developer/apps
  deviceName: 'Desktop Browser',        // device name to help the user, will be kept secure in Vault
  storage,
  towerBaseUrl: 'https://tower.aviato.media',
})

// 2. Boot — load persisted identity if any.
await client.hydrate()

// 3. If no identity, start a pair flow. Show the user pairingUrl + code.
if (!(await client.hasIdentity())) {
  const handle = await client.beginPair()
  console.log('Show this to the user:', handle.pairingUrl, handle.code)
  await handle.await()                  // resolves when the user approves on Tower
}

// 4. Resolve the user's linked servers and sign in to each.
await client.initializeAllConnections()

// 5. Read state — refreshes on every status change via subscribe().
const conns = client.getConnections()
for (const c of conns) {
  // serverPubKey is a `PublicKey` — call `.toHex()` for display, or hand
  // it back to any SDK call as-is.
  console.log(`${c.serverPubKey} ${c.status.state}`)
}

// 6. Per-server sign-in. `serverPubKey` accepts any `PublicKeyLike`:
//    - a `PublicKey` instance (e.g. from another SDK call)
//    - raw 32-byte `Uint8Array`
//    - lowercase 64-char hex string (e.g. from config or env)
const conn = await client.signInToServer({
  serverPubKey: 'aa…',
})
if (conn.status.state === 'online') {
  console.log('Session token:', conn.status.sessionToken)
}

// Round-trip: hand back what you got, no encoding fiddling.
const sameConn = await client.signInToServer({ serverPubKey: conn.serverPubKey })
```

### Key classes (`PublicKey`, `PrivateKey`, `PublicPrivateKey`)

The SDK uses class wrappers from `@aviato-media/pilot-core` so input and output share one type:

- `PublicKey` — `.toHex()` / `.toString()` / `.toRaw()` / `.toBase64Url()` / `.toJSON()` / `.equals(other)`. JSON.stringify round-trips through `toHex()`. Construct from bytes, hex string, or another `PublicKey`.
- `PrivateKey` — `.toString()` is redacted (`'[PrivateKey]'`), `.toJSON()` throws (defends against accidental leaks). Explicit secret extraction via `.toRaw()` or `.toBase64Url()`.
- `PublicPrivateKey` — bundles `pubKey` + `privKey`. Generators: `PublicPrivateKey.generateEd25519()` / `generateX25519()`.

`PublicKeyLike = PublicKey | Uint8Array | string` is the boundary input type for any public key parameter.

---

## What lives where

| API | Use it for |
|---|---|
| `AviatoPilotClient` | Default. Orchestrates pair, hydrate, sign-in, sign-out, cert renewal, subscribe. |
| `LocalStorageBackend` | Default browser storage. Persists raw private keys in localStorage. **Vulnerable to XSS exfiltration** — see below. |
| `SubtleCryptoKeyStorageBackend` | **Recommended for production browser apps.** Persists device private keys as non-extractable WebCrypto `CryptoKey` handles in IndexedDB. |
| `MemoryStorageBackend` | Tests / ephemeral sessions. |
| `serverCertAuth` | Low-level per-server cert-auth handshake. Use when you want to drive sign-in manually. |
| `resolveServerConnInfo` | Low-level conn-info fetch + verify + decrypt. Returns `{protocol, host, port}` for a server. |
| `TowerClient` | Raw Tower HTTP client. Power users only. |

---

## Storage backends — pick the right one

### Default: `LocalStorageBackend`

Stores everything in browser `localStorage`, including base64url-encoded device private keys.

**Threat model:** any XSS in your app can read the keys via `localStorage.getItem(...)` and exfiltrate them off-origin. Use only for prototypes, internal tools, or apps where you accept that risk.

### Production: `SubtleCryptoKeyStorageBackend`

Generates device Ed25519 (signing) + X25519 (encryption) keypairs as **non-extractable** WebCrypto `CryptoKey` handles. Persists them in IndexedDB. Identity metadata, bundle, and session tokens still live in localStorage (those are not sensitive in the same way — they don't grant signing power).

**XSS containment:** an attacker with XSS can *use* the keys within the page lifetime (sign one request, open one envelope) but cannot copy the bytes anywhere persistent or off-origin. There is no `localStorage.getItem('client-priv')` to scrape.

**Browser support:** Chrome 137+, Firefox 130+, Safari 17+. Use `isSubtleCryptoStorageSupported()` to probe at startup and fall back to `LocalStorageBackend` if not available.

### Custom backends

Implement `IdentityStorage` to plug in native secure storage (OS keychain on iOS/macOS, EncryptedSharedPreferences on Android, libsecret on Linux, Electron `safeStorage`, etc.). The optional `generateClientKeys` / `loadClientKeys` / `clearClientKeys` methods, when present, activate the handle-based code path — the SDK then never touches raw private key bytes. The `KeyOps` type defines what those methods must return:

```ts
import type { KeyOps } from '@aviato-media/pilot-client-sdk'

class NativeKeychainBackend implements IdentityStorage {
  async generateClientKeys(): Promise<KeyOps> {
    // Generate keys inside your OS keychain, return KeyOps callbacks
    // that proxy sign + ECDH through the native bridge.
  }
  async loadClientKeys(): Promise<KeyOps | null> { /* ... */ }
  async clearClientKeys(): Promise<void> { /* ... */ }
  // ... rest of IdentityStorage methods
}
```

---

## React

```tsx
import { PilotProvider, usePairing, usePilotConnections } from '@aviato-media/pilot-client-react'

function App() {
  return (
    <PilotProvider client={client}>
      <SignInFlow />
    </PilotProvider>
  )
}

function SignInFlow() {
  const { phase, begin, cancel } = usePairing()
  const connections = usePilotConnections()
  // ...
}
```

See `@aviato-media/pilot-client-react` for the full hook surface.

---

## Error codes

`ServerConnection.status` is a tagged union. When `state === 'error'`, the `code` field tells you why:

| `code` | Meaning | Typical UI response |
|---|---|---|
| `http` | Server returned a non-OK HTTP status (other than 401) | Retry / show server-error message |
| `shape` | Server response shape was invalid | Bug or version mismatch — log it |
| `sig` | Server signature failed verification | Show "server identity check failed" — likely tampered cache |
| `no_server_pubkey` | The serverPubKey we paired with no longer exists | Re-pair |
| `tower_sig_invalid` | Tower returned a conn-info record whose sig didn't verify | Likely Tower-side tamper / cache poisoning |
| `shape_invalid` | Stored data corruption | Sign out + re-pair |
| `no_identity` | No identity persisted yet | Show pair flow |
| `unknown` | Unhandled error | Log + show retry |

`state === 'unauthorized'` (with optional `httpStatus`) means the server returned 401 — the cert is no longer trusted by the server. Prompt the user to re-pair.

`state === 'stale_k'` means the per-server K is stale; the SDK will refresh K from the next in-session envelope. Show "reconnecting" if it persists.

---

## Trust model

The protocol is designed to be Tower-honest at code resolution only. Concretely:

1. **At first pair**, the user's browser learns the media server's pubkey via Tower (`GET /api/identity/code/:code/resolve`). The SDK trusts Tower to honestly map the user-entered code to the right serverPubKey. Once the pair completes, the user holds the serverPubKey directly and all subsequent verifications are independent of Tower.
2. **The cert** is signed by the user's master key (M) inside their Tower-side vault. The SDK verifies the cert at first pair and again at every renewal. The first-pair check has no pre-existing `expectedUserPubKey` (we are learning it now); the trust root is enforced by the **media server** verifying session assertions against *its* own stored userPubKey — a mismatched userPubKey will fail at sign-in.
3. **The cert MUST be minted for this app's `appId`**. The SDK checks `cert.appId === opts.appId` at `finalizePair`. A mismatch (mistaken Tower or malicious tampering) is rejected loud.
4. **`signInToServer` uses the serverPubKey the caller passes in**, not whatever Tower happens to return. The pairing-response signature on K and the conn-info publish signature are both verified against the caller's expected serverPubKey.

If you want stronger first-pair trust (no Tower-mediated step), generate an invite token signed by the server's private key out-of-band (QR code, signed URL) and verify it before passing the bytes to `signInToServer`. The SDK does not impose a particular out-of-band channel.

---

## Cert renewal

```ts
const result = await client.renewCertIfNeeded(30)  // renew if expiring within 30 days
// result: 'renewed' | 'not-needed' | 'unavailable' | 'failed'
```

Renewal calls `verifyClientCert(..., { expectedUserPubKey })` to pin the trust root against the userPubKey learned at first pair. Tower cannot swap to a different user via renewal.

---

## See also

- Aviato Pilot License protocol spec — `docs/specs/` in this repo.
- `@aviato-media/pilot-core` — the cross-system protocol contract (schemas, crypto, JCS, sealedbox).
- `@aviato-media/pilot-client-react` — React hooks built on this SDK.
- Security review — `docs/specs/security-review.md`.
