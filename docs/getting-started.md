# Getting Started

This page is the entry point for client-app developers integrating Aviato Pilot's License.

## What you're integrating

Pilot's License is a privacy-preserving identity protocol: one user, one Tower vault, many independent media servers. Your app pairs the user's vault once, receives a 60-day delegation cert, and uses that cert to authenticate against the user's media servers directly. The Aviato Tower never sees the bytes that flow between your app and the user's servers.

If you have not already, skim [`overview.md`](./overview.md) for the role diagram and pairing flow.

## Install

```sh
npm install @aviato-media/pilot-client-sdk @aviato-media/pilot-core
# or
bun add @aviato-media/pilot-client-sdk @aviato-media/pilot-core
```

For React apps, also add:

```sh
npm install @aviato-media/pilot-client-react
```

## Register your app

Every client app declares a public `appId` slug (no client secret) at [`tower.aviato.media/developer/apps`](https://tower.aviato.media/developer/apps). Tower uses this to render the consent screen the user sees while pairing — name, icon, description, requested scopes, callback URLs.

Pick a slug that is stable and reverse-DNS-style, e.g. `com.example.myapp`. You will pass it as `appId` when constructing the SDK.

## Read the SDK reference

The full quickstart, storage-backend guidance, error-code table, trust model, and cert-renewal API live in:

- **[`packages/client-sdk/README.md`](../packages/client-sdk/README.md)** — `AviatoPilotClient`, storage backends, low-level helpers, React quickstart.

For React-specific surface, the hook list is exported from `@aviato-media/pilot-client-react` (`PilotProvider`, `useAviatoPilotClient`, `usePilotConnections`, `usePilotConnection`, `usePilotIdentity`, `usePairing`, `useSignInToServer`, `useSignOut`) — see `packages/client-react/src/hooks.ts`.

The 60-second version:

```ts
import {
  AviatoPilotClient,
  SubtleCryptoKeyStorageBackend,
  isSubtleCryptoStorageSupported,
  LocalStorageBackend,
} from '@aviato-media/pilot-client-sdk'

const storage = (await isSubtleCryptoStorageSupported())
  ? new SubtleCryptoKeyStorageBackend()
  : new LocalStorageBackend()

const client = new AviatoPilotClient({
  appId: 'com.example.myapp',
  deviceName: 'Desktop Browser',
  storage,
  towerBaseUrl: 'https://tower.aviato.media',
})

await client.hydrate()

if (!(await client.hasIdentity())) {
  const handle = await client.beginPair()
  // show handle.pairingUrl + handle.code to the user
  await handle.await()
}

await client.initializeAllConnections()
const connections = client.getConnections()
```

## Picking a storage backend

Browser apps in production should prefer `SubtleCryptoKeyStorageBackend` — it stores device private keys as non-extractable WebCrypto `CryptoKey` handles in IndexedDB. An attacker with XSS can *use* the keys within the page lifetime but cannot exfiltrate them. Fall back to `LocalStorageBackend` only when `isSubtleCryptoStorageSupported()` returns `false`.

Native apps should implement `IdentityStorage` with `generateClientKeys` / `loadClientKeys` / `clearClientKeys` proxying to the OS keychain (iOS / macOS Keychain, Android EncryptedSharedPreferences, libsecret on Linux, Electron `safeStorage`). When those methods are present, the SDK never touches raw private-key bytes.

The full backend interface lives in `packages/client-sdk/src/storage.ts`; the IndexedDB / non-extractable-`CryptoKey` implementation is in `packages/client-sdk/src/subtle-crypto-storage.ts`.

## What to read next

| If you want to… | Read |
|---|---|
| Wire up React hooks | "React" section in [`packages/client-sdk/README.md`](../packages/client-sdk/README.md) and the hook exports in `packages/client-react/src/hooks.ts` |
| Handle `ServerConnection.status` error codes in your UI | error-codes table in [`packages/client-sdk/README.md`](../packages/client-sdk/README.md) |
| Understand the trust model and cross-system contract | [`whitepaper.md`](./whitepaper.md) |
| See every signature in the protocol at a glance | §6 of [`whitepaper.md`](./whitepaper.md) |
| Implement a native storage backend | "Custom backends" in [`packages/client-sdk/README.md`](../packages/client-sdk/README.md) |
| Build a media server that speaks the protocol | [`whitepaper.md`](./whitepaper.md) §5 and the public surface of `@aviato-media/pilot-server-sdk` (`PairingService`, `ConnInfoPublisher`, `verifyServerLinkAssertion`, `verifyServerSignInAssertion`, `beginChallenge`, `completeChallenge`) |

## Reporting issues

This repo is open-source. File bugs against the `@aviato-media/pilot-client-sdk` package with a reproduction. Security-sensitive reports should go to `security@aviato.media` rather than the public tracker.
