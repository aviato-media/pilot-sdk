# Aviato Pilot's License SDK

SDKs for **Aviato Pilot's License**, an identity system that lets one user link many media servers without those servers learning about each other and without Aviato learning about the media being shared.

This monorepo holds the SDKs every Pilot's License integration needs: one for clients, one for media servers, one for the Tower itself. It also ships optional React bindings and a shared cryptographic core that defines the wire contract.

## Packages

| Package | Audience | Purpose |
|---|---|---|
| [`@aviato-media/pilot-core`](packages/core) | Shared internal | Crypto primitives, Zod schemas, assertion and cert helpers. The shared wire contract |
| [`@aviato-media/pilot-client-sdk`](packages/client-sdk) | Client apps (TypeScript, Swift, Rust, etc.) | Pair with Tower, fetch and decrypt server connection info, authenticate to media servers via cert. Universal orchestration (subscribe, connection cache, parallel init, cert renewal, hydrate) lives here so clients on every platform reuse it |
| [`@aviato-media/pilot-client-react`](packages/client-react) | React apps (Aviato Web, external React clients) | Thin React bindings: `PilotProvider`, `usePilotConnections`, `usePilotConnection`, `usePilotIdentity`, `usePairing`. Backed by `useSyncExternalStore` over the SDK's subscribe surface |
| [`@aviato-media/pilot-server-sdk`](packages/server-sdk) | Media server hosts (Aviato server, external implementations of the Aviato protocol) | Drive pairing flows, verify assertions and certs, publish encrypted connection info to Tower |
| [`@aviato-media/pilot-tower-sdk`](packages/tower-sdk) | Tower web (and any alternative Tower implementation) | Vault crypto, passkey PRF unwrap, build and sign assertions with the user's master key |

## Why this exists

Aviato wants to make sharing your media with friends and family effortless, and we also believe Aviato should have no insight into what you share. Your videos, images, and text are yours.

These two goals usually conflict. A central service that handles login and synchronization typically also sees the data it syncs.

Pilot's License resolves that tension. Each user holds a single license in a vault hosted by the [Aviato Tower](https://tower.aviato.media), and that license proves "this is me" to every Aviato media server you link. Every signature it produces comes from a master key that lives encrypted in your vault and surfaces only briefly in memory on your device, never on a server controlled by [aviato.media](https://aviato.media). The Tower relays the sealed bundles your servers and clients need to reach each other, but it cannot read them. No media server learns about another, and the Tower learns nothing about what is inside the bundles it forwards.

## How it works

1. **Register with the Tower.** You create an Aviato Identity by signing up on the [Aviato Tower](https://tower.aviato.media) using a passkey. Your browser generates a master key, encrypts it with a key derived from your passkey via the WebAuthn [PRF extension](https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/), and stores the ciphertext in your vault. The plaintext master key never leaves your device.

2. **Pair a media server.** When you sign in to an Aviato media server, the server uses the [server SDK](packages/server-sdk) to begin a pairing handshake with your Tower. You authorize the pairing inside Tower by tapping your passkey, which unwraps your master key for just long enough to sign a delegation certificate and seal the server's connection info into your vault. The server now recognizes your Aviato identity. The Tower learns only that pairing happened, not what the server is or what it holds.

3. **Sign in from a client app.** Any client app, including Aviato Web, uses the [client SDK](packages/client-sdk) to ask Tower for access to your servers. You authorize the app, choose which paired servers it may reach, and Tower seals the relevant connection info for the app's ephemeral key. The app decrypts the bundle locally and receives a longer lived certificate it can present directly to those servers. After that the app talks to servers without going through Tower, until the certificate expires and a new one is issued.

The wire format that ties all three sides together (Ed25519 signatures, X25519 sealed boxes, JCS canonicalized payloads, AES GCM symmetric encryption) lives in [`@aviato-media/pilot-core`](packages/core) and is reused by every SDK in this repo.

## Encrypted KV sync

In addition to the identity protocol, the SDKs ship an encrypted key/value sync surface so client apps can mirror settings, non-Aviato server connections, and cross-app media progress through Tower without depending on any single Aviato media server being online. Tower stores ciphertext only.

- `KVStoreClient` in `@aviato-media/pilot-client-sdk` exposes `batchGet`, `batchPut`, `delete`, and `list`. Callers pass plaintext `Uint8Array` values; the SDK seals each blob under a per-user 32 byte AES GCM 256 key with AAD `aviato-kv-blob-v1 ‖ utf8(keyString)` so a ciphertext cannot be replayed under a different key.
- Wire envelope per blob is `nonce(12) ‖ aesGcmCiphertext`, base64url encoded. Tower also stores `sha256(wireBytes)` per row. Clients pass the same hash as `knownChecksum` on read to skip the blob payload, and as `expectedChecksum` on write to assert an optimistic concurrency token.
- `MemoryKvStore` in `@aviato-media/pilot-tower-sdk` is a persistence agnostic backend implementing the same `KvStore` abstraction the upcoming `tower-api` route layer will mount onto its DynamoDB rows. The helpers `partitionBatchGet`, `decodePutItem`, `toListEntry`, and `sha256OfCiphertext` keep the wire shape consistent between the SDK and the eventual server.
- All wire schemas live in `@aviato-media/pilot-core` under the `./kv` subpath (`KvBatchGetRequestSchema`, `KvBatchPutRequestSchema`, `KvListResponseSchema`, `KvErrorResponseSchema`, `KvQuotaSchema`).

## Development

```sh
bun install
bun run build
bun run test
bun run typecheck
bun run lint
```
