# Aviato Identity Protocol

## A Distributed Identity and Server Discovery System for Self-Hosted Media

---

## Abstract

Aviato is a self-hosted media server. Each server instance is independently operated, managing its own library of movies, music, photos, and other media. The Aviato Identity Protocol solves three problems that arise when users interact with multiple servers: identity fragmentation (separate accounts per server), manual configuration (entering server addresses on every device), and tedious onboarding (admins creating credentials for every user).

The protocol introduces a cryptographic identity system where a user's identity is an Ed25519 keypair. A network of lightweight relays — built into every Aviato server — syncs encrypted identity data between devices. Users join servers through invite links and a challenge/response handshake. An optional central service provides commercial licensing and convenience features (passkey-based device linking, key escrow) but cannot see which users belong to which servers, what content exists on any server, or how to reach them.

The result: a user creates one identity, accepts invite links to join servers, and every device they own automatically discovers all their servers — with no central authority controlling access and no sensitive data exposed to intermediaries.

---

## 1. Problem

Self-hosted media servers create identity silos. Each server manages its own user accounts with independent credentials. This produces friction at three levels:

**For server administrators.** Inviting a friend to access your media library means creating a username and password for them, communicating it securely, and taking on the responsibility of storing their credentials safely. Every server repeats this process independently.

**For users.** Each server requires a separate login. Setting up a new phone means manually entering the address and credentials for every server. There is no way to discover servers or synchronize access information across devices.

**For the ecosystem.** There is no interoperability between servers. A user's relationship with Server A is invisible to Server B. Adding a new device requires re-entering everything from scratch.

---

## 2. Design Principles

The protocol is built on five principles:

**Cryptographic identity.** A user's identity is their Ed25519 public key — not a username, email, or any string registered in a central directory. The private key proves ownership. No authority issues or revokes identities.

**Server sovereignty.** Each server is the sole authority over its own access control list. The server decides who can connect, what they can access, and when to revoke access. No external system can override these decisions.

**Relay minimalism.** Relays store and forward signed, encrypted events. They verify signatures but cannot read content. They require no authentication. They are stateless intermediaries — if all relays disappear, servers continue to function.

**Privacy by architecture.** The central service (used for licensing and optional convenience features) is structurally unable to learn which users belong to which servers, how to reach any server, or what content exists. This is not a policy choice — the architecture makes it impossible.

**User agency.** Users choose their own tradeoffs between convenience and control. Key escrow is optional. Passkey device linking is optional. The seed phrase recovery path always works, with no third-party dependency.

---

## 3. Identity

### 3.1 Keypair

A user's identity is an Ed25519 keypair. The public key (32 bytes) serves as the universal identifier — it is stored in server access control lists, signs relay events, and is visible to other participants. There is no username, email, or display name at the protocol level.

The keypair is generated deterministically from a 256-bit seed via HKDF-SHA256. This seed is encoded as a 24-word BIP-39 mnemonic (the "seed phrase"), allowing the user to regenerate their identity from the mnemonic alone.

### 3.2 Seed Phrase

The seed phrase is a 24-word mnemonic following the BIP-39 standard. It encodes 256 bits of entropy plus an 8-bit SHA-256 checksum. The checksum detects transcription errors — a mistyped word will fail validation.

The seed phrase is shown once at identity creation. The user is responsible for storing it securely. It serves two purposes:

1. **Recovery.** If all devices are lost, the seed phrase regenerates the keypair.
2. **Key escrow encryption.** If the user opts into key escrow, the seed phrase derives the encryption key for the escrowed private key bundle.

### 3.3 Key Storage

On each device, the private key is encrypted at rest using a device-local secret (OS keychain on macOS/iOS, Keystore on Android, IndexedDB with encryption in web browsers). The private key never leaves the device unencrypted.

### 3.4 Device Linking

Getting the private key onto a new device is the core UX challenge. Three paths are provided:

**Passkey (smoothest).** The user authenticates to the central service via WebAuthn. The central service returns an encrypted key bundle (stored during a prior escrow opt-in). The device decrypts it with a key derived from the seed phrase. This requires the central service to be available and the user to have opted into escrow.

**QR code (local transfer).** An existing device displays a QR code containing the private key encrypted with a short-lived random key. The new device scans it. No network is involved — the transfer is proximity-based.

**Seed phrase (universal fallback).** The user enters their 24-word mnemonic. The keypair is regenerated deterministically. This works without any other device, without the central service, and without network access. The user then needs one relay address (from an invite link or manual entry) to bootstrap sync.

### 3.5 Key Lifecycle

The keypair is permanent. There is no key rotation — the public key IS the identity. If the private key is compromised, the user creates a new identity and re-accepts invites on all servers. This tradeoff keeps the protocol simple and avoids key rotation ceremonies, which would require coordinating with every server the user has access to.

---

## 4. Relay Network

### 4.1 Architecture

The relay network is a collection of independent WebSocket servers that store and forward signed events. Every Aviato server instance runs a relay as part of its process. There is no central relay infrastructure — the network is self-sustaining, growing with each server that joins the ecosystem.

The protocol is inspired by Nostr's simplicity but is a fully custom design optimized for Aviato's specific needs.

### 4.2 Events

The fundamental data unit is a signed event:

```
{
  id:         SHA-256(pubkey + kind + created_at + content)
  pubkey:     author's Ed25519 public key (hex)
  kind:       event type (text enum)
  created_at: unix timestamp
  content:    encrypted or plaintext payload
  sig:        Ed25519 signature over id (hex)
}
```

The `id` is a deterministic hash of the event's content fields. The `sig` is an Ed25519 signature over the `id`, proving the event was authored by the holder of the corresponding private key. Relays verify signatures before storing. Clients verify on read. No trust in relays is required.

### 4.3 Event Kinds

| Kind | Author | Encryption | Purpose |
|---|---|---|---|
| `user:profile` | User | Symmetric key derived from user's private key | Display name, avatar. Encrypted to self — only the user's devices can read it. |
| `user:keychain` | User | Symmetric key derived from user's private key | List of server memberships: server IDs, access keys, relay addresses. The core device sync payload. |
| `server:record` | Server | Server access key (shared symmetric key) | Server connection info (address, port, name). Encrypted so only invited users can read it. One record per server. |
| `server:key_update` | Server | Recipient's Ed25519 public key (asymmetric) | New server access key after rotation. One event per remaining user. |

### 4.4 Replaceable Semantics

For a given `pubkey + kind` pair, the relay stores only the most recent event (highest `created_at`). This means each user has at most one profile event and one keychain event on each relay. There is no history accumulation and no conflict resolution — the latest event wins.

### 4.5 Operations

The relay protocol uses WebSocket with four message types:

| Message | Direction | Description |
|---|---|---|
| `PUBLISH` | Client to Relay | Submit a signed event. Relay verifies the signature, stores the event (replacing any older event for the same pubkey+kind), and forwards it to matching subscribers. |
| `SUBSCRIBE` | Client to Relay | Register a filter. The relay immediately sends all matching stored events, followed by an `EOSE` (end of stored events) marker, then pushes new matches as they arrive. |
| `EVENT` | Relay to Client | Deliver a matching event to a subscriber. |
| `UNSUBSCRIBE` | Client to Relay | Cancel a subscription. |

### 4.6 Filters

Subscriptions use filters with four optional fields, combined with AND logic:

- `authors` — only events from these public keys
- `kinds` — only events of these kinds
- `since` — only events newer than this timestamp
- `limit` — maximum initial batch size

A user subscribes to their own pubkey to receive their profile and keychain. They subscribe to server pubkeys to receive server records.

### 4.7 Relay Discovery

A user's first relay address comes from their first invite link — the inviting server runs a relay, and the invite response includes the relay WebSocket URL. As the user joins more servers, each server's relay is added to the known relay list. The app publishes to all known relays for redundancy. A new device only needs to reach one relay to bootstrap the full keychain.

### 4.8 No Authentication

Relays do not require authentication to read or write. Events are self-authenticating via signatures. Any client can publish events (signed by their key) and subscribe to any events. This is safe because all sensitive content is encrypted — the relay serves ciphertext to everyone, but only authorized parties can decrypt.

---

## 5. Server Access Control

### 5.1 Public Key ACL

Each server maintains a local access control list (ACL) mapping Ed25519 public keys to roles (admin, user, guest) and optional library-level permissions. The ACL is the sole authority on who can access the server. No external system can modify it.

When a user connects to a server, they prove they hold the private key corresponding to a public key in the ACL by signing a challenge. If the signature verifies and the public key is in the ACL, the user is authenticated.

### 5.2 Server Access Key

Each server generates a 32-byte random symmetric key called the "server access key." This key is used to encrypt the server's `server:record` event on the relay (containing the server's address, port, and name). Users receive the access key during the invite process and store it in their keychain.

The access key exists so that the server's connection information is not publicly readable on the relay. An observer who sees the encrypted `server:record` event cannot determine the server's address. Only users who have been invited (and thus hold the access key) can decrypt it.

### 5.3 Server Identity

Each server has its own Ed25519 keypair, used to sign relay events (`server:record` and `server:key_update`). The server's public key serves as the "server ID" — the identifier that users store in their keychain to find the server's record on relays.

This keypair is separate from the license identifier used for commercial license validation, maintaining the privacy boundary between the licensing system and the relay network.

---

## 6. Invite Flow

Invites are the only mechanism for gaining access to a server. There is no public server directory, no search, and no user lookup. A user learns about a server only through a direct invite from someone who already has access.

### 6.1 Creating an Invite

A server administrator creates an invite through the admin panel. The invite is a cryptographically random token with optional constraints:

- **Expiry** — how long the invite remains valid
- **Max uses** — how many users can accept it (single-use or multi-use)
- **Role** — what permissions the invited user receives
- **Library access** — which specific media libraries the user can see

The server produces an invite link: `https://<server-address>/invite/<token>`.

### 6.2 Accepting an Invite

The invite acceptance is a direct interaction between the user's app and the server. The relay is not involved.

1. The user opens the invite link in their Aviato app.
2. The app connects to the server and requests a cryptographic challenge (a 32-byte random nonce).
3. The user's app signs the challenge with their Ed25519 private key and sends back the signature along with their public key.
4. The server verifies:
   - The invite token is valid (not expired, not exhausted).
   - The Ed25519 signature is valid for the claimed public key.
5. The server adds the public key to its ACL with the configured permissions.
6. The server responds with:
   - **Server access key** — the symmetric key for decrypting the server's relay record
   - **Server ID** — the server's public key on the relay
   - **Relay address** — the WebSocket URL of the server's built-in relay

The user's app stores this information in its keychain and publishes the updated keychain to all known relays (encrypted to self). Other devices pick up the change automatically.

### 6.3 Revoking Access

An administrator removes a user by deleting their public key from the ACL. The user can no longer authenticate.

Optionally, the admin can rotate the server access key. This generates a new key, re-encrypts the server's relay record, and publishes a `server:key_update` event for each remaining user (encrypted to their individual public key). Each user's app decrypts the update and refreshes their keychain with the new access key.

Key rotation is optional because the ACL is the primary access control — even with the old access key, a revoked user cannot authenticate to the server. The old access key only lets them decrypt the server's relay record (revealing the server address), but the server will refuse their connections.

---

## 7. Device Sync

### 7.1 What Syncs

The relay network carries exactly three types of data:

| Data | Who Writes | Who Reads | Encryption |
|---|---|---|---|
| User profile | The user | Only the user | Symmetric (derived from private key) |
| User keychain | The user | Only the user | Symmetric (derived from private key) |
| Server record | The server | Invited users | Symmetric (server access key) |

Everything else — library content, playback history, ratings, preferences — stays local to each server.

### 7.2 Sync Mechanics

The user's app maintains WebSocket connections to all known relays (one per server). On each connection, it subscribes to:

1. Its own events (`user:profile`, `user:keychain`)
2. Server records for all servers in its keychain (`server:record`)
3. Key update events (`server:key_update`)

When a new event arrives, the app decrypts it and updates local state. When the user makes a change (updates profile, joins a new server), the app publishes the updated event to all connected relays.

Conflict resolution is unnecessary. Each event kind is written by exactly one author — the user writes their own profile and keychain, the server writes its own record. The relay's replaceable semantics (latest timestamp wins) handle concurrent updates from multiple devices belonging to the same user.

### 7.3 New Device Bootstrap

A new device goes from blank to fully synced in these steps:

1. Obtain the private key (via passkey, QR code, or seed phrase).
2. Obtain one relay address (from the key escrow response, the QR payload, or a manual invite link).
3. Connect to the relay and fetch the `user:keychain` event.
4. Decrypt the keychain — now the device knows all servers, their access keys, and their relay addresses.
5. Connect to each server's relay and fetch `server:record` events.
6. Decrypt each record — now the device knows every server's address, port, and name.

The device is fully synced. Any single relay being reachable is sufficient.

### 7.4 Redundancy

The user's data is published to every known relay. If Server A goes offline, the user's data remains available on Server B and C's relays. The only scenario where sync breaks entirely is if all of the user's servers are simultaneously offline.

### 7.5 Offline Behavior

The app caches all synced data locally. It works offline for browsing known servers (addresses are cached). Changes made offline are queued and published when a relay becomes available.

---

## 8. Cryptography

### 8.1 Algorithms

| Purpose | Algorithm |
|---|---|
| Identity | Ed25519 |
| Symmetric encryption | XSalsa20-Poly1305 (AEAD, 24-byte nonce) |
| Key derivation | HKDF-SHA256 |
| Seed phrase | BIP-39 (24 words, 256-bit entropy) |
| Asymmetric encryption | X25519 key agreement + XSalsa20-Poly1305 |
| Event ID | SHA-256 |

All primitives are standard, widely audited, and available in established libraries (tweetnacl, libsodium, @noble/hashes). No custom cryptographic constructions are used.

### 8.2 Encryption Layers

**User data (profile, keychain)** is encrypted with a symmetric key derived from the user's Ed25519 private key via HKDF-SHA256, using a context string that differentiates between data types (`user:profile` vs. `user:keychain`). Only the user's own devices, which hold the private key, can decrypt.

**Server records** are encrypted with the server access key — a random 32-byte symmetric key generated by the server and distributed to authorized users during invite acceptance. All invited users share the same key.

**Key update events** use asymmetric encryption. The server converts each recipient's Ed25519 public key to Curve25519 (X25519), performs key agreement with an ephemeral keypair, and encrypts the new access key. Only the intended recipient can decrypt.

**Escrowed key bundles** are encrypted with a key derived from the user's seed phrase via HKDF-SHA256. The central service stores the ciphertext but cannot decrypt it.

### 8.3 Signature Chain

Every relay event carries an Ed25519 signature over its deterministic content hash. This creates a verifiable chain of authenticity:

- Relays reject unsigned or incorrectly signed events at the storage layer.
- Clients verify signatures on read, protecting against malicious relays.
- Servers verify signatures during invite acceptance, confirming the user holds the claimed private key.

---

## 9. Central Service

### 9.1 Role

The central service exists because Aviato has a commercial license model. Since a central touchpoint is already needed for licensing, it optionally provides identity convenience features. Its three responsibilities:

1. **License management** — Activate and periodically validate server licenses.
2. **Passkey authentication** — WebAuthn registration and authentication for device linking.
3. **Key escrow** — Store and serve encrypted private key bundles.

### 9.2 Privacy Boundaries

The central service is structurally unable to:

- See which users have access to which servers
- Know the network address of any server
- Read user profiles, display names, or any relay content
- Deauthorize users or block access to servers
- Decrypt escrowed key bundles

If the central service is unavailable, all existing server connections and relay sync continue to work. Only new license activations and passkey-based device linking are affected.

### 9.3 License Isolation

The server identifier used for licensing is intentionally separate from the server's relay identity. The central service knows "license key X is activated on server identifier Y" but does not know the server's relay public key, its address, or its name.

---

## 10. Trust Boundaries

| Entity | Knows | Cannot Know | Can Do | Cannot Do |
|---|---|---|---|---|
| **Central service** | License status. Passkey credentials. Encrypted key blobs. | Server addresses. User-server relationships. User profiles. Relay content. | Validate licenses. Authenticate passkeys. Store encrypted blobs. | Deauthorize users. Read user data. Correlate users to servers. |
| **Relay** | Encrypted event blobs. Public keys. Event kinds and timestamps. | Decrypted content. User profiles or keychains in plaintext. | Store events. Verify signatures. Reject invalid events. | Read encrypted content. Modify events. Selectively censor (users replicate across relays). |
| **Server** | Its own ACL. Its own content. Connected users' public keys. | Other servers. Users' keychains. Users' other memberships. | Grant/revoke access. Publish relay records. Rotate access keys. Issue invites. | Access other servers. Read users' encrypted data. Track users across servers. |
| **User's app** | Full identity (private key). All server access keys. All server connection info. | Other users' private keys or keychains. | Connect to all servers. Publish/read own relay events. Accept invites. Link devices. | Access uninvited servers. Read other users' data. Forge events as another user. |

---

## 11. Data Flow Summary

```
IDENTITY CREATION
  User → generates Ed25519 keypair from BIP-39 seed phrase
  User → stores private key in device keychain
  User → saves seed phrase as backup

JOINING A SERVER
  Admin → creates invite link with constraints
  Admin → shares link out-of-band (text, email, etc.)
  User  → opens link, app connects to server
  Server → sends challenge nonce
  User  → signs challenge, sends signature + public key
  Server → verifies, adds public key to ACL
  Server → returns server access key + relay address + server ID
  User  → stores in keychain, publishes to relays

DEVICE SYNC
  New device → recovers private key (passkey / QR / seed phrase)
  New device → connects to one relay
  New device → fetches encrypted keychain, decrypts
  New device → now knows all servers + access keys + relay addresses
  New device → connects to all server relays
  New device → fetches encrypted server records, decrypts
  New device → fully synced

ACCESS REVOCATION
  Admin  → removes public key from ACL
  User   → can no longer authenticate
  Admin  → optionally rotates server access key
  Server → publishes new server:record + server:key_update per remaining user
  Users  → apps decrypt key updates, refresh keychains

KEY ESCROW (OPTIONAL)
  User → encrypts private key with seed-phrase-derived key
  User → uploads encrypted blob to central service
  New device → authenticates via passkey
  New device → downloads encrypted blob
  New device → decrypts with seed phrase
  New device → has private key, proceeds to device sync
```
