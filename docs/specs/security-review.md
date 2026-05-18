# Pilot SDK — Security Review

Scope: full repo as of `main` (commit `68436d4`). Reviewed against three requirements:

1. Server payloads carrying a server pubkey or identifier are signed by the server.
2. All crypto operations live in this repo (third-party-auditable).
3. The client SDK is easy to integrate.

---

## Requirement 1 — Server-side signatures on payloads bearing serverPubKey

### ✅ What is correctly signed

| Payload | Signer | Verifier | Binding |
|---|---|---|---|
| `PairingResponse` (sealed K reply) | server Ed25519 (`serverPrivKey`) | user, with `expectedServerPubKey` | `utf8(serverPubKeyHex) ‖ utf8(JSON.stringify({ct, ephPub, nonce}))` — `packages/core/src/conn-info/pairing-response.ts:22-37`. The alphabetical 3-key JSON is byte-equivalent to JCS for these string-only fields. The hex-encoded serverPubKey is the binding prefix; the user verifies with `expectedServerPubKey` lifted from their just-signed assertion. |
| `ServerConnInfoRecord` (publish) | server Ed25519 | client + Tower (defense-in-depth) | `JSON({ct, nonce, serverPubKey, version})` — `packages/core/src/conn-info/publish-sig.ts` |
| `ServerConnInfo` AEAD | server (K-keyed AES-GCM) | client/Tower | AAD = `"aviato-server-conninfo-v1" ‖ serverPubKeyHex ‖ u64BE(version)` — `packages/core/src/conn-info/aad.ts` |
| `ClientDelegationCert` | user master (M) | server + client (renewal) | JCS payload includes `userPubKey`, `clientPubKey`, `clientEncPubKey` — `packages/core/src/cert/build.ts` |
| Pairing assertions (`server-link`, `server-sign-in`) | user master (M) | server with `expectedServerPubKey` + `expectedRequestId` | `packages/core/src/assertions/master-signed.ts:118` |
| Session assertion (per-session cert-auth) | client (`C_n`), wrapping M-signed cert | server with `expectedServerPubKey` + `expectedChallenge` | `packages/core/src/assertions/session.ts:90` |
| Revocation envelopes | user master (M) | anyone with stored `userPubKey` | `packages/core/src/revocation/index.ts` |

Verification on the server side rejects mismatched server pubkey (`wrong_server`), mismatched request id (`wrong_request_id`), and stale signatures (`stale`, default 300 s) — `packages/core/src/assertions/master-signed.ts` and `assertions/session.ts:93`.

### ⚠️ Findings

1. **Trust root for `serverPubKey` at first pair is Tower.** The wire schema `PairingRegisterRequest` (server → Tower) carries only `serverId`, never `serverPubKey`. Tower returns the `serverPubKey` to the user's browser via `GET /api/identity/code/:code/resolve` (`packages/core/src/schemas/pairing.ts`). If Tower is malicious it can substitute its own pubkey *here*, and from then on all subsequent verifications will pass (against the wrong key). **Once paired the user holds the bytes directly and the chain is sound.** Recommendation: document explicitly that the trust model treats Tower as honest *only at code resolution*, and consider an out-of-band attestation channel (invite-token-signed payload, or QR including pubkey fingerprint) so the first-pair step does not need to trust Tower.

2. **`verifyConnInfoRecordSig` lifts `serverPubKey` from the record itself.** Sound *because* the client looks up by `sha256(serverPubKey)` partition hash (`deriveServerConnInfoHash` — `packages/client-sdk/src/server-conninfo.ts`) and the user already has the trusted serverPubKey in their identity bundle. Worth a one-line comment in `verify.ts` calling out that the trust root for the comparison is the caller-supplied hash, not the record.

3. **`PairingResponsePayload.sig` does NOT cover `PairingResponseSealed.serverPubKey` directly** — it covers the sealed bytes (`ct/ephPub/nonce`). The serverPubKey-binding comes from the prefix in the sig message. Internal consistency is enforced via the optional `inner_server_mismatch` check inside `openPairingResponse`. **Confirm the user side always supplies `expectedServerPubKey` lifted from their own just-signed assertion** — `tower-sdk/pairing-response.ts:claimConnInfoKey` does this correctly. No change required, but keep the comment in `pairing-response.ts` lines 1-10 — it is the only thing that documents the binding intent.

4. **Session-auth `/complete` response carrying `SessionConnInfoEnvelope` (refreshed K) is sealed to `clientEncPubKey` but not Ed25519-signed by the server.** Confidentiality holds (only the right client can open it), but integrity rides on AES-GCM under K — which the server already controls. Adding a server-signature over the envelope would be belt-and-suspenders; not strictly required since K-refresh only happens inside an already-authenticated session.

5. **`AviatoPilotClient.finalizePair()` calls `verifyClientCert(cert)` WITHOUT `expectedUserPubKey`** (`packages/client-sdk/src/identity-client.ts:343`). This is the trust-boundary moment for a new client — by definition there is no prior userPubKey to compare against. The downstream protections that catch a malicious Tower swap are: (a) `clientPubKey`/`clientEncPubKey` in the cert must equal the bytes the SDK just generated locally (already enforced, lines 351-358), and (b) server-side cert-auth must verify the cert against the server's known userPubKey, so a swapped userPubKey will fail there. **No bug, but worth a `// Trust-root note:` comment** at line 343 documenting why no `expectedUserPubKey` is passed.

6. **`finalizePair` does not check `cert.appId === this.opts.appId`.** A malicious Tower could return a cert minted for a different app the same user has paired. Add: `if (payload.appId !== this.opts.appId) throw …` right after the clientPubKey checks. One line; closes a small misuse window.

---

## Requirement 2 — Crypto is contained in this repo

### ✅ All primitives are visible in TypeScript source, no native blobs

| Primitive | Implementation | Audit lineage |
|---|---|---|
| Ed25519 sign/verify | `@noble/curves/ed25519` | Cure53-audited |
| X25519 ECDH | `@noble/curves/ed25519` (x25519) | Cure53-audited |
| HKDF-SHA-256 | `@noble/hashes/hkdf` | Cure53-audited |
| AES-GCM-256 | WebCrypto (`crypto.subtle`) | Browser/OS-audited |
| SHA-256 | `@noble/hashes/sha2` | Cure53-audited |
| JCS (RFC 8785) | `canonicalize` (npm, RFC author's reference impl) | matches v2 spec mandate |
| base64url no-pad | `@scure/base/base64urlnopad` | paulmillr |
| Hex | `@noble/hashes/utils` | Cure53-audited |

All cross-system constants are in this repo and grepped from a single location:

- HKDF info for sealedbox: `"aviato-sealedbox-v1"` (`crypto/sealedbox.ts:33`)
- HKDF info for vault wrap: `"aviato-vault-wrap/v1"` (`tower-sdk/prf.ts:10`)
- AEAD prefix for conn-info: `"aviato-server-conninfo-v1"` (`conn-info/aad.ts:6`)
- Pairing-response sig binding: hex-encoded `serverPubKey` is concatenated as the message prefix before the canonical sealed-envelope JSON. There is no version literal in the sig message — the protocol version on this leg is carried by the schema `v: 1` field inside the inner sealed payload and by Tower's HTTP route version.

### ✅ Operations covered

- **Sealedbox** (X25519 + HKDF + AES-GCM-256, 12-byte random nonce) — `crypto/sealedbox.ts`
- **Server conn-info AEAD** (per-server K, random nonce, AAD bound to pubkey+version) — `conn-info/seal.ts`
- **Vault wrap** (PRF → HKDF → AES-GCM around VK; VK encrypts payload) — `tower-sdk/vault.ts`
- **WebAuthn PRF extension wrapper** — `tower-sdk/prf.ts`
- **Ed25519 over JCS canonical bytes for all signatures** — uniform pattern, `jcs()` throws explicitly on un-canonicalizable input (`crypto/encoding.ts`)

### ⚠️ Findings

1. **AES-GCM nonces are random 12-byte values.** For per-server K with strict-monotonic `version`, a deterministic nonce derived from `version` would be theoretically safer (eliminates birthday-bound collision risk under huge volume). Random 96-bit nonces remain safe up to ~2^32 messages per key; well above expected publish rates. Acceptable as-is; document the assumed publish-volume bound.

2. **AEAD AAD construction does not pin protocol version.** The prefix string `"aviato-server-conninfo-v1"` carries the `v1` baked in, which suffices. The vault and sealedbox prefixes likewise. No action.

3. **No constant-time comparison wrappers.** Ed25519 verify and AES-GCM tag check are constant-time inside the libraries; equality checks elsewhere in the SDK (e.g. `payload.serverPubKey !== hexEncode(...)`) are over hex strings derived from already-validated bytes — not security-relevant for timing.

4. **`canonicalize` returns `string | undefined`** and `jcsString` throws on `undefined` — `crypto/encoding.ts`. Correct; do not weaken. The throw is a load-bearing invariant for signature integrity. Already documented in `CLAUDE.md`.

5. **No misuse-resistant API for K.** `connInfoKey: Uint8Array` is passed around as plain bytes. Consider wrapping in a `ConnInfoKey` opaque type with `Symbol.toPrimitive` returning `'[redacted]'` to avoid accidental serialization (a one-time log statement would otherwise dump K). Not a flaw, an ergonomic + safety upgrade.

6. **Storage backend (`LocalStorageBackend`) persists private keys (`clientPrivBase64url`, `clientEncPrivBase64url`) in localStorage in clear.** Browser-XSS in a consumer app can exfiltrate them. The `IdentityStorage` interface allows swapping; document strongly that production consumers must use an OS-backed keychain on native or a Web Crypto `CryptoKey` non-extractable handle on web — and provide a built-in `SubtleCryptoKeyStorageBackend` that stores `CryptoKey` handles non-extractably (will require a refactor since several call sites need raw bytes for signing; doable by replacing Ed25519 sign with a closure over the CryptoKey).

---

## Requirement 3 — Easy to integrate

### ✅ What is well-designed

- **One orchestrator class:** `AviatoPilotClient` encapsulates pair, hydrate, sign-in, sign-out, conn-info resolution, cert renewal, subscribe.
- **Sensible defaults:** `pollIntervalMs=2000`, `maxAttempts=600` (20 min), `clockSkewSec=60`, `maxAgeMs=300_000`, `LocalStorageBackend` default.
- **Discriminated-union returns** for every fallible op (`{ok: true, ...} | {ok: false, error: '<kind>'}`), enabling exhaustive switches in TypeScript.
- **Bytes-only public boundary** (`Uint8Array` for every pubkey/privkey/sig). This is the strongest single API decision in the repo — it makes wire-encoding mismatches a type error.
- **React hooks ship in `client-react`** — `usePairing`, `useSignInToServer`, `useSignOut`, `usePilotConnections`, `usePilotConnection`, `usePilotIdentity`, backed by `useSyncExternalStore` for correctness under concurrent rendering.
- **Resumable flows:** `pollPair({ ephemeral })` lets a paired flow survive page reloads (the ephemeral state is the only required handoff).
- **Power-user escape hatches** are also exported (`TowerClient`, `serverCertAuth`, `resolveServerConnInfo`) so unusual integrations don't need to fork the orchestrator.
- **`finalizePair` cross-checks** that the cert's `clientPubKey`/`clientEncPubKey` equal the keys generated locally — fails loud on Tower swap.
- **`respondWithK` insists on a `VerifiedPairingAssertion` (the `ok:true` branch),** not raw bytes — eliminates a whole class of wrong-key bugs at the SDK boundary (`server-sdk/pairing.ts`).

### ⚠️ Findings

1. **Third-party README is missing.** There is no `packages/client-sdk/README.md`. The first third-party developer experience hits `index.ts` cold. Add a README at the package root with: 30-line quickstart, `AviatoPilotClient` minimum viable example, React quickstart, error-code reference, storage-backend guidance. This single change is the highest-leverage ergonomics win.

2. **No worked example of native (non-browser) storage backend.** `IdentityStorage` is an interface but only `LocalStorageBackend` and `MemoryStorageBackend` exist. Add a `SubtleCryptoKeyStorageBackend` or at least a documented example (e.g. for React Native / Electron secure-storage).

3. **Error types leak through `Error.message` strings.** `serverCertAuth` throws `ServerAuthError` with a tagged `code` field — good. But `AviatoPilotClient.signInToServer` catches it and persists only `errMsg` into the connection's `error` field. Surface the original code so consumers can branch on it rather than parse message text.

4. **No `clientIdFromPub` import path is documented inline.** It is exported from `client-sdk` but absent from the React hooks. Useful for consumers that want to display the current client's id.

5. **App id verification missing.** As noted in Req 1 finding 6, `finalizePair` doesn't verify `cert.appId === this.opts.appId`. Add that check; it's also an ergonomics improvement (an early actionable error instead of a downstream cert-auth failure).

6. **`signInToServer` returns the connection but does not surface the underlying `body` typing in a discoverable way.** The TypeScript generic `<TBody>` is on `serverCertAuth` but on `signInToServer` is hidden under an optional generic. Consider documenting the recommended pattern in README.

7. ~~**Test coverage gaps for the security-critical paths:**~~ — **RESOLVED.** All three gaps closed in the implementation pass:
   - Tampered pairing-response sig: covered by `adversarial: openPairingResponse rejects tampered sig` (`packages/core/__tests__/crypto.test.ts`).
   - `verifyRevocation` mismatch path: error code split into `expected_user_mismatch` (distinct from `signature_invalid`), covered by `adversarial: verifyRevocation expected_user_mismatch is its own error`.
   - `ConnInfoPublisher.publish` monotonicity: enforced in-process via a strict-monotonic guard; covered by `ConnInfoPublisher: strict-monotonic version` in `packages/server-sdk/__tests__/pairing.test.ts`.

---

## Summary

The protocol's cryptographic core is sound, well-modularized, and bytes-on-the-boundary. The main residual risks are at the **bootstrap trust boundary** (first time a user learns a server's pubkey, mediated by Tower) and at **client-side key storage** (default localStorage backend). All wire payloads carrying a `serverPubKey` are either signed by the server's private key (`PairingResponse`, `ServerConnInfoRecord`) or sealed under a key the user already controls (`ClientPairBundle` to `clientEncPubKey`). Verification helpers consistently take an `expected*PubKey` parameter and refuse to proceed without it.

### Highest-value follow-ups (in priority order)

1. **Add `cert.appId === opts.appId` check in `finalizePair`** — one line, closes a Tower-mediated misuse window. *(Req 1 finding 6)*
2. **Add a `packages/client-sdk/README.md` quickstart** — biggest third-party ergonomics gain. *(Req 3 finding 1)*
3. **Document the Tower-as-trust-root assumption at first pair**, ideally with a recommended out-of-band attestation path (signed invite token, QR with serverPubKey fingerprint). *(Req 1 finding 1)*
4. **Provide a `SubtleCryptoKeyStorageBackend`** that keeps private keys as non-extractable `CryptoKey` handles to neutralize XSS exfiltration in browser consumers. *(Req 2 finding 6, Req 3 finding 2)*
5. **Surface `ServerAuthError.code` through `ServerConnection.status`** instead of stringifying. *(Req 3 finding 3)*
6. **Add adversarial test cases** for tampered sigs and non-monotonic publish versions. *(Req 3 finding 7)*

No wire-bytes changes are recommended — the protocol contract is solid.
