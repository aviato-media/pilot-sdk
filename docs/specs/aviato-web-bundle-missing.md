# Pairing-response K decrypt failure — diagnostic state

> **Audience:** whoever picks this back up next.
> **Status:** root cause **not yet identified**. What we've ruled out and the
> next instrumentation pass are below.

## Symptom

Tower-web's `claimConnInfoKey` poll receives the sealed pairing-response payload
within the deadline, the server's Ed25519 signature over `(serverPubKey ‖
canonical sealed bytes)` verifies, but AES-GCM decryption fails:

```
[tower-web] pairing-response K claim failed (will retry on next sign-in)
{ requestId, serverPubKeyPrefix, reason: 'Could not decrypt the sealed reply — vault key mismatch.' }
```

This persists across a clean cycle: user unlinks on Aviato, forgets servers in
the Tower vault, performs a fresh `server-link`.

## Ruled out (don't re-investigate these)

1. **Aviato sealing to a stale/cached `userEncPubKey`.** Verified at
   `~/projects/aviato/aviato/packages/server/src/api/identity-link.ts:250` —
   `userEncPubKey` is destructured from the just-verified assertion payload and
   passed directly to `deliverPairingResponseKey` at `:354` with no intervening
   DB read. The same is true for server-sign-in (`identity-web-session.ts:208`
   → `:225`). Aviato's seal recipient is always the live assertion's pubkey.

2. **`aviato-sealedbox-v1` construction drift between repos.** Byte-by-byte
   comparison of `~/projects/aviato/aviato/packages/crypto/src/sealedbox.ts`
   vs `~/projects/ato/ato.software/packages/tower-web/src/lib/sealedbox.ts`
   on all ten relevant items (HKDF salt, info string, output length, X25519
   shared-secret derivation, AES-GCM key length, nonce length, AAD,
   ct‖tag layout, base64url encoding, plaintext encoding) — **all match**.
   Both pull `x25519` from `@noble/curves/ed25519.js` and `hkdf` from
   `@noble/hashes` with identical parameters.

3. **Tower-api transport.** `POST /api/identity/pairing/:requestId/response`
   now logs `[tower-api] pairing-response attached { requestId, serverId,
   serverPubKeyPrefix }` on success. Confirmed firing in the user's testing.

4. **Browser poll timing.** `claimConnInfoKey` default deadline raised from
   30s → 270s. The user is seeing the failure log fire, so the payload is
   reaching the browser inside the deadline — not a timeout.

5. **Tower-web pattern-attribute regex error.** The `[0-9-]*` warning in
   the console was an unrelated cosmetic issue with HTML5's `v`-flag regex
   parser; fixed to `[0-9\-]*`. Not related to the decrypt failure.

## Remaining hypotheses (in order)

### H1. Tower-web vault's encKey pair is internally inconsistent

`vault.payload.encKeyPriv` doesn't actually correspond to the
`vault.payload.encKeyPub` that was just sent in the assertion. This would
happen if a vault-rebuild path generated a fresh keypair but only updated
one half, or if a load path mixes the new priv with an old pub (or vice
versa). Both halves come from `generateX25519Keypair()` at
`vault-context.tsx:459` / `register/page.tsx:194`, but the actual on-wire
storage and round-trip needs verification.

**Diagnostic in place.** `claimConnInfoKey` now self-checks:

```ts
const derivedPub = x25519.getPublicKey(base64urlDecode(input.vaultEncKeyPrivBase64url))
console.info('[tower-web] pairing-response decrypt keypair self-check', {
  derivedEncPubFromPriv: base64urlEncode(derivedPub),
})
```

Compare `derivedEncPubFromPriv` (what the priv actually corresponds to) against:

- The `userEncPubKeyPrefix` from `[tower-web] claiming K (server-sign-in)`
  / `[tower-web] claiming K (server-link)` — the pubkey sent in the
  assertion.
- The pubkey Aviato received (add a log on Aviato's side at the seal site
  echoing `input.userEncPubKeyHex`).

**If `derivedEncPubFromPriv` ≠ what the assertion carried** → confirmed
vault corruption / load bug on Tower-web. Look at `unlock` in
`vault-context.tsx` and `decryptVaultBody` in `vault.ts` for where the
pair could split.

**If they match but Aviato's logged recipient is different** → Aviato is
sealing to something other than the assertion's `userEncPubKey` (re-open
the Aviato investigation; possibly the assertion-builder path is wrong).

**If all three match** → see H2.

### H2. AAD asymmetry at the wrapper layer

Both primitives default AAD to `undefined`, but a *caller* somewhere
might pass `aad` on encrypt without the decrypt side knowing. Grep both
repos for `aad:`, `aad =`, `additionalData` and verify no caller passes
non-undefined AAD on the pairing-response path. The current
investigation found both sides default to `undefined` on the active call
sites, but a wrapper introduced later could break this.

### H3. Wrong primitive used on encrypt side

Aviato's `packages/crypto/` also has `public-encrypt.ts` with a legacy
NaCl-box `sealedBoxEncrypt`/`sealedBoxDecrypt`. If anywhere in the seal
pipeline imports from `./public-encrypt` instead of `./sealedbox`, the
wire shape `{ ct, ephPub, nonce }` would look identical but the
underlying construction is XSalsa20-Poly1305 + HSalsa20, not
HKDF+AES-GCM. Verify the import path at `pairing-response.ts:57-62`.

### H4. Key-encoding mix-up on transport

`userEncPubKey` is hex-64 in the assertion (verified). Confirm Aviato's
verifier path decodes it as hex (32 raw bytes) before passing to the
seal — not as base64, base58, or DER-wrapped. Aviato's `encoding.ts`
exposes `base58Encode`/`hexEncode` so the wrong helper could silently
produce 32 bytes of garbage.

## Three logs to capture and diff next

Re-run a fresh `server-sign-in` after the user is signed in with a working
vault. Collect:

1. **Tower-web console:**
   ```
   [tower-web] onApprove server-sign-in: vault keypair snapshot
   { encKeyPubFull: '<hex 64>' }
   [tower-web] claiming K (server-sign-in)
   { userEncPubKeyPrefix: '<first 8 hex>…' }
   [tower-web] pairing-response decrypt keypair self-check
   { derivedEncPubFromPriv: '<base64url>' }   ← convert to hex and compare
   ```

2. **Aviato server log (needs to be added):**
   At `~/projects/aviato/aviato/packages/server/src/identity/v2/pairing-response.ts`
   line ~57, log `input.userEncPubKeyHex` (the recipient pubkey passed to
   `aviatoSealedBoxEncrypt`) just before the seal call.

3. **Tower-api log:** `[tower-api] pairing-response attached` —
   already in place.

Three identical hex pubkeys → vault, assertion, and seal recipient all agree.
Any divergence pinpoints the bug.

## Tower-side workaround already shipped

The Tower-web consent UI no longer silently drops K-less servers from the
client-pair bundle. It disables their checkbox, labels them "sign in from this
server to enable", and pre-selects only K-having servers. So users with K-less
servers can still pair the client cert (cert-only) and authorize servers later
as K arrives. See `tower-web/src/app/pair/page.tsx` (`ClientPairConsent` and
`resolveCode`).

## Cross-system contract (unchanged)

```ts
ClientKeyBundleContentsSchema = z.object({
  v: z.literal(1),
  issuedAtSec: z.number().int(),
  servers: z.array(z.object({
    serverPubKey: HEX_32,
    connInfoKey: BASE64URL,  // base64url 32-byte AES-GCM-256 K
  })),
})

PairingResponseSealedPlainSchema = z.object({
  v: z.literal(1),
  connInfoKey: BASE64URL,
  issuedAtSec: z.number().int(),
  serverPubKey: HEX_64,
})
```

Sealedbox HKDF info: `"aviato-sealedbox-v1"`. Reference impls at
`tower-web/src/lib/sealedbox.ts` and
`aviato/packages/crypto/src/sealedbox.ts` — confirmed byte-equivalent.
