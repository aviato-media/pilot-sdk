# Aviato server bug: pairing-response leg not posting K back to Tower

> **Audience:** an implementer working inside `~/projects/aviato/aviato` on
> the Aviato media server. This is the server side of the Aviato Identity v2
> pairing-response leg.

## The problem (from Tower's side)

When a user goes through **server-link** or **server-sign-in** at
`tower.aviato.media/pair`, Tower's browser:

1. Approves the pairing and submits a master-signed assertion to Tower-api
   via `POST /api/identity/code/:code/complete`.
2. Tower-api stores the assertion on the pairing row and waits for the
   Aviato server to fetch it.
3. The Aviato server polls the pairing row, verifies the user's assertion
   against the user's Ed25519 pubkey, and **is supposed to POST a sealed
   reply containing a fresh per-server symmetric key K**
   (the `connInfoKey`) back to Tower-api at
   `POST /api/identity/pairing/:requestId/response`.
4. Tower's browser polls
   `GET /api/identity/pairing-response/:requestId`, verifies the server's
   signature, decrypts the sealed reply, and writes K into the user's
   encrypted vault under `vault.servers[i].connInfoKey`.

**The Aviato server isn't doing step 3.** Tower's browser polls for up to
30 seconds (`packages/tower-web/src/lib/pairing-response.ts:76`),
times out, and the vault stores `connInfoKey: null` permanently for that
server. After that, when the user authorizes a client app
(e.g. Aviato Web) via the `client-pair` flow, Tower-web has no K to seal
into the per-server bundle and the client app pairs without server
access.

We've now fixed Tower-web's `/pair` consent UI to surface K-less servers
as disabled with a "sign in from this server to enable" hint, but that's
just symptom UX — the actual fix is on the Aviato server: **post the
sealed K reply during the pairing-response leg for every server-link and
server-sign-in.**

## What the server has to do

Two trigger events. Both follow the same shape.

### Trigger 1 — server-link approval (first-time link)

The server has just verified the user's `server-link` assertion via its
existing poll against Tower (assertion contains `userPubKey`,
`userEncPubKey`, `serverPubKey`, `iat`, `nonce`, etc., canonical-signed
by the user's master Ed25519 key). At this point:

1. Persist the user record (Aviato's `identity_users` table or
   equivalent) keyed on `userPubKey`.
2. **Generate a fresh K**: 32 random bytes, base64url-encoded. This K
   becomes the AES-GCM-256 key the server will use to encrypt its
   `SERVER_CONNINFO` ciphertext (the published blob containing the
   server's reachability info — URL, cert fingerprint, etc.). Same K
   is shared with every paired user / client so they can decrypt that
   ciphertext.
   - If the server already has a published K (multi-user server), reuse
     it. K is per-server, not per-user.
3. **Seal K to the user's `encKeyPub`** using `aviato-sealedbox-v1`
   (X25519 ECDH + HKDF-SHA256 + AES-GCM-256). See "Crypto spec" below.
4. **Sign** `serverPubKey_hex_ascii_bytes ‖ canonical_sealed_bytes` with
   the server's Ed25519 private key. Signature is over the byte
   concatenation — see "Signature input" below.
5. **POST** the sealed payload + signature to Tower-api:
   `POST /api/identity/pairing/:requestId/response`. Auth: server bearer
   token (whatever your server uses to authenticate to Tower-api today
   for the existing assertion-poll endpoint). Schema below.

### Trigger 2 — server-sign-in approval (re-sign-in)

Identical to Trigger 1, but the server is re-attesting an existing user.
Still post a fresh seal-of-K (K itself can be the same — the user's
browser overwrites `vault.servers[i].connInfoKey` with whatever this
reply delivers). This is how a user with `connInfoKey: null` recovers:
they sign into the server again, the server delivers K via this leg,
and the vault picks it up.

If your server is currently doing server-sign-in *without* posting a
pairing-response reply, that's the second half of the bug. Both legs
have to post.

## Endpoint spec

**URL:** `POST https://tower.aviato.media/api/identity/pairing/:requestId/response`

`:requestId` is the pairing row's UUID — the same one the server's
existing assertion-poll endpoint uses to fetch the user's assertion. The
server already knows it.

**Auth:** Server bearer token (the same auth used for the assertion-poll
endpoint that the server already calls today). Tower-api's middleware
verifies `serverId == row.serverId`.

**Request body** (matches `PairingResponseSchema` in
`packages/tower-api/src/routes/identity-pairing.ts:405-414`):

```json
{
  "sealed": {
    "ct":     "<base64url AES-GCM ciphertext>",
    "ephPub": "<base64url 32-byte X25519 ephemeral public key>",
    "nonce":  "<base64url 12-byte AES-GCM nonce>"
  },
  "sig": "<base64url Ed25519 signature, 64 bytes raw>"
}
```

**Responses:**
- `201 { ok: true }` — sealed reply attached to the row.
- `400 invalid_body` — schema validation failed.
- `403 not_owner` — bearer's serverId doesn't match row.serverId.
- `409 not_completed` — call this *after* the user's `/complete` has
  landed; row must be in `completed` state. Either poll for completion
  first (your server probably already does) or just retry on 409.
- `400 wrong_kind` — only valid for `server-link` and `server-sign-in`
  rows. Don't call this for `client-pair`.

**Timing:** Tower's browser polls every 1.5s for up to 30s after the
user's approve. Post within that window. The pairing row TTLs out
5 minutes after creation, so don't sit on it for longer than that.

## Crypto spec — `aviato-sealedbox-v1`

The browser-side reference implementation lives at
`packages/tower-web/src/lib/sealedbox.ts` in this repo
(`~/projects/ato/ato.software`). The construction:

1. **Generate an ephemeral X25519 keypair** `(ephPriv, ephPub)`. Discard
   `ephPriv` after deriving the shared secret; `ephPub` is the 32-byte
   public key that goes into the sealed payload.
2. **ECDH** with the user's static X25519 pubkey:
   `shared = X25519(ephPriv, userEncPubKey)`. `userEncPubKey` is the
   32-byte raw X25519 public key the user signed into their assertion
   as `userEncPubKey` (it appears as a 64-char hex string in the
   assertion payload — decode hex to 32 bytes before passing to X25519).
3. **HKDF-SHA256** the shared secret to a 32-byte AES-GCM key:
   - `salt`: empty / unset
   - `info`: ASCII bytes of the string **`"aviato-sealedbox-v1"`** (19 bytes,
     no terminator)
   - output length: 32 bytes
4. **Generate a 12-byte random nonce.**
5. **AES-GCM-256 encrypt** the plaintext (see below) under the derived
   key with that nonce. Output is `ciphertext ‖ 16-byte GCM tag`. Both
   together get base64url-encoded into `ct`. The 12-byte nonce gets
   base64url-encoded into `nonce`.

**Plaintext to seal** (JSON, then UTF-8 encoded):

```json
{
  "v": 1,
  "connInfoKey": "<base64url 32-byte K>",
  "issuedAtSec": <unix seconds>,
  "serverPubKey": "<hex 64-char server Ed25519 pubkey>"
}
```

Field order in the JSON does not matter — `JSON.stringify` with the
fields in this order is fine; the browser deserializes by name. The
`serverPubKey` field inside the sealed body is a defense-in-depth cross-
check: the browser refuses a sealed reply whose inner `serverPubKey`
doesn't match the `serverPubKey` it expected for this pairing
(`packages/tower-web/src/lib/pairing-response.ts:140`).

## Signature input

The `sig` field is the server's Ed25519 signature over a byte string
constructed deterministically by both sides. This lets the browser
verify the reply is from this server (not a Tower-side substitution)
before attempting decryption.

```
message = utf8_bytes(serverPubKey_hex) ‖ canonical_sealed_bytes
sig     = Ed25519_sign(serverPriv, message)
```

Where `canonical_sealed_bytes` is the UTF-8 bytes of:

```js
JSON.stringify({ ct: <ct>, ephPub: <ephPub>, nonce: <nonce> })
```

with those three fields in **exactly that order** (`ct`, `ephPub`,
`nonce`). The browser re-constructs the same bytes using the exact same
field order before calling `crypto.subtle.verify`
(`packages/tower-web/src/lib/pairing-response.ts:150-158`). If your JSON
encoder reorders fields alphabetically (some Go encoders do), explicitly
control the order or use the canonical struct ordering matching
`{ct, ephPub, nonce}`.

`serverPubKey_hex` is the lowercase hex encoding of the server's 32-byte
Ed25519 public key (64 hex chars, no `0x` prefix, no whitespace). This
must match the hex pubkey the browser saw in the assertion / resolve
response.

## Reference implementations to crib from

The browser side (which is what you have to interoperate with) lives in
this repo:

- `packages/tower-web/src/lib/sealedbox.ts` — `aviato-sealedbox-v1`
  encrypt/decrypt. The HKDF info string at line 35:
  `const HKDF_INFO = ENCODER.encode('aviato-sealedbox-v1')`.
- `packages/tower-web/src/lib/pairing-response.ts` — the polling client.
  Lines 104-119 show the exact signature-verification construction.
  Lines 121-127 show the seal-decrypt. Lines 128-142 show the
  shape/cross-pubkey checks.

You don't need to read Tower-api code beyond the endpoint signature
above — the endpoint just stashes whatever you POST onto the pairing
row and the browser does all the verification.

## Diagnostic — how to confirm it works

After your change, do a fresh server-link from
`tower.aviato.media/pair`:

1. **Server logs:** confirm you generated K, sealed it, signed it, and
   got `201 { ok: true }` from
   `POST /api/identity/pairing/:requestId/response`.
2. **Browser console (Tower-web):** the dashboard server row should
   transition from "awaiting first sign-in" to "ready" within ~5
   seconds. The vault entry for that server should now have
   `connInfoKey` set (32-byte base64url, ~43 chars).
3. **Aviato Web client-pair flow:** sign into Aviato Web via the
   `client-pair` flow. On the Tower consent screen, the server should
   be checked and enabled (not greyed out). After approve, the Aviato
   SDK console should log `pollPair: bundle decoded with 1 server(s)`
   (or 2, depending on how many you've linked).

If you see the SDK log
`pollPair: sealedConnInfoBundle decrypt failed — recipient X25519 key
mismatch or tampered ciphertext`, that means the seal happened but to
the wrong pubkey — double-check you're sealing to the user's
`userEncPubKey` from the *assertion payload*, not anything else.

If you see
`pollPair: bundle plaintext failed schema validation`, that means seal
+ decrypt succeeded but the JSON shape inside is wrong — check field
names (`serverPubKey` hex, `connInfoKey` base64url 32 bytes,
`issuedAtSec` integer, `v: 1`).

If Tower's browser logs
`Server signature did not verify against its registered pubkey`, the
`sig` is wrong — most likely a JSON-field-order mismatch in the
canonical bytes, or signing the hex bytes through a different encoder.
Match the byte construction in `pairing-response.ts:150-158` exactly.

## Why this is urgent

Until the Aviato server posts K via this leg, **every newly-linked
server will be unusable from client apps** — Aviato Web's `client-pair`
will pair the cert but never get a usable server list, because Tower
can't seal a K it doesn't have. Existing users with already-paired
servers that have `connInfoKey: null` recover by signing into the
server once via server-sign-in (which fires the same leg). New users
won't have a working server at all until this lands.
