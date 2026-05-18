# Tower: server-sign-in pairing kind (streamlined web sign-in)

**Status:** open. **Repo:** ato.software (this one). **Scope:** `packages/tower-api/` + `packages/tower-web/`.

## Problem

Today, when a user signs in to an Aviato media server's web frontend via Aviato Identity, the flow goes through the client-pair pipeline: the browser generates an Ed25519 keypair, the Aviato server brokers a `client-pair` registration as `appId='aviato-web'`, Tower-web shows the full app-consent UI with per-server checkboxes, the user signs a long-lived `client-cert`, and the browser stores both privKey + cert in IndexedDB. Every browser is registered as a new "Connected App" entry in the user's Tower dashboard.

This is wrong for the web case:

- The browser is not a long-lived device that needs offline auth. The session cookie already handles "skip Tower for weeks."
- Every web sign-in pollutes the user's device list with another `Aviato Web` row.
- The user is asked to approve which servers to share, but they're signing in to *one specific server they've already linked*. The consent screen is redundant.
- IndexedDB cert storage + WebCrypto + cert renewal is a lot of complexity to drag around for "remember the user for 60 days."

## Solution

Introduce a new pairing kind `server-sign-in` that:

1. Is brokered by the Aviato media server (with its bearer), exactly like `server-link`.
2. Carries one `serverPubKey` value — the server the user is trying to sign in to.
3. On the user side, Tower-web shows a **single-button consent**: "Sign in to **<Server Name>**?" — no app card, no per-server checkboxes, no cert preview.
4. On approval, Tower-web master-signs a short-lived **assertion** (not a cert) and Tower API hands it back to the polling Aviato server.
5. The Aviato server verifies the assertion against the user's stored master pubkey and mints a session cookie.

No client-pair row, no `vault.clients[]` entry, no cert envelope, no IndexedDB on the browser side. Just a passkey tap → server session.

## Wire contract

### Assertion payload (master-signed, JCS-canonical, keys in alphabetical order)

```ts
{
  kind: 'server-sign-in',
  requestId: string,            // Tower pairing requestId
  serverPubKey: string,         // hex 64 (the Aviato server's Ed25519 pubkey)
  ts: number,                   // unix ms, signed-at
  userId: string,               // Tower opaque user uuid
  userPubKey: string,           // hex 64, the user's master pubkey
  v: 1,
}
```

Encoded the same way as the server-link assertion: `signedAssertionBytes = base64url(jcs(payload))`, `assertionSignature = base64url(sig)`. Note: hex encoding for both pubkey fields (see the cross-repo encoding contract in the server-link fix brief).

### New Tower API endpoints

| Method | Path | Auth | Body / Params | Returns |
|---|---|---|---|---|
| `POST` | `/api/identity/server-sign-in/begin` | Bearer (server) | `{ serverPubKey: hex64, serverName?: string }` | `{ requestId, code, expiresAt }` |
| `GET` | `/api/identity/server-sign-in/:requestId` | Bearer (server) | — | `{ state, requestId, expiresAt, signedAssertionBytes?, assertionSignature? }` |

`begin` mirrors `/api/identity/pairing/register` (server-link) almost exactly. The difference: it stores a pairing row with `kind: 'server-sign-in'` and the `serverPubKey` value.

`/api/identity/code/:code/resolve` (existing) gains a third `kind` branch in its response: returns `{ kind: 'server-sign-in', requestId, expiresAt, serverPubKey, serverName? }`. No `appId`, no `scope`, no `serverIds`.

`/api/identity/code/:code/complete` (existing) accepts the same `{ approve, signedAssertionBytes, assertionSignature }` shape it already accepts for server-link.

### Tower-web `/pair` page changes

`packages/tower-web/src/app/pair/page.tsx` currently has two branches (server-link, client-pair). Add a third:

```ts
if (resolved.kind === 'server-sign-in') {
  // 1. Open vault (passkey + PRF unwrap of master key) — same as the other flows.
  // 2. Look up `resolved.serverPubKey` in vault.servers[]:
  //      - if NOT found: show error "This server isn't linked to your Aviato Identity.
  //                       Use an invite to link it first." (offer link to dashboard)
  //      - if found: surface the server's stored name (vault.servers[i].name)
  // 3. Render simplified consent: a single "Sign in to <Server Name>?" card with
  //    one primary button. No checkbox grid. No app card.
  // 4. On Approve, build the server-sign-in assertion payload (see above) and
  //    POST /api/identity/code/:code/complete { approve: true, signedAssertionBytes, assertionSignature }
}
```

The vault lookup is the privacy-respecting equivalent of "server already approved" — Tower-web sees the server in *the user's local* vault decryption (Tower API never sees this), so the consent is implicit: the user can only sign in to servers they have already chosen to link.

### Tower API — `identity-pairing-db.ts`

Add a `createServerSignInPairing` function paralleling `createServerLinkPairing`. The row carries:

```ts
{
  pk: PAIRING#<requestId>, sk: META,
  kind: 'server-sign-in',
  serverId: <bearer-derived-server-id>,
  serverPubKey: <from request body>,
  serverName: <from request body, optional>,
  state: 'pending',
  signedAssertionBytes?: string,
  assertionSignature?: string,
  expiresAt, ttl, claimedByUserId, attemptCount, ...
}
```

Reuse `bumpPairingPoll` and the `PairingPollLimitError` machinery — the polling shape is identical to server-link.

### Aviato-side contract (consumer)

The Aviato server will:

1. On `POST /api/auth/identity-web-session/start`, call `POST /api/identity/server-sign-in/begin` with `{ serverPubKey: getServerPublicKeyHex(), serverName: settings('server.name') }`, store the requestId+code in its local pairing cache, return `{ requestId, code, pairingUrl }` to the browser.
2. On `GET /api/auth/identity-web-session/{requestId}/poll`, poll Tower's `/api/identity/server-sign-in/:requestId`. When state is `completed`:
   - Decode the assertion envelope, parse the payload, verify the signature against `payload.userPubKey`.
   - Confirm `payload.serverPubKey === getServerPublicKeyHex()`.
   - Confirm `Math.abs(Date.now() - payload.ts) < 10 * 60_000`.
   - Look up the local user by `payload.userPubKey` (`getUserByPublicKey`). Reject 403 if not found.
   - Mint a session for that user and return `{ sessionToken, expiresAt, user, profiles }` to the browser.
3. The browser stores the session token in its usual cookie/localStorage location and redirects to home. **No IndexedDB. No keypair. No cert.**

The existing `/api/auth/identity-web-session/pair/start` and `/pair/{id}/poll` endpoints will be deleted on the Aviato side as part of this change. So will `web-client.ts` (IndexedDB+WebCrypto) and the cert-auth path in Login.tsx.

## Why this is a clean architectural split

- **server-link** = "add this server to my identity" (one-time, via invite or relink). Already exists.
- **server-sign-in** = "let me sign in to a server I've already linked" (every session). NEW. This brief.
- **client-pair** = "register a long-lived native app as a client of my identity" (TV apps, mobile, desktop). Stays as-is; not used for web.

Three kinds, three intents, no overlap. The web doesn't need to pretend to be a native app anymore.

## Tower-web vault.servers lookup detail

The vault payload's `servers` array (per `~/projects/aviato/aviato/docs/specs/aviato-identity-v2.md` §3.3) has entries like:

```ts
{
  serverId: '<hex pubkey>',      // already exists as the identifier
  baseUrl: 'https://...',
  name: 'Home media server',
  linkedAt: <ms>,
  ...
}
```

So the lookup is `vault.servers.find(s => s.serverId === resolved.serverPubKey)`. If found, `s.name` drives the consent UI. If not found, the user must server-link first (offer a link to the dashboard or a clear error).

## Verifying the fix

1. Apply the Tower API changes (`identity-pairing-db.ts` + new routes in `identity-pairing.ts` or a new `identity-server-sign-in.ts`).
2. Apply the Tower-web `/pair` branch.
3. The Aviato side will independently rewrite its `/api/auth/identity-web-session/*` endpoints to call the new Tower routes and delete the cert path.
4. End-to-end test:
   - Sign in to an Aviato server you've already linked → click "Sign in with Aviato Identity" → enter code in Tower → one passkey tap → automatically signed in to Aviato web.
   - Confirm: no new entry in your Tower → Dashboard → Devices list (or whatever the connected-apps page is).
   - Confirm: no "Aviato Web" entry in `vault.clients[]` after the flow.
   - Sign out of Aviato web → sign back in → same UX, same single tap, still no new device row.

## Out of scope

- **Native client apps** (TV, phone, desktop apps published as Aviato clients): keep using `client-pair`. Those genuinely need a long-lived cert + clientPubKey for offline / cross-server use.
- **server-link** (the invite-acceptance flow): unchanged.
- **Revocation / dashboard UI**: the user's dashboard now only shows native clients in the Devices list. Web sessions are tracked by Aviato's own session DB and revoked there (existing functionality).

## Open questions for the Tower-web session

- Should `server-sign-in` pairings have a shorter TTL than the 10 min default (e.g., 5 min)? The user is going to confirm within seconds; a tighter window reduces abuse surface. Recommend 5 min.
- Should the Aviato server be allowed to begin a server-sign-in pairing for **any** `serverPubKey`, or must the `serverPubKey` match the bearer's owning serverId? Recommend: enforce match. Tower verifies that the bearer was issued for the same `serverPubKey` the body references; otherwise reject `400 server_pubkey_mismatch`. Prevents one media server from initiating sign-ins targeted at another server.
