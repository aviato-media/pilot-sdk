# Aviato Identity — Web Client Integration Guide

This document describes how a browser-based web app (Aviato Web, future
companion SPAs) integrates with Tower's Identity endpoints. The flow
is identical in wire shape to the native client-pair flow — what differs
is **where the credentials live**: localStorage instead of the OS
keychain, with the corresponding UX tradeoffs around cache eviction and
profile / incognito boundaries.

For the underlying wire flow + crypto + endpoints, see
`identity-client-app.md`. This guide focuses on what's specific to a
web environment.

For the server side of the integration, see `identity-server-link.md`.

---

## Why a web-specific guide

Browser-based web apps differ from native clients in three ways that
affect how you implement the pairing flow:

1. **No persistent OS-keychain storage.** localStorage is the most
   durable option, but it's per-origin, scoped to the browser profile,
   and routinely cleared (incognito, "clear data", aggressive privacy
   settings, multi-profile users).
2. **No long-lived background process.** Cert renewal can only run
   while a tab is open. Don't rely on it; plan for re-pair to be the
   common refresh path.
3. **Streamlined UX expectations.** A web sign-in should feel like a
   sign-in, not an OAuth-style consent dance every session. We
   accomplish this by running the client-pair flow under the hood and
   reusing its long-lived cert for as long as localStorage survives.

Concretely: the web client uses the **client-pair** endpoints, NOT
`server-sign-in`. server-sign-in was an earlier idea; it's now reserved
for the case where a user logs into a media server directly from
Tower-web's `/pair` page (i.e. the server itself initiates a sign-in).
For a web app like Aviato Web that connects to media servers on the
user's behalf, the long-lived delegation cert from client-pair is what
you want.

---

## What you store, and where

| Item                       | Storage location          | Survives           |
|----------------------------|---------------------------|--------------------|
| `clientPriv` (Ed25519)     | `localStorage`            | Until cache clear  |
| `clientEncPriv` (X25519)   | `localStorage`            | Until cache clear  |
| `signedCertBytes` + sig    | `localStorage`            | Until cache clear  |
| `clientId` (UUID)          | `localStorage`            | Until cache clear  |
| K per server               | `localStorage` (encrypted with a derived key, optional) | Until cache clear |
| Per-session API state      | `sessionStorage` or memory | Tab lifetime      |

**Why localStorage and not IndexedDB**: localStorage is synchronous and
its data model is trivial (string keys, string values). For the small
amount of credential data here it's the lower-friction choice.
IndexedDB is a fine alternative if you're already using it for other
data — both have the same lifecycle semantics from the user's
perspective.

**Re-pair is normal.** Plan UX around the assumption that any user who
clears cookies, opens incognito, switches browsers, or uses a different
profile will need to re-pair. The 8-digit code + QR flow takes ~30
seconds for a logged-in user, so this is acceptable.

---

## The sign-in flow, end-to-end

### 1. Check for an existing local cert

On app boot:

```typescript
const stored = localStorage.getItem('aviato-cert')
if (stored) {
  const cert = JSON.parse(stored)
  if (cert.exp * 1000 > Date.now() + 30 * 24 * 60 * 60 * 1000) {
    // Valid for more than 30 days — use it.
    return useExistingCert(cert)
  }
  if (cert.exp * 1000 > Date.now()) {
    // Valid but close to expiry — try renewal in the background.
    void renewInBackground(cert)
    return useExistingCert(cert)
  }
  // Expired — must re-pair.
}
return startPairFlow()
```

### 2. Pair flow

Generate fresh keypairs (use a small crypto library like
`@noble/curves` — the same one Tower-web uses):

```typescript
import { ed25519, x25519 } from '@noble/curves/ed25519.js'

const edPriv = ed25519.utils.randomSecretKey()
const edPub  = ed25519.getPublicKey(edPriv)
const xPriv  = x25519.utils.randomSecretKey()
const xPub   = x25519.getPublicKey(xPriv)
```

Initiate:

```typescript
const begin = await fetch('https://tower.aviato.media/api/identity/clients/pair/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    appId: 'aviato-web',
    clientPubKey: base64url(edPub),
    clientEncPubKey: base64url(xPub),
    displayName: detectBrowserName(),
    platform: 'web',
  })
}).then((r) => r.json())

// begin = { requestId, code, expiresAt }
```

Display the code with a deep link to Tower-web:

```typescript
const pairUrl = `https://tower.aviato.media/pair?code=${begin.code}`
// Render as a clickable button + QR code; the user can either click
// straight through (if signed into Tower in the same browser session)
// or scan with their phone.
```

The user lands on `/pair?code=…`, signs into Tower (if they aren't
already), reviews "Aviato Web" with its name/icon/description, picks
which of their linked servers to expose, and approves.

### 3. Poll for completion

```typescript
async function pollForCert (requestId: string): Promise<CompletedResponse> {
  const deadline = Date.now() + 5 * 60 * 1000
  while (Date.now() < deadline) {
    const res = await fetch(`https://tower.aviato.media/api/identity/clients/pair/${requestId}`)
    const body = await res.json()
    if (body.state === 'completed') return body
    if (body.state === 'denied' || body.state === 'expired') {
      throw new PairFailed(body.state)
    }
    await sleep(2000)
  }
  throw new PairTimeout()
}
```

Note the endpoint is unauthenticated — the `requestId` (a UUID, 122 bits
of entropy) IS the capability. Don't log it; don't put it in URL bars
or analytics events.

### 4. Validate the cert + decrypt the bundle

Same shape as native clients (see `identity-client-app.md` §"Persist
the cert"). The cert payload's `clientEncPubKey` must match the
`base64url(xPub)` you generated, and `clientPubKey` must match
`base64url(edPub)`.

Decrypt the sealed K-bundle with `xPriv` (use the sealedbox primitive
documented in `identity-server-link.md` §"Cryptography reference").

### 5. Persist

```typescript
localStorage.setItem('aviato-cert', JSON.stringify({
  clientPriv:    base64url(edPriv),
  clientEncPriv: base64url(xPriv),
  signedCertBytes: completed.signedCertBytes,
  certSignature: completed.certSignature,
  clientId:      cert.clientId,
  exp:           cert.exp,
  iat:           cert.iat,
}))
localStorage.setItem('aviato-conn-keys', JSON.stringify({
  // serverPubKey (hex) → connInfoKey (base64url)
  [server.serverPubKey]: server.connInfoKey,
  // ...
}))
```

The user is now signed in. Subsequent media-server requests use the
cert + clientPriv to mint identity-session assertions (see
`identity-client-app.md` §"Connect to the server").

---

## Discovering a server

Identical to the native client flow. See `identity-client-app.md`
§"Discovering a server". The only web-specific note: prefer using
`fetch()` with `mode: 'cors'` (the endpoint sets permissive CORS for
the Tower web origin and is unauthenticated, so cross-origin reads
work).

---

## Cert renewal in a browser

You **can** call renewal from a tab:

```typescript
async function renewInBackground (cert: StoredCert) {
  const requestedAt = new Date().toISOString()
  const clientId    = await sha256Hex(base64urlDecode(cert.clientPriv).publicKey)
  const message     = JSON.stringify({ clientId, requestedAt })
  const signature   = base64url(await ed25519_sign(cert.clientPriv, utf8(message)))

  const res = await fetch(
    `https://tower.aviato.media/api/identity/clients/${clientId}/renew`,
    { method: 'POST', body: JSON.stringify({ requestedAt, signature }) }
  )
  if (res.status === 404) return // cert_not_available — re-pair on next sign-in
  if (!res.ok) throw new Error('renewal failed')
  const fresh = await res.json()
  // Persist the fresh cert; clientId + private keys unchanged.
}
```

**Limitations**:
- Renewal only happens while a tab is open. If users keep tabs short,
  re-pair will be the dominant refresh path.
- The cert must be pre-issued by Tower-web. The user signing into
  Tower-web (which they did when they paired) triggers pre-issuance;
  subsequent visits keep it fresh. If they haven't been to Tower-web
  in 11+ months, `/renew` returns 404 — fall back to re-pair.

**Recommended cadence**: try renewal at 30 days remaining; retry on
each app load while still in the renewal window.

---

## Sign out

To sign the user out of the web app:

```typescript
function signOut () {
  localStorage.removeItem('aviato-cert')
  localStorage.removeItem('aviato-conn-keys')
  // Optionally call POST /api/identity/revocations from a Tower-web
  // session to revoke the cert globally. This requires the user be
  // signed into Tower-web — usually done from their Tower dashboard.
}
```

Local sign-out only clears the browser's state; the cert remains
valid at media servers until expiry or until the user revokes from
their Tower dashboard. If sign-out should be global, surface a "manage
devices at Aviato Tower" link to `https://tower.aviato.media/dashboard/devices`.

---

## Multi-tab considerations

If a user signs in in one tab, other tabs should pick it up:

```typescript
window.addEventListener('storage', (e) => {
  if (e.key === 'aviato-cert') {
    if (e.newValue) reloadAuthState()    // signed in elsewhere
    else clearAuthState()                 // signed out elsewhere
  }
})
```

The `storage` event fires in all tabs of the origin except the one that
wrote. Use it to keep tabs in sync without polling.

---

## What NOT to do

- **Do not use sessionStorage for the cert.** It dies with the tab,
  forcing re-pair on every page reload.
- **Do not use cookies for clientPriv.** Cookies have no enforced
  encryption-at-rest in the browser and might be sent on cross-origin
  requests (depending on `SameSite`). localStorage is the right
  primitive for this credential material.
- **Do not implement your own crypto.** Use `@noble/curves` /
  `@noble/hashes` / WebCrypto. The sealedbox construction is documented
  in `identity-server-link.md` and a reference implementation lives in
  `packages/tower-web/src/lib/sealedbox.ts`.
- **Do not transmit K's anywhere.** They stay in localStorage and are
  used only for AEAD-decrypt of `server-conninfo` responses. Sending K
  to a server (yours or anyone else's) defeats the entire scheme.
- **Do not log `requestId` or `code`.** Both are short-lived
  capabilities; logging them creates a 5-minute window for replay /
  takeover.
- **Do not try to "share" a cert across origins.** If you have multiple
  web apps, each one pairs separately. The user's consent screen will
  tell them which app they're approving.

---

## Threat-model notes

A localStorage cert is materially less protected than an OS-keychain
cert. The user's revocation surface (the Tower dashboard's "Connected
Apps" page) is the recovery path:

| Threat                                           | Mitigation                                                              |
|--------------------------------------------------|--------------------------------------------------------------------------|
| XSS on your web app exfiltrates the cert         | Standard CSP + input sanitization; revoke the cert from Tower dashboard |
| Browser sync uploads the cert to another device  | User's choice; if they don't want it, they don't sync passwords/storage |
| Malicious extension reads localStorage           | Outside the threat model for any web app; revoke from Tower dashboard   |
| Cert exfiltrated, user wants to invalidate       | `/dashboard/devices` → revoke. CRL propagates to media servers.         |

The cert's authority is bounded by what the user approved at pair time
(the per-server checkboxes) and by its 1-year expiry. A compromised
cert can read media from approved servers; it cannot escalate to other
servers or to the user's master key.

---

## Implementation checklist

- [ ] Register `aviato-web` as an app at `tower.aviato.media/developer/apps`
- [ ] Generate Ed25519 + X25519 keypairs on first pair (use `@noble/curves`)
- [ ] localStorage layout: `aviato-cert` + `aviato-conn-keys`
- [ ] Pair flow: deep link to `/pair?code=…`, poll endpoint, validate
      cert + decrypt sealed bundle
- [ ] Discovery: hash → fetch → verify sig → AEAD-decrypt with K
- [ ] Background renewal at ≤30 days remaining (best-effort)
- [ ] AEAD-decrypt failure → prompt re-pair (server rotated K)
- [ ] `storage` event listener for multi-tab sync
- [ ] "Manage devices" link to `tower.aviato.media/dashboard/devices`
- [ ] Sign-out clears local state; document that global revocation
      requires the Tower dashboard
- [ ] CSP header excludes `unsafe-inline` and pins script-src to known
      origins (defense against XSS exfiltrating cert)
