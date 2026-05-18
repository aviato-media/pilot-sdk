// Additional coverage:
//  - util.clientIdFromPub
//  - LocalStorageBackend (via a tiny in-memory localStorage stub)
//  - resolveServerConnInfo error branches
//  - serverCertAuth error branches (HTTP / shape / sig / refreshedConnInfoKey)

import type { PublicKeyLike } from '@aviato-media/pilot-core'
import {
  aviatoSealedBoxEncrypt,
  base64urlDecode,
  base64urlEncode,
  buildClientCert,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
  jcs,
  randomAesKey,
  sealServerConnInfo,
} from '@aviato-media/pilot-core'
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test'

import { clientIdFromPub } from '../src/index.js'
import { ServerAuthError, serverCertAuth } from '../src/server-cert-auth.js'
import {
  deriveServerConnInfoHash,
  resolveServerConnInfo,
} from '../src/server-conninfo.js'
import {
  LocalStorageBackend,
  MemoryStorageBackend,
} from '../src/storage.js'
import { TowerClient } from '../src/tower-client.js'

// Inline minimal session-envelope sealer so this test file doesn't depend
// on the server-sdk (different workspace package). Matches the wire shape
// SessionConnInfoEnvelopeSchema expects.
async function sealSessionEnvelope (input: { clientEncPubKey: PublicKeyLike,
  connInfoKey: Uint8Array }) {
  return aviatoSealedBoxEncrypt({
    plaintext: jcs({
      connInfoKey: base64urlEncode(input.connInfoKey),
      issuedAtSec: Math.floor(Date.now() / 1000),
      v: 1,
    }),
    recipientPub: input.clientEncPubKey,
  })
}

// ── localStorage stub ────────────────────────────────────────────────
//
// Bun's runtime has no `localStorage` by default. A tiny in-memory shim
// covers the API surface LocalStorageBackend needs.

class FakeLocalStorage implements Storage {
  private store = new Map<string, string>()
  get length (): number {
    return this.store.size
  }

  clear (): void {
    this.store.clear()
  }

  getItem (key: string): string | null {
    return this.store.get(key) ?? null
  }

  key (i: number): string | null {
    return Array.from(this.store.keys())[i] ?? null
  }

  removeItem (key: string): void {
    this.store.delete(key)
  }

  setItem (key: string, value: string): void {
    this.store.set(key, value)
  }
}

let fakeLs: FakeLocalStorage
beforeAll(() => {
  fakeLs = new FakeLocalStorage()
  ;(globalThis as { localStorage?: Storage }).localStorage = fakeLs
})
afterAll(() => {
  delete (globalThis as { localStorage?: Storage }).localStorage
})
beforeEach(() => {
  fakeLs.clear()
})

// ── util ─────────────────────────────────────────────────────────────

describe('clientIdFromPub', () => {
  test('deterministic 32-hex-char output for a given pubkey', () => {
    const { publicKey } = generateEd25519Keypair()
    const a = clientIdFromPub(hexEncode(publicKey))
    const b = clientIdFromPub(hexEncode(publicKey))
    expect(a).toBe(b)
    expect(a).toMatch(/^[0-9a-f]{32}$/)
  })
  test('different pubkeys yield different ids', () => {
    const a = generateEd25519Keypair()
    const b = generateEd25519Keypair()
    expect(clientIdFromPub(hexEncode(a.publicKey))).not.toBe(clientIdFromPub(hexEncode(b.publicKey)))
  })
})

// ── LocalStorageBackend ──────────────────────────────────────────────

describe('LocalStorageBackend', () => {
  test('identity round-trip + null deletes the row', async () => {
    const ls = new LocalStorageBackend()
    expect(await ls.getIdentity()).toBeNull()
    const identity = {
      certSignature: 'sig',
      clientEncPrivBase64url: 'enc',
      clientId: 'cid',
      clientPrivBase64url: 'priv',
      exp: 1,
      iat: 0,
      signedCertBytes: 'cert',
      userPubKey: hexEncode(new Uint8Array(32).fill(0xaa)),
    }
    await ls.setIdentity(identity)
    expect(await ls.getIdentity()).toEqual(identity)
    await ls.setIdentity(null)
    expect(await ls.getIdentity()).toBeNull()
  })

  test('bundle + upsertServerKey insert-then-replace', async () => {
    const ls = new LocalStorageBackend()
    expect(await ls.getBundle()).toBeNull()
    await ls.setBundle({
      issuedAtSec: 100,
      servers: [{
        connInfoKey: 'K1',
        serverPubKey: 'a'.repeat(64),
      }],
    })
    const a = await ls.getBundle()
    expect(a?.servers).toHaveLength(1)
    // Upserting same serverPubKey replaces in place
    await ls.upsertServerKey({
      connInfoKey: 'K2',
      serverPubKey: 'a'.repeat(64),
    })
    const b = await ls.getBundle()
    expect(b?.servers).toHaveLength(1)
    expect(b?.servers[0]!.connInfoKey).toBe('K2')
    // Upserting a different server appends
    await ls.upsertServerKey({
      connInfoKey: 'K3',
      serverPubKey: 'b'.repeat(64),
    })
    const c = await ls.getBundle()
    expect(c?.servers).toHaveLength(2)
  })

  test('upsertServerKey creates the bundle from nothing when none exists', async () => {
    const ls = new LocalStorageBackend()
    await ls.upsertServerKey({
      connInfoKey: 'K',
      serverPubKey: 'c'.repeat(64),
    })
    const b = await ls.getBundle()
    expect(b?.servers).toHaveLength(1)
    expect(typeof b?.issuedAtSec).toBe('number')
  })

  test('server token round-trip + null deletes', async () => {
    const ls = new LocalStorageBackend()
    const pub = 'd'.repeat(64)
    expect(await ls.getServerToken(pub)).toBeNull()
    await ls.setServerToken(pub, {
      expiresAt: '2099-01-01T00:00:00.000Z',
      token: 'session_xyz',
    })
    expect(await ls.getServerToken(pub)).toEqual({
      expiresAt: '2099-01-01T00:00:00.000Z',
      token: 'session_xyz',
    })
    await ls.setServerToken(pub, null)
    expect(await ls.getServerToken(pub)).toBeNull()
  })

  test('corrupted JSON in localStorage returns null (does not throw)', async () => {
    const ls = new LocalStorageBackend()
    fakeLs.setItem('aviato:pilot:identity:v1', 'not valid json {')
    expect(await ls.getIdentity()).toBeNull()
  })

  test('setBundle(null) deletes the bundle row', async () => {
    const ls = new LocalStorageBackend()
    await ls.setBundle({
      issuedAtSec: 1,
      servers: [],
    })
    expect(await ls.getBundle()).not.toBeNull()
    await ls.setBundle(null)
    expect(await ls.getBundle()).toBeNull()
  })
})

// ── MemoryStorageBackend cross-check (re-runs to count) ──────────────

describe('MemoryStorageBackend (cross-check)', () => {
  test('upsertServerKey from a fresh backend creates the bundle', async () => {
    const m = new MemoryStorageBackend()
    await m.upsertServerKey({
      connInfoKey: 'K',
      serverPubKey: 'e'.repeat(64),
    })
    const b = await m.getBundle()
    expect(b?.servers).toHaveLength(1)
  })
})

// ── resolveServerConnInfo error branches ─────────────────────────────

describe('resolveServerConnInfo error branches', () => {
  function makeTower (record: unknown) {
    const mockFetch = (async () =>
      new Response(JSON.stringify(record), { status: 200 })) as unknown as typeof globalThis.fetch
    return new TowerClient({
      baseUrl: 'https://tower.test',
      fetch: mockFetch,
    })
  }
  function makeNotFoundTower () {
    const mockFetch = (async () => new Response(null, { status: 404 })) as unknown as typeof globalThis.fetch
    return new TowerClient({
      baseUrl: 'https://tower.test',
      fetch: mockFetch,
    })
  }

  test('not_found when Tower returns null', async () => {
    const r = await resolveServerConnInfo({
      connInfoKey: randomAesKey(),
      serverPubKey: new Uint8Array(32).fill(0xaa),
      tower: makeNotFoundTower(),
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('not_found')
    }
  })

  test('tower_sig_invalid when sig is tampered', async () => {
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const sealed = await sealServerConnInfo({
      connInfoKey: K,
      payload: {
        issuedAtSec: 1,
        port: 443,
        protocol: 'https',
        publicHost: 'media.test',
        rotationCounter: 1,
        v: 1,
      },
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      version: 1,
    })
    // Tamper the sig.
    const sigBytes = base64urlDecode(sealed.sig)
    sigBytes[0] = sigBytes[0]! ^ 0xff
    const tampered = {
      ...sealed,
      lastUpdatedAtSec: 1,
      sig: base64urlEncode(sigBytes),
    }
    const r = await resolveServerConnInfo({
      connInfoKey: K,
      serverPubKey: server.publicKey,
      tower: makeTower(tampered),
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('tower_sig_invalid')
    }
  })

  test('stale_k_or_decrypt_failed when K is wrong', async () => {
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const sealed = await sealServerConnInfo({
      connInfoKey: K,
      payload: {
        issuedAtSec: 1,
        port: 443,
        protocol: 'https',
        publicHost: 'media.test',
        rotationCounter: 1,
        v: 1,
      },
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      version: 1,
    })
    const r = await resolveServerConnInfo({
      connInfoKey: randomAesKey(), // wrong K
      serverPubKey: server.publicKey,
      tower: makeTower({
        ...sealed,
        lastUpdatedAtSec: 1,
      }),
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('stale_k_or_decrypt_failed')
    }
  })

  test('deriveServerConnInfoHash accepts hex string + bytes + PublicKey', () => {
    const server = generateEd25519Keypair()
    const fromBytes = deriveServerConnInfoHash(server.publicKey)
    const fromHex = deriveServerConnInfoHash(hexEncode(server.publicKey))
    expect(fromBytes).toBe(fromHex)
  })
})

// ── serverCertAuth error branches ────────────────────────────────────

describe('serverCertAuth error branches', () => {
  function makeFixtures () {
    const user = generateEd25519Keypair()
    const client = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const nowSec = Math.floor(Date.now() / 1000)
    const cert = buildClientCert({
      masterPrivKey: user.privateKey,
      payload: {
        appId: 'aviato-web',
        clientEncPubKey: hexEncode(clientEnc.publicKey),
        clientId: '00000000-0000-4000-8000-000000000099',
        clientPubKey: hexEncode(client.publicKey),
        deviceName: 'T',
        exp: nowSec + 3600,
        iat: nowSec,
        scope: ['identity'],
        userEncPubKey: hexEncode(new Uint8Array(32).fill(0xee)),
        userId: 'u',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    return {
      cert,
      client,
      clientEnc,
      server,
      user,
    }
  }

  test('ServerAuthError exposes code + status', () => {
    const err = new ServerAuthError('boom', 'http', 401)
    expect(err.code).toBe('http')
    expect(err.status).toBe(401)
    expect(err.message).toBe('boom')
    expect(err.name).toBe('ServerAuthError')
  })

  test('begin returns non-200 → ServerAuthError(http, status)', async () => {
    const f = makeFixtures()
    const mockFetch = (async () => new Response('nope', { status: 503 })) as unknown as typeof globalThis.fetch
    await expect(serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })).rejects.toThrow(/begin: 503/)
  })

  test('begin returns missing challenge → ServerAuthError(shape)', async () => {
    const f = makeFixtures()
    const mockFetch = (async () =>
      new Response(JSON.stringify({ notChallenge: 'oops' }), { status: 200 })) as unknown as typeof globalThis.fetch
    await expect(serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })).rejects.toThrow(/missing\/invalid challenge/)
  })

  test('complete returns non-200 → ServerAuthError(http, status)', async () => {
    const f = makeFixtures()
    const mockFetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/begin')) {
        return new Response(JSON.stringify({ challenge: 'aabb' }), { status: 200 })
      }
      return new Response('nope', { status: 401 })
    }) as unknown as typeof globalThis.fetch
    await expect(serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })).rejects.toThrow(/complete: 401/)
  })

  test('complete missing token/expiresAt → ServerAuthError(shape)', async () => {
    const f = makeFixtures()
    const mockFetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/begin')) {
        return new Response(JSON.stringify({ challenge: 'aabb' }), { status: 200 })
      }
      return new Response(JSON.stringify({}), { status: 200 })
    }) as unknown as typeof globalThis.fetch
    await expect(serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })).rejects.toThrow(/missing token\/expiresAt/)
  })

  test('happy path with refreshedConnInfoKey populates the field', async () => {
    const f = makeFixtures()
    const refreshedK = randomAesKey()
    const envelope = await sealSessionEnvelope({
      clientEncPubKey: f.clientEnc.publicKey,
      connInfoKey: refreshedK,
    })
    const mockFetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/begin')) {
        return new Response(JSON.stringify({ challenge: 'aabbccdd' }), { status: 200 })
      }
      return new Response(JSON.stringify({
        aviato_conn_info_key_envelope: envelope,
        expiresAt: '2099-01-01T00:00:00.000Z',
        token: 'tok',
      }), { status: 200 })
    }) as unknown as typeof globalThis.fetch
    const result = await serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })
    expect(result.token).toBe('tok')
    expect(result.refreshedConnInfoKey).not.toBeUndefined()
    expect(result.refreshedConnInfoKey!.connInfoKey).toBe(base64urlEncode(refreshedK))
  })

  test('non-hex challenge rejected as shape error', async () => {
    const f = makeFixtures()
    const mockFetch = (async () =>
      new Response(JSON.stringify({ challenge: 'not-hex!' }), { status: 200 })) as unknown as typeof globalThis.fetch
    await expect(serverCertAuth({
      baseUrl: 'https://media.test',
      cert: f.cert,
      clientEncPrivKey: f.clientEnc.privateKey,
      clientPrivKey: f.client.privateKey,
      fetch: mockFetch,
      serverPubKey: f.server.publicKey,
    })).rejects.toThrow(/missing\/invalid challenge/)
  })
})

describe('TowerApiError', () => {
  test('carries status + body alongside the message', async () => {
    const { TowerApiError } = await import('../src/tower-client.js')
    const err = new TowerApiError('rate limited', 429, { detail: 'slow down' })
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('TowerApiError')
    expect(err.message).toBe('rate limited')
    expect(err.status).toBe(429)
    expect(err.body).toEqual({ detail: 'slow down' })
  })

  test('body is optional', async () => {
    const { TowerApiError } = await import('../src/tower-client.js')
    const err = new TowerApiError('boom', 500)
    expect(err.status).toBe(500)
    expect(err.body).toBeUndefined()
  })
})

describe('resolveServerConnInfo shape_invalid branch', () => {
  test('returns shape_invalid when AEAD opens but the inner payload fails schema', async () => {
    // Construct a record where the AEAD plaintext is JSON but not a valid
    // ServerConnInfoPayload (missing required fields). openServerConnInfo
    // returns payload_shape_invalid; resolveServerConnInfo maps that to
    // shape_invalid.
    const { base64urlEncode: b64u, ENCODER, ed25519Sign, generateEd25519Keypair, hexEncode, randomAesKey, sha256Bytes } = await import('@aviato-media/pilot-core')
    const { aesGcmEncrypt } = await import('@aviato-media/pilot-core')
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const version = 1
    const serverPubKeyHex = hexEncode(server.publicKey)
    // Build the AAD the same way conn-info/aad.ts does.
    const aadPrefix = ENCODER.encode('aviato-server-conninfo-v1')
    const aadHex = ENCODER.encode(serverPubKeyHex)
    const u64BE = (n: number) => {
      const out = new Uint8Array(8)
      let v = BigInt(n)
      for (let i = 7; i >= 0; i--) {
        out[i] = Number(v & 0xffn)
        v >>= 8n
      }
      return out
    }
    const aad = new Uint8Array(aadPrefix.length + aadHex.length + 8)
    aad.set(aadPrefix, 0)
    aad.set(aadHex, aadPrefix.length)
    aad.set(u64BE(version), aadPrefix.length + aadHex.length)
    // Plaintext is JSON but missing required schema fields.
    const plaintext = ENCODER.encode(JSON.stringify({ not: 'a valid payload' }))
    const { ct, nonce } = await aesGcmEncrypt(K, plaintext, aad)
    const canonical = ENCODER.encode(JSON.stringify({
      ct: b64u(ct),
      nonce: b64u(nonce),
      serverPubKey: serverPubKeyHex,
      version,
    }))
    const sig = ed25519Sign(canonical, server.privateKey.toRaw())
    const record = {
      ct: b64u(ct),
      lastUpdatedAtSec: Math.floor(Date.now() / 1000),
      nonce: b64u(nonce),
      serverPubKey: serverPubKeyHex,
      sig: b64u(sig),
      version,
    }
    const hash = b64u(sha256Bytes(server.publicKey.toRaw()))
    const towerMock: { fetchServerConnInfo: (h: string) => Promise<unknown> } = {
      fetchServerConnInfo: async (h: string) => h === hash ? record : null,
    }
    const { resolveServerConnInfo } = await import('../src/server-conninfo.js')
    const r = await resolveServerConnInfo({
      connInfoKey: K,
      serverPubKey: server.publicKey,
      tower: towerMock as Parameters<typeof resolveServerConnInfo>[0]['tower'],
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('shape_invalid')
    }
  })
})
