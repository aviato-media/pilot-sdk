// Tests for the expanded orchestration surface: subscribe, hydrate,
// initializeAllConnections, renewCertIfNeeded, signOut, getConnections.

import type { Ed25519Keypair } from '@aviato-media/pilot-core'
import {
  base64urlEncode,
  buildClientCert,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
  randomAesKey,
  sealServerConnInfo,
  verifySessionAssertion,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import {
  AviatoPilotClient,
  MemoryStorageBackend,
  type ServerConnection,
} from '../src/index.js'

function makeCertFor (user: Ed25519Keypair, opts: {
  clientPubHex: string
  clientEncPubHex: string
  userEncPubHex: string
  exp?: number
  iat?: number
} = {
  clientEncPubHex: '',
  clientPubHex: '',
  userEncPubHex: '',
}) {
  const nowSec = Math.floor(Date.now() / 1000)
  return buildClientCert({
    masterPrivKey: user.privateKey,
    payload: {
      appId: 'aviato-web',
      clientEncPubKey: opts.clientEncPubHex,
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPubKey: opts.clientPubHex,
      deviceName: 'Test',
      exp: opts.exp ?? nowSec + 86400 * 60,
      iat: opts.iat ?? nowSec,
      scope: ['identity'],
      userEncPubKey: opts.userEncPubHex,
      userId: 'user_test',
      userPubKey: hexEncode(user.publicKey),
      v: 1,
    },
  })
}

describe('AviatoPilotClient orchestration', () => {
  test('subscribe receives snapshots and unsubscribe stops them', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    const snapshots: ReadonlyArray<ServerConnection>[] = []
    const unsub = client.subscribe((s) => {
      snapshots.push(s)
    })

    await client.signOut() // triggers an emit
    expect(snapshots.length).toBeGreaterThanOrEqual(1)

    unsub()
    const before = snapshots.length
    await client.signOut()
    expect(snapshots.length).toBe(before)
  })

  test('getConnections returns reference-stable snapshot across reads', () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    const r1 = client.getConnections()
    const r2 = client.getConnections()
    const r3 = client.getConnections()
    // Reference equality is what React's useSyncExternalStore uses to skip
    // no-op renders. Returning a fresh array each call caused infinite
    // re-render loops in consumer components.
    expect(r1 === r2).toBe(true)
    expect(r2 === r3).toBe(true)
  })

  test('emit invalidates the cached snapshot', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    const before = client.getConnections()
    await client.signOut() // mutates → emit → invalidates the cached snapshot
    const after = client.getConnections()
    expect(after === before).toBe(false)
  })

  test('subscribers receive the same snapshot reference that getConnections returns', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    let received: ReadonlyArray<ServerConnection> | null = null
    client.subscribe((snapshot) => {
      received = snapshot
    })
    await client.signOut()
    expect(received).not.toBeNull()
    // The subscriber's snapshot MUST be the same reference React's next
    // getSnapshot() call will see — otherwise useSyncExternalStore tears
    // during concurrent rendering.
    expect(received === client.getConnections()).toBe(true)
  })

  test('listener errors do not break sibling listeners', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    let goodCount = 0
    client.subscribe(() => {
      throw new Error('boom')
    })
    client.subscribe(() => {
      goodCount += 1
    })
    await client.signOut()
    expect(goodCount).toBe(1)
  })

  test('hydrate seeds connection slots as idle', async () => {
    const storage = new MemoryStorageBackend()
    await storage.setIdentity({
      certSignature: 'sig',
      clientEncPrivBase64url: base64urlEncode(new Uint8Array(32)),
      clientId: 'cid',
      clientPrivBase64url: base64urlEncode(new Uint8Array(32)),
      exp: 9_999_999_999,
      iat: 0,
      signedCertBytes: 'bytes',
      userPubKey: 'a'.repeat(64),
    })
    await storage.setBundle({
      issuedAtSec: 1,
      servers: [
        {
          connInfoKey: 'k1',
          serverPubKey: 'a'.repeat(64),
        },
        {
          connInfoKey: 'k2',
          serverPubKey: 'b'.repeat(64),
        },
      ],
    })
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    const had = await client.hydrate()
    expect(had).toBe(true)
    const conns = client.getConnections()
    expect(conns).toHaveLength(2)
    expect(conns.every((c) => c.status.state === 'idle')).toBe(true)
  })

  test('hydrate returns false when no identity', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    expect(await client.hydrate()).toBe(false)
    expect(client.getConnections()).toHaveLength(0)
  })

  test('initializeAllConnections probes each server in parallel; per-server failure isolated', async () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const clientSig = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const serverOnline = generateEd25519Keypair()
    const serverOffline = generateEd25519Keypair()
    const serverOnlineHex = hexEncode(serverOnline.publicKey)
    const serverOfflineHex = hexEncode(serverOffline.publicKey)
    const K = randomAesKey()
    const nowSec = Math.floor(Date.now() / 1000)

    const conninfo = await sealServerConnInfo({
      connInfoKey: K,
      payload: {
        issuedAtSec: nowSec,
        port: 443,
        protocol: 'https',
        publicHost: 'media.up',
        rotationCounter: 1,
        v: 1,
      },
      serverPrivKey: serverOnline.privateKey,
      serverPubKey: serverOnline.publicKey,
      version: 1,
    })

    let challengeIssued: string | null = null

    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'

      if (url.includes('/api/identity/server-conninfo/') && method === 'GET') {
        // Online server publishes; offline returns 404.
        const onlineHash = await import('../src/server-conninfo.js').then((m) => m.deriveServerConnInfoHash(serverOnline.publicKey))
        if (url.endsWith(onlineHash)) {
          return new Response(JSON.stringify({
            ...conninfo,
            lastUpdatedAtSec: nowSec,
          }), { status: 200 })
        }
        return new Response(null, { status: 404 })
      }
      if (url.endsWith('/api/auth/identity-session/begin') && method === 'POST') {
        challengeIssued = 'cafef00d'
        return new Response(JSON.stringify({ challenge: challengeIssued }), { status: 200 })
      }
      if (url.endsWith('/api/auth/identity-session/complete') && method === 'POST') {
        const assertion = JSON.parse(init!.body as string)
        const v = verifySessionAssertion(assertion, {
          challenge: challengeIssued!,
          serverPubKey: serverOnline.publicKey,
        })
        if (!v.ok) {
          return new Response(JSON.stringify({ error: v.error }), { status: 401 })
        }
        return new Response(JSON.stringify({
          expiresAt: '2099-01-01T00:00:00.000Z',
          token: 'tok_online',
        }), { status: 200 })
      }
      throw new Error(`unexpected fetch: ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    const cert = makeCertFor(user, {
      clientEncPubHex: hexEncode(clientEnc.publicKey),
      clientPubHex: hexEncode(clientSig.publicKey),
      userEncPubHex: hexEncode(userEnc.publicKey),
    })

    const storage = new MemoryStorageBackend()
    await storage.setIdentity({
      certSignature: cert.sig,
      clientEncPrivBase64url: clientEnc.privateKey.toBase64Url(),
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPrivBase64url: clientSig.privateKey.toBase64Url(),
      exp: nowSec + 86400 * 60,
      iat: nowSec,
      signedCertBytes: cert.payload,
      userPubKey: hexEncode(user.publicKey),
    })
    await storage.setBundle({
      issuedAtSec: nowSec,
      servers: [
        {
          connInfoKey: base64urlEncode(K),
          serverPubKey: serverOnlineHex,
        },
        {
          connInfoKey: base64urlEncode(randomAesKey()),
          serverPubKey: serverOfflineHex,
        },
      ],
    })

    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    await client.hydrate()
    await client.initializeAllConnections()

    const online = client.getConnection(serverOnlineHex)
    const offline = client.getConnection(serverOfflineHex)
    expect(online?.status.state).toBe('online')
    expect(offline?.status.state).toBe('offline')
  })

  test('renewCertIfNeeded returns not-needed when cert still fresh', async () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const clientSig = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const cert = makeCertFor(user, {
      clientEncPubHex: hexEncode(clientEnc.publicKey),
      clientPubHex: hexEncode(clientSig.publicKey),
      userEncPubHex: hexEncode(userEnc.publicKey),
    })
    const storage = new MemoryStorageBackend()
    const nowSec = Math.floor(Date.now() / 1000)
    await storage.setIdentity({
      certSignature: cert.sig,
      clientEncPrivBase64url: clientEnc.privateKey.toBase64Url(),
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPrivBase64url: clientSig.privateKey.toBase64Url(),
      exp: nowSec + 86400 * 90, // 90 days out
      iat: nowSec,
      signedCertBytes: cert.payload,
      userPubKey: hexEncode(user.publicKey),
    })
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => {
        throw new Error('should not fetch')
      }) as unknown as typeof globalThis.fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    expect(await client.renewCertIfNeeded(30)).toBe('not-needed')
  })

  test('renewCertIfNeeded returns unavailable when no identity', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    expect(await client.renewCertIfNeeded()).toBe('unavailable')
  })

  test('renewCertIfNeeded renews when cert is close to expiry', async () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const clientSig = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const nowSec = Math.floor(Date.now() / 1000)

    const oldCert = makeCertFor(user, {
      clientEncPubHex: hexEncode(clientEnc.publicKey),
      clientPubHex: hexEncode(clientSig.publicKey),
      exp: nowSec + 86400 * 5, // 5 days out — well under default 30
      iat: nowSec - 86400 * 60,
      userEncPubHex: hexEncode(userEnc.publicKey),
    })
    const newCert = makeCertFor(user, {
      clientEncPubHex: hexEncode(clientEnc.publicKey),
      clientPubHex: hexEncode(clientSig.publicKey),
      exp: nowSec + 86400 * 60, // fresh 60-day cert
      iat: nowSec,
      userEncPubHex: hexEncode(userEnc.publicKey),
    })

    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.includes('/api/identity/clients/') && url.endsWith('/renew') && init?.method === 'POST') {
        return new Response(JSON.stringify({
          certSignature: newCert.sig,
          clientId: '00000000-0000-4000-8000-000000000abc',
          expiresAt: new Date((nowSec + 86400 * 60) * 1000).toISOString(),
          signedCertBytes: newCert.payload,
        }), { status: 200 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }) as unknown as typeof globalThis.fetch

    const storage = new MemoryStorageBackend()
    await storage.setIdentity({
      certSignature: oldCert.sig,
      clientEncPrivBase64url: clientEnc.privateKey.toBase64Url(),
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPrivBase64url: clientSig.privateKey.toBase64Url(),
      exp: nowSec + 86400 * 5,
      iat: nowSec - 86400 * 60,
      signedCertBytes: oldCert.payload,
      userPubKey: hexEncode(user.publicKey),
    })
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    const result = await client.renewCertIfNeeded(30)
    expect(result).toBe('renewed')
    const updated = await storage.getIdentity()
    expect(updated?.signedCertBytes).toBe(newCert.payload)
    expect(updated?.exp).toBeGreaterThan(nowSec + 86400 * 50)
  })

  test('signOut clears identity, bundle, tokens, and connections', async () => {
    const storage = new MemoryStorageBackend()
    await storage.setIdentity({
      certSignature: 'sig',
      clientEncPrivBase64url: base64urlEncode(new Uint8Array(32)),
      clientId: 'cid',
      clientPrivBase64url: base64urlEncode(new Uint8Array(32)),
      exp: 9_999_999_999,
      iat: 0,
      signedCertBytes: 'bytes',
      userPubKey: 'a'.repeat(64),
    })
    await storage.setBundle({
      issuedAtSec: 1,
      servers: [{
        connInfoKey: 'k',
        serverPubKey: 'a'.repeat(64),
      }],
    })
    await storage.setServerToken('a'.repeat(64), {
      expiresAt: 'iso',
      token: 't',
    })

    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    await client.hydrate()
    expect(client.getConnections()).toHaveLength(1)

    await client.signOut()
    expect(await storage.getIdentity()).toBeNull()
    expect(await storage.getBundle()).toBeNull()
    expect(await storage.getServerToken('a'.repeat(64))).toBeNull()
    expect(client.getConnections()).toHaveLength(0)
  })
})
