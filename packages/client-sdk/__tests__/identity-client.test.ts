// End-to-end pair + sign-in test using mocked Tower + media server fetch.
//
// Walks the full happy path:
//   1. beginPair() → Tower returns code + requestId; we capture the SDK's
//      clientPubKey + clientEncPubKey from the begin body.
//   2. Tower-web side (simulated): build a cert binding those pub keys to
//      the user's master key, seal a K bundle to the client's encPub.
//   3. Polling returns `completed` → SDK finalizes pair → identity in storage.
//   4. signInToServer() → SDK fetches conn-info from Tower (we publish it
//      under K), then talks to the (mocked) media server's session
//      begin+complete endpoints. Server verifies the assertion against
//      the SDK's cert+keys.

import {
  base64urlDecode,
  base64urlEncode,
  buildClientCert,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
  randomAesKey,
  sealClientBundle,
  sealServerConnInfo,
  verifySessionAssertion,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { AviatoPilotClient } from '../src/identity-client.js'
import { deriveServerConnInfoHash } from '../src/server-conninfo.js'
import { MemoryStorageBackend } from '../src/storage.js'

describe('AviatoPilotClient end-to-end', () => {
  test('pair then sign-in', async () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const serverPubHex = hexEncode(server.publicKey)
    const K = randomAesKey()
    const nowSec = Math.floor(Date.now() / 1000)
    const userPubHex = hexEncode(user.publicKey)
    const userEncPubHex = hexEncode(userEnc.publicKey)

    let capturedClientPubHex: string | null = null
    let capturedClientEncPubHex: string | null = null
    let pollCalls = 0
    let challengeIssued: string | null = null

    // Pre-build the published conn-info row — the SDK will fetch this.
    const conninfo = await sealServerConnInfo({
      connInfoKey: K,
      payload: {
        issuedAtSec: nowSec,
        port: 8443,
        protocol: 'https',
        publicHost: 'media.test',
        rotationCounter: 1,
        v: 1,
      },
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      version: 1,
    })

    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'

      // ── Tower endpoints ──
      if (url.endsWith('/api/identity/clients/pair/begin') && method === 'POST') {
        const body = JSON.parse(init!.body as string) as { clientPubKey: string,
          clientEncPubKey: string }
        capturedClientPubHex = hexEncode(base64urlDecode(body.clientPubKey))
        capturedClientEncPubHex = hexEncode(base64urlDecode(body.clientEncPubKey))
        return new Response(JSON.stringify({
          code: '12345678',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_test',
        }), { status: 200 })
      }

      if (url.includes('/api/identity/clients/pair/req_test') && method === 'GET') {
        pollCalls += 1
        if (pollCalls === 1) {
          return new Response(JSON.stringify({
            expiresAt: '2099-01-01T00:00:00.000Z',
            requestId: 'req_test',
            state: 'pending',
          }), { status: 200 })
        }
        // Tower-web side: now we have the SDK's pubs, build the cert.
        const cert = buildClientCert({
          masterPrivKey: user.privateKey,
          payload: {
            appId: 'aviato-web',
            clientEncPubKey: capturedClientEncPubHex!,
            clientId: '00000000-0000-4000-8000-000000000001',
            clientPubKey: capturedClientPubHex!,
            deviceName: 'Test Device',
            exp: nowSec + 86400 * 60,
            iat: nowSec,
            scope: ['identity'],
            userEncPubKey: userEncPubHex,
            userId: 'user_test',
            userPubKey: userPubHex,
            v: 1,
          },
        })
        const bundle = await sealClientBundle({
          bundle: {
            issuedAtSec: nowSec,
            servers: [{
              connInfoKey: base64urlEncode(K),
              serverPubKey: serverPubHex,
            }],
            v: 1,
          },
          clientEncPubKey: base64urlDecode(base64urlEncode(
            // round-trip: capturedClientEncPubHex back to bytes
            new Uint8Array(capturedClientEncPubHex!.match(/.{2}/g)!.map((h) => parseInt(h, 16))),
          )),
        })
        return new Response(JSON.stringify({
          certSignature: cert.sig,
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_test',
          sealedConnInfoBundle: bundle,
          signedCertBytes: cert.payload,
          state: 'completed',
        }), { status: 200 })
      }

      if (url.includes('/api/identity/server-conninfo/') && method === 'GET') {
        return new Response(JSON.stringify({
          ...conninfo,
          lastUpdatedAtSec: nowSec,
        }), { status: 200 })
      }

      // ── Media server endpoints ──
      if (url.endsWith('/api/auth/identity-session/begin') && method === 'POST') {
        challengeIssued = `aabbccdd${ Math.floor(Math.random() * 1e8).toString(16).padStart(8, '0')}`
        return new Response(JSON.stringify({ challenge: challengeIssued }), { status: 200 })
      }
      if (url.endsWith('/api/auth/identity-session/complete') && method === 'POST') {
        const assertion = JSON.parse(init!.body as string)
        const verified = verifySessionAssertion(assertion, {
          challenge: challengeIssued!,
          serverPubKey: server.publicKey,
        })
        if (!verified.ok) {
          return new Response(JSON.stringify({ error: verified.error }), { status: 401 })
        }
        return new Response(JSON.stringify({
          expiresAt: '2099-01-01T00:00:00.000Z',
          token: 'session_token_xyz',
        }), { status: 200 })
      }

      throw new Error(`unexpected fetch: ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test Device',
      fetch: mockFetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })

    expect(await client.hasIdentity()).toBe(false)

    const handle = await client.beginPair({ pollIntervalMs: 1 })
    expect(handle.code).toBe('12345678')

    const identity = await handle.await()
    expect(identity.clientId).toBe('00000000-0000-4000-8000-000000000001')
    expect(identity.userPubKey).toBe(userPubHex)
    expect(await client.hasIdentity()).toBe(true)

    const conn = await client.signInToServer({ serverPubKey: server.publicKey })
    expect(conn.status.state).toBe('online')
    if (conn.status.state === 'online') {
      expect(conn.status.sessionToken).toBe('session_token_xyz')
      expect(conn.status.baseUrl).toBe('https://media.test:8443')
    }
  })

  test('signInToServer returns unauthorized for unknown server', async () => {
    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test Device',
      fetch: (() => Promise.reject(new Error('should not fetch'))) as unknown as typeof globalThis.fetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    await client.beginPair({}).then((h) => h.cancel()).catch(() => undefined)

    // populate a fake identity so hasIdentity is true
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
    const c2 = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: (() => Promise.reject(new Error('should not fetch'))) as unknown as typeof globalThis.fetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    const result = await c2.signInToServer({ serverPubKey: new Uint8Array(32).fill(0xbb) })
    expect(result.status.state).toBe('unauthorized')
  })

  test('beginPair exposes pairingUrl built from towerWebUrl', async () => {
    const mockFetch = (async () => new Response(JSON.stringify({
      code: '00112233',
      expiresAt: '2099-01-01T00:00:00.000Z',
      requestId: 'req_url',
    }), { status: 200 })) as unknown as typeof globalThis.fetch

    const c1 = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: mockFetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    const h1 = await c1.beginPair({})
    h1.cancel()
    expect(h1.pairingUrl).toBe('https://tower.test/pair?code=00112233')

    const c2 = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      fetch: mockFetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://api.tower.test',
      towerWebUrl: 'https://www.tower.test/',
    })
    const h2 = await c2.beginPair({})
    h2.cancel()
    expect(h2.pairingUrl).toBe('https://www.tower.test/pair?code=00112233')
  })

  test('deriveServerConnInfoHash matches sha256(serverPubKey).base64url', () => {
    const hash = deriveServerConnInfoHash(new Uint8Array(32).fill(0xaa))
    // 32 bytes → base64url 43 chars (no padding)
    expect(hash).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  test('finalizePair rejects cert minted for a different appId', async () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const nowSec = Math.floor(Date.now() / 1000)
    const userPubHex = hexEncode(user.publicKey)
    const userEncPubHex = hexEncode(userEnc.publicKey)

    let capturedClientPubHex: string | null = null
    let capturedClientEncPubHex: string | null = null
    let pollCalls = 0

    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'
      if (url.endsWith('/api/identity/clients/pair/begin') && method === 'POST') {
        const body = JSON.parse(init!.body as string) as { clientPubKey: string,
          clientEncPubKey: string }
        capturedClientPubHex = hexEncode(base64urlDecode(body.clientPubKey))
        capturedClientEncPubHex = hexEncode(base64urlDecode(body.clientEncPubKey))
        return new Response(JSON.stringify({
          code: '99999999',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_mismatch',
        }), { status: 200 })
      }
      if (url.includes('/api/identity/clients/pair/req_mismatch') && method === 'GET') {
        pollCalls += 1
        // Build a cert with the WRONG appId — SDK is configured with "right-app",
        // but Tower returns a cert minted for "wrong-app". finalizePair must reject.
        const cert = buildClientCert({
          masterPrivKey: user.privateKey,
          payload: {
            appId: 'wrong-app',
            clientEncPubKey: capturedClientEncPubHex!,
            clientId: '00000000-0000-4000-8000-000000000abc',
            clientPubKey: capturedClientPubHex!,
            deviceName: 'Test Device',
            exp: nowSec + 86400 * 60,
            iat: nowSec,
            scope: ['identity'],
            userEncPubKey: userEncPubHex,
            userId: 'user_test',
            userPubKey: userPubHex,
            v: 1,
          },
        })
        const clientEncPubBytes = new Uint8Array(capturedClientEncPubHex!.match(/.{2}/g)!.map((h) => parseInt(h, 16)))
        const sealedBundle = await sealClientBundle({
          bundle: {
            issuedAtSec: nowSec,
            servers: [{
              connInfoKey: base64urlEncode(K),
              serverPubKey: hexEncode(server.publicKey),
            }],
            v: 1,
          },
          clientEncPubKey: clientEncPubBytes,
        })
        return new Response(JSON.stringify({
          certSignature: cert.sig,
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_mismatch',
          sealedConnInfoBundle: sealedBundle,
          signedCertBytes: cert.payload,
          state: 'completed',
        }), { status: 200 })
      }
      throw new Error(`unexpected ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    const client = new AviatoPilotClient({
      appId: 'right-app',
      deviceName: 'Test',
      fetch: mockFetch,
      storage: new MemoryStorageBackend(),
      towerBaseUrl: 'https://api.tower.test',
    })
    const handle = await client.beginPair({ pollIntervalMs: 1 })
    await expect(handle.await()).rejects.toThrow(/appId mismatch/)
    expect(pollCalls).toBeGreaterThan(0)
  })
})
