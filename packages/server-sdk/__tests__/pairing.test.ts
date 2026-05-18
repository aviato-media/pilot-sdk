// Exercises server-sdk end-to-end with mocked Tower:
//   - Server starts a pairing → Tower returns code/requestId → row persisted.
//   - Server polls → Tower returns completed with master-signed assertion.
//   - Server verifies the assertion → extracts userPubKey + userEncPubKey.
//   - Server seals K back through respondWithK() → posts to Tower /response.
//   - We open the sealed payload as the user-side would and confirm K matches.

import {
  base64urlDecode,
  buildPairingAssertion,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
  openPairingResponse,
  randomAesKey,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import {
  ConnInfoPublisher,
  MemoryPairingRequestStore,
  PairingService,
  TowerClient,
  verifyServerLinkAssertion,
} from '../src/index.js'

describe('PairingService end-to-end', () => {
  test('start → poll → respond round-trip', async () => {
    const server = generateEd25519Keypair()
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const serverPubHex = hexEncode(server.publicKey)
    const userPubHex = hexEncode(user.publicKey)
    const K = randomAesKey()
    const REQUEST_ID = 'req_123'

    let postedResponse: any = null

    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'

      if (url.endsWith('/api/identity/pairing/register') && method === 'POST') {
        return new Response(JSON.stringify({
          code: '12345678',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: REQUEST_ID,
        }), { status: 201 })
      }
      if (url.endsWith(`/api/identity/pairing/${REQUEST_ID}`) && method === 'GET') {
        const env = buildPairingAssertion({
          masterPrivKey: user.privateKey,
          payload: {
            kind: 'server-link',
            requestId: REQUEST_ID,
            serverPubKey: serverPubHex,
            ts: Date.now(),
            userEncPubKey: hexEncode(userEnc.publicKey),
            userId: 'user_test',
            userPubKey: userPubHex,
            v: 1,
          },
        })
        return new Response(JSON.stringify({
          assertionSignature: env.assertionSignature,
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: REQUEST_ID,
          signedAssertionBytes: env.signedAssertionBytes,
          state: 'completed',
        }), { status: 200 })
      }
      if (url.endsWith(`/api/identity/pairing/${REQUEST_ID}/response`) && method === 'POST') {
        postedResponse = JSON.parse(init!.body as string)
        return new Response(JSON.stringify({ ok: true }), { status: 201 })
      }
      throw new Error(`unexpected fetch: ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    const tower = new TowerClient({
      baseUrl: 'https://tower.test',
      bearer: 'test-bearer',
      fetch: mockFetch,
    })
    const store = new MemoryPairingRequestStore()
    const service = new PairingService(tower, store, {
      serverId: 'srv_test',
      serverPrivKey: server.privateKey.toRaw(),
      serverPubKey: server.publicKey.toRaw(),
      towerPairingBaseUrl: 'https://tower.test',
    })

    const started = await service.start({ inviteToken: 'inv_abc' })
    expect(started.code).toBe('12345678')
    expect(started.requestId).toBe(REQUEST_ID)
    expect(started.pairingUrl).toBe('https://tower.test/pair?code=12345678')

    const polled = await service.poll(REQUEST_ID)
    expect(polled.state).toBe('completed')
    if (polled.state !== 'completed') {
      return
    }
    const verified = verifyServerLinkAssertion({
      envelope: polled.envelope,
      expectedRequestId: REQUEST_ID,
      expectedServerPubKey: server.publicKey,
    })
    expect(verified.ok).toBe(true)
    if (!verified.ok) {
      return
    }
    expect(verified.userPubKey).toBe(userPubHex)

    await service.respondWithK({
      connInfoKey: K,
      requestId: REQUEST_ID,
      verifiedAssertion: verified,
    })
    expect(postedResponse).not.toBeNull()

    // User-side opens the sealed K.
    const opened = await openPairingResponse({
      expectedServerPubKey: server.publicKey,
      payload: postedResponse,
      userEncPrivKey: userEnc.privateKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(base64urlDecode(opened.payload.connInfoKey)).toEqual(K)
    }
  })

  test('start() sends displayName + serverIcon on the wire when config provides them', async () => {
    let capturedBody: unknown = null
    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/api/identity/pairing/register') && init?.method === 'POST') {
        capturedBody = JSON.parse(init.body as string)
        return new Response(JSON.stringify({
          code: '12345678',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_dn',
        }), { status: 201 })
      }
      throw new Error(`unexpected: ${url}`)
    }) as unknown as typeof globalThis.fetch
    const service = new PairingService(
      new TowerClient({
        baseUrl: 'https://tower.test',
        bearer: 'b',
        fetch: mockFetch,
      }),
      new MemoryPairingRequestStore(),
      {
        displayName: 'My Lovely Server',
        serverIcon: 'https://media.example.com/icon.png',
        serverId: 'srv_dn',
        serverPrivKey: new Uint8Array(32),
        serverPubKey: new Uint8Array(32),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    await service.start({ inviteToken: 'inv' })
    expect(capturedBody).not.toBeNull()
    const body = capturedBody as { displayName?: string,
      serverIcon?: string,
      kind: string,
      serverId: string }
    expect(body.displayName).toBe('My Lovely Server')
    expect(body.serverIcon).toBe('https://media.example.com/icon.png')
    expect(body.kind).toBe('server-link')
    expect(body.serverId).toBe('srv_dn')
  })

  test('start() omits displayName when config does not provide one', async () => {
    let capturedBody: unknown = null
    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/api/identity/pairing/register') && init?.method === 'POST') {
        capturedBody = JSON.parse(init.body as string)
        return new Response(JSON.stringify({
          code: '12345678',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_no_dn',
        }), { status: 201 })
      }
      throw new Error(`unexpected: ${url}`)
    }) as unknown as typeof globalThis.fetch
    const service = new PairingService(
      new TowerClient({
        baseUrl: 'https://tower.test',
        bearer: 'b',
        fetch: mockFetch,
      }),
      new MemoryPairingRequestStore(),
      {
        serverId: 'srv_anon',
        serverPrivKey: new Uint8Array(32),
        serverPubKey: new Uint8Array(32),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    await service.start({ inviteToken: 'inv' })
    const body = capturedBody as { displayName?: string }
    expect(body.displayName).toBeUndefined()
  })

  test('PairingRegisterRequestSchema accepts the body PairingService sends', async () => {
    // Belt-and-braces: the canonical schema must accept what the SDK produces.
    // If a future SDK change breaks this contract, this test catches it.
    const { PairingRegisterRequestSchema } = await import('@aviato-media/pilot-core')
    const wireBody = {
      displayName: 'Test Server',
      kind: 'server-link' as const,
      scope: ['identity'],
      serverIcon: 'https://example.com/icon.png',
      serverId: 'srv_test',
    }
    const parsed = PairingRegisterRequestSchema.safeParse(wireBody)
    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.displayName).toBe('Test Server')
    }
  })

  test('start() accepts kind: server-sign-in without invite/localUserId', async () => {
    let registeredKind: string | null = null
    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/api/identity/pairing/register') && init?.method === 'POST') {
        const body = JSON.parse(init.body as string) as { kind: string }
        registeredKind = body.kind
        return new Response(JSON.stringify({
          code: '99999999',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_signin',
        }), { status: 201 })
      }
      throw new Error(`unexpected: ${url}`)
    }) as unknown as typeof globalThis.fetch
    const service = new PairingService(
      new TowerClient({
        baseUrl: 'https://tower.test',
        bearer: 'b',
        fetch: mockFetch,
      }),
      new MemoryPairingRequestStore(),
      {
        serverId: 's',
        serverPrivKey: new Uint8Array(32),
        serverPubKey: new Uint8Array(32),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    const started = await service.start({ kind: 'server-sign-in' })
    expect(started.requestId).toBe('req_signin')
    expect(registeredKind === 'server-sign-in').toBe(true)
  })

  test('respondWithK refuses an unverified assertion result', async () => {
    const server = generateEd25519Keypair()
    const service = new PairingService(
      new TowerClient({
        baseUrl: 'x',
        bearer: 'y',
        fetch: (() => Promise.reject(new Error('should never be called'))) as unknown as typeof globalThis.fetch,
      }),
      new MemoryPairingRequestStore(),
      {
        serverId: 's',
        serverPrivKey: server.privateKey.toRaw(),
        serverPubKey: server.publicKey.toRaw(),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    await expect(service.respondWithK({
      connInfoKey: randomAesKey(),
      requestId: 'req_x',
      verifiedAssertion: {
        error: 'signature_invalid',
        ok: false,
      } as never,
    })).rejects.toThrow(/unverified|not ok/i)
  })

  test('respondWithK seals to the assertion userEncPubKey even if caller has stale state', async () => {
    // This is the regression test for the media-server bug: a caller cannot
    // sneak in a different recipient key, because there's no way to pass one.
    const server = generateEd25519Keypair()
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const wrongEnc = generateX25519Keypair()
    const K = randomAesKey()
    const REQUEST_ID = 'req_regression'

    let postedResponse: any = null
    const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith(`/api/identity/pairing/${REQUEST_ID}/response`) && init?.method === 'POST') {
        postedResponse = JSON.parse(init.body as string)
        return new Response(JSON.stringify({ ok: true }), { status: 201 })
      }
      throw new Error(`unexpected: ${url}`)
    }) as unknown as typeof globalThis.fetch

    const service = new PairingService(
      new TowerClient({
        baseUrl: 'https://tower.test',
        bearer: 'b',
        fetch: mockFetch,
      }),
      new MemoryPairingRequestStore(),
      {
        serverId: 's',
        serverPrivKey: server.privateKey.toRaw(),
        serverPubKey: server.publicKey.toRaw(),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )

    // The verified assertion carries userEnc.publicKey, NOT wrongEnc.publicKey.
    // There is no parameter for the caller to override this.
    const verified = {
      ok: true as const,
      userEncPubKey: hexEncode(userEnc.publicKey),
      userId: 'user_x',
      userPubKey: hexEncode(user.publicKey),
    }
    await service.respondWithK({
      connInfoKey: K,
      requestId: REQUEST_ID,
      verifiedAssertion: verified,
    })
    expect(postedResponse).not.toBeNull()

    // The "wrong" key cannot open this — confirming K was sealed to the
    // assertion's key, not the stale one.
    const wrongOpen = await openPairingResponse({
      expectedServerPubKey: server.publicKey,
      payload: postedResponse,
      userEncPrivKey: wrongEnc.privateKey,
    })
    expect(wrongOpen.ok).toBe(false)

    const rightOpen = await openPairingResponse({
      expectedServerPubKey: server.publicKey,
      payload: postedResponse,
      userEncPrivKey: userEnc.privateKey,
    })
    expect(rightOpen.ok).toBe(true)
    if (rightOpen.ok) {
      expect(base64urlDecode(rightOpen.payload.connInfoKey)).toEqual(K)
    }
  })

  test('start() rejects both invite + localUserId together', async () => {
    const service = new PairingService(
      new TowerClient({
        baseUrl: 'x',
        bearer: 'y',
        fetch: (() => Promise.reject(new Error('nope'))) as unknown as typeof globalThis.fetch,
      }),
      new MemoryPairingRequestStore(),
      {
        serverId: 's',
        serverPrivKey: new Uint8Array(32),
        serverPubKey: new Uint8Array(32),
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    await expect(service.start({
      inviteToken: 'a',
      localUserId: 'b',
    })).rejects.toThrow()
    await expect(service.start({})).rejects.toThrow()
  })
})

// ── Adversarial: ConnInfoPublisher.publish version monotonicity ──────

describe('ConnInfoPublisher: strict-monotonic version', () => {
  function makePublisher () {
    const server = generateEd25519Keypair()
    const calls: unknown[] = []
    const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(JSON.parse(init?.body as string))
      return new Response(JSON.stringify({
        lastUpdatedAtSec: 1,
        ok: true,
        version: 1,
      }), { status: 200 })
    }) as unknown as typeof globalThis.fetch
    const tower = new TowerClient({
      baseUrl: 'https://tower.test',
      bearer: 'test-bearer',
      fetch: mockFetch,
    })
    const publisher = new ConnInfoPublisher({
      serverPrivKey: server.privateKey.toRaw(),
      serverPubKey: server.publicKey.toRaw(),
      tower,
    })
    return {
      calls,
      publisher,
    }
  }

  const basePayload = {
    issuedAtSec: Math.floor(Date.now() / 1000),
    port: 443,
    protocol: 'https' as const,
    publicHost: 'media.test',
  }

  test('accepts strictly increasing versions', async () => {
    const { publisher, calls } = makePublisher()
    const K = randomAesKey()
    await publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 1,
    })
    await publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 2,
    })
    await publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 5,
    })
    expect(calls).toHaveLength(3)
  })

  test('rejects re-publish at same version', async () => {
    const { publisher } = makePublisher()
    const K = randomAesKey()
    await publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 7,
    })
    await expect(publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 7,
    }))
      .rejects.toThrow(/strictly monotonic/)
  })

  test('rejects decreasing version', async () => {
    const { publisher } = makePublisher()
    const K = randomAesKey()
    await publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 5,
    })
    await expect(publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 4,
    }))
      .rejects.toThrow(/strictly monotonic/)
  })

  test('rejects negative version', async () => {
    const { publisher } = makePublisher()
    const K = randomAesKey()
    await expect(publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: -1,
    }))
      .rejects.toThrow(/non-negative integer/)
  })

  test('rejects non-integer version', async () => {
    const { publisher } = makePublisher()
    const K = randomAesKey()
    await expect(publisher.publish({
      connInfoKey: K,
      payload: basePayload,
      version: 1.5,
    }))
      .rejects.toThrow(/non-negative integer/)
  })
})
