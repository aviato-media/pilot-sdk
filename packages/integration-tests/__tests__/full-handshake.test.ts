// Cross-package end-to-end protocol handshake.
//
// This is the single test that catches drift between the three SDKs. It
// drives all four packages through the full lifecycle:
//
//   1. tower-sdk creates the user's vault + master keys (passkey/PRF
//      simulated with a deterministic AES-GCM key).
//   2. server-sdk starts a pairing flow (mocked Tower HTTP).
//   3. tower-sdk approves it: signs server-link assertion with M.
//   4. server-sdk polls, verifies, builds sealed K reply (pairing-response).
//   5. tower-sdk opens the sealed K and writes it into the user's vault.
//   6. tower-sdk builds a client-pair cert + sealed K bundle for a new app.
//   7. pilot-client-sdk completes pairing using that cert+bundle.
//   8. server-sdk publishes conn-info encrypted under K.
//   9. pilot-client-sdk fetches conn-info, decrypts with K, then runs
//      cert-auth against the (server-sdk-driven) media server.
//
// If anything drifts — schema field name, AAD bytes, JCS ordering, sig
// scheme — at least one assertion in this test fails. That's the whole
// reason this package exists.

import { AviatoPilotClient, MemoryStorageBackend } from '@aviato-media/pilot-client-sdk'
import {
  base64urlDecode,
  base64urlEncode,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
  PublicPrivateKey,
  randomAesKey,
  verifySessionAssertion,
} from '@aviato-media/pilot-core'
import {
  ConnInfoPublisher,
  MemoryPairingRequestStore,
  PairingService,
  TowerClient as ServerTowerClient,
  verifyServerLinkAssertion,
} from '@aviato-media/pilot-server-sdk'
import {
  approveServerLink,
  buildClientPairBundle,
  buildClientPairCert,
  claimConnInfoKey,
  createVault,
  openVault,
} from '@aviato-media/pilot-tower-sdk'
import { describe, expect, test } from 'bun:test'

// Deterministic stand-in for a real PRF wrapping key.
async function fakeWrappingKey (seed = 1): Promise<CryptoKey> {
  const raw = new Uint8Array(32).fill(seed)
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

describe('full cross-package handshake', () => {
  test('tower → server → client lifecycle', async () => {
    // ───── Tower-side: set up the user's identity + vault ─────
    const userMaster = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const userPubHex = hexEncode(userMaster.publicKey)
    const userEncPubHex = hexEncode(userEnc.publicKey)

    const wrappingKey = await fakeWrappingKey(1)
    const { blob: vault0 } = await createVault({
      credentialId: 'cred_test',
      payload: {
        masterPrivKey: base64urlEncode(userMaster.privateKey.toRaw()),
        masterPubKey: userPubHex,
        servers: [],
        userEncPrivKey: base64urlEncode(userEnc.privateKey.toRaw()),
        userEncPubKey: userEncPubHex,
        v: 1,
      },
      prfSalt: 'salt_a',
      prfWrappingKey: wrappingKey,
    })

    // ───── Media server identity ─────
    const server = generateEd25519Keypair()
    const serverPubHex = hexEncode(server.publicKey)
    const K = ConnInfoPublisher.generateConnInfoKey()
    const REQ_ID = 'req_int_1'

    // ───── Tower mock that captures whatever Server posts ─────
    const posted: { conninfo?: any,
      response?: any } = {}
    const towerFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'

      if (url.endsWith('/api/identity/pairing/register') && method === 'POST') {
        return new Response(JSON.stringify({
          code: '11112222',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: REQ_ID,
        }), { status: 201 })
      }

      if (url.endsWith(`/api/identity/pairing/${REQ_ID}`) && method === 'GET') {
        // Tower-sdk approves the pairing — sign assertion with M.
        const opened = await openVault({
          blob: vault0,
          credentialId: 'cred_test',
          prfWrappingKey: wrappingKey,
        })
        if (!opened.ok) {
          throw new Error('open vault failed')
        }
        const env = approveServerLink({
          masterPrivKey: base64urlDecode(opened.payload.masterPrivKey),
          requestId: REQ_ID,
          serverPubKey: server.publicKey.toRaw(),
          userEncPubKey: userEnc.publicKey.toRaw(),
          userId: 'user_int',
          userPubKey: userMaster.publicKey.toRaw(),
        })
        return new Response(JSON.stringify({
          assertionSignature: env.assertionSignature,
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: REQ_ID,
          signedAssertionBytes: env.signedAssertionBytes,
          state: 'completed',
        }), { status: 200 })
      }

      if (url.endsWith(`/api/identity/pairing/${REQ_ID}/response`) && method === 'POST') {
        posted.response = JSON.parse(init!.body as string)
        return new Response(JSON.stringify({ ok: true }), { status: 201 })
      }

      if (url.endsWith('/api/identity/server-conninfo') && method === 'POST') {
        posted.conninfo = JSON.parse(init!.body as string)
        return new Response(JSON.stringify({
          lastUpdatedAtSec: 1,
          ok: true,
          version: 1,
        }), { status: 200 })
      }

      // Client SDK paths (used later)
      if (url.endsWith('/api/identity/clients/pair/begin') && method === 'POST') {
        return new Response(JSON.stringify({
          code: '33334444',
          expiresAt: '2099-01-01T00:00:00.000Z',
          requestId: 'req_cli_1',
        }), { status: 200 })
      }
      if (url.includes('/api/identity/server-conninfo/') && method === 'GET') {
        return new Response(JSON.stringify({
          ...posted.conninfo,
          lastUpdatedAtSec: 1,
        }), { status: 200 })
      }

      throw new Error(`unexpected tower fetch: ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    // ───── 1+2: server-sdk drives pairing through Tower ─────
    const serverTower = new ServerTowerClient({
      baseUrl: 'https://tower.test',
      bearer: 'server-bearer',
      fetch: towerFetch,
    })
    const pairing = new PairingService(
      serverTower,
      new MemoryPairingRequestStore(),
      {
        serverId: 'srv_int',
        serverKey: server,
        towerPairingBaseUrl: 'https://tower.test',
      },
    )
    const started = await pairing.start({ inviteToken: 'inv_int' })
    expect(started.requestId).toBe(REQ_ID)

    // ───── 3+4: poll → verify assertion → seal K back ─────
    const polled = await pairing.poll(REQ_ID)
    expect(polled.state).toBe('completed')
    if (polled.state !== 'completed') {
      return
    }
    const verified = verifyServerLinkAssertion({
      envelope: polled.envelope,
      expectedRequestId: REQ_ID,
      expectedServerPubKey: server.publicKey,
    })
    expect(verified.ok).toBe(true)
    if (!verified.ok) {
      return
    }
    expect(verified.userPubKey).toBe(userPubHex)
    expect(verified.userEncPubKey).toBe(userEncPubHex)

    await pairing.respondWithKFromEnvelope({
      connInfoKey: K,
      envelope: polled.envelope,
      requestId: REQ_ID,
    })
    expect(posted.response).not.toBeUndefined()

    // ───── 5: tower-sdk opens the sealed K (the browser-side leg) ─────
    const claimed = await claimConnInfoKey({
      expectedServerPubKey: server.publicKey,
      record: {
        payload: posted.response,
        postedAtSec: 1,
      },
      userEncPrivKey: userEnc.privateKey.toRaw(),
    })
    expect(claimed.ok).toBe(true)
    if (claimed.ok) {
      expect(base64urlDecode(claimed.sealed.connInfoKey)).toEqual(K)
    }

    // ───── 6: tower-sdk builds cert + sealed bundle for a new client app ─────
    const clientSig = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const cert = buildClientPairCert({
      appId: 'aviato-web',
      clientEncPubKey: clientEnc.publicKey.toRaw(),
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPubKey: clientSig.publicKey.toRaw(),
      deviceName: 'Integration Test',
      masterPrivKey: userMaster.privateKey.toRaw(),
      scope: ['identity'],
      userEncPubKey: userEnc.publicKey.toRaw(),
      userId: 'user_int',
      userPubKey: userMaster.publicKey.toRaw(),
    })
    const sealedBundle = await buildClientPairBundle({
      clientEncPubKey: clientEnc.publicKey.toRaw(),
      servers: [{
        connInfoKey: K,
        serverPubKey: server.publicKey.toRaw(),
      }],
    })

    // ───── 8 (out of order): publish conn-info under K ─────
    const publisher = new ConnInfoPublisher({
      serverPrivKey: server.privateKey.toRaw(),
      serverPubKey: server.publicKey.toRaw(),
      tower: serverTower,
    })
    await publisher.publish({
      connInfoKey: K,
      payload: {
        issuedAtSec: Math.floor(Date.now() / 1000),
        port: 8443,
        protocol: 'https',
        publicHost: 'media.int.test',
      },
      version: 1,
    })
    expect(posted.conninfo).not.toBeUndefined()

    // ───── 7: pilot-client-sdk completes pairing using the prepared cert ─────
    let challengeIssued: string | null = null
    const clientFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      const method = init?.method ?? 'GET'

      if (url.endsWith('/api/identity/clients/pair/begin') && method === 'POST') {
        // Note: SDK already generated its own keypair — but we test with
        // the prepared cert+bundle we built above. To match, we override
        // the SDK's keypair by injecting test storage with a known cert.
        // Cleaner: bypass beginPair and use signInToServer directly with
        // pre-populated storage.
        throw new Error('should not call begin in this branch')
      }

      if (url.includes('/api/identity/server-conninfo/') && method === 'GET') {
        return new Response(JSON.stringify({
          ...posted.conninfo,
          lastUpdatedAtSec: 1,
        }), { status: 200 })
      }

      if (url.endsWith('/api/auth/identity-session/begin') && method === 'POST') {
        challengeIssued = 'aabbccdd'
        return new Response(JSON.stringify({ challenge: challengeIssued }), { status: 200 })
      }
      if (url.endsWith('/api/auth/identity-session/complete') && method === 'POST') {
        const assertion = JSON.parse(init!.body as string)
        const v = verifySessionAssertion(assertion, {
          challenge: challengeIssued!,
          serverPubKey: server.publicKey,
        })
        if (!v.ok) {
          return new Response(JSON.stringify({ error: v.error }), { status: 401 })
        }
        // App-specific extras travel in the same response — proves the
        // generic-body plumbing works end-to-end.
        return new Response(JSON.stringify({
          expiresAt: '2099-01-01T00:00:00.000Z',
          profiles: [{
            id: 'p1',
            name: 'Default',
          }],
          token: 'integration_token',
        }), { status: 200 })
      }
      throw new Error(`unexpected client fetch: ${method} ${url}`)
    }) as unknown as typeof globalThis.fetch

    const storage = new MemoryStorageBackend()
    await storage.setIdentity({
      certSignature: cert.sig,
      clientEncPrivBase64url: base64urlEncode(clientEnc.privateKey.toRaw()),
      clientId: '00000000-0000-4000-8000-000000000abc',
      clientPrivBase64url: base64urlEncode(clientSig.privateKey.toRaw()),
      exp: Math.floor(Date.now() / 1000) + 86400 * 60,
      iat: Math.floor(Date.now() / 1000),
      signedCertBytes: cert.payload,
      userPubKey: userPubHex,
    })
    // The bundle carries K — but the client SDK normally fetches it via
    // openClientBundle during finalizePair. Since we pre-populated identity
    // we also pre-populate the bundle (skipping the polling phase).
    await storage.setBundle({
      issuedAtSec: Math.floor(Date.now() / 1000),
      servers: [{
        connInfoKey: base64urlEncode(K),
        serverPubKey: serverPubHex,
      }],
    })

    const client = new AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Integration Test',
      fetch: clientFetch,
      storage,
      towerBaseUrl: 'https://tower.test',
    })
    interface AviatoSessionBody {
      token: string
      expiresAt: string
      profiles: Array<{ id: string,
        name: string }>
    }
    const conn = await client.signInToServer<AviatoSessionBody>({ serverPubKey: server.publicKey })
    expect(conn.status.state).toBe('online')
    if (conn.status.state === 'online') {
      expect(conn.status.sessionToken).toBe('integration_token')
      expect(conn.status.baseUrl).toBe('https://media.int.test:8443')
    }
    expect(conn.body?.profiles).toEqual([{
      id: 'p1',
      name: 'Default',
    }])

    // Also verify the sealedBundle round-trips on the client side (would
    // happen during real finalizePair). Confirms tower-sdk and client-sdk
    // agree on the bundle's wire shape.
    const { openClientBundle } = await import('@aviato-media/pilot-core')
    const opened = await openClientBundle({
      box: sealedBundle,
      clientEncPrivKey: clientEnc.privateKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.bundle.servers[0]!.connInfoKey).toBe(base64urlEncode(K))
    }
  })

  test('respondWithK rejects hand-constructed verifiedAssertion (stale-snapshot defense)', async () => {
    const server = generateEd25519Keypair()
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const tower = new ServerTowerClient({
      baseUrl: 'https://tower.test',
      bearer: 't',
      fetch: (async () => new Response('{}', { status: 200 })) as unknown as typeof globalThis.fetch,
    })
    const svc = new PairingService(tower, new MemoryPairingRequestStore(), {
      serverId: 'srv',
      serverKey: new PublicPrivateKey({
        privateKey: server.privateKey,
        publicKey: server.publicKey,
      }),
      towerPairingBaseUrl: 'https://tower.test',
    })
    await expect(svc.respondWithK({
      connInfoKey: randomAesKey(),
      requestId: 'r',
      // @ts-expect-error — intentionally unbranded
      verifiedAssertion: {
        ok: true,
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'u',
        userPubKey: hexEncode(user.publicKey),
      },
    })).rejects.toThrow(/missing brand/)
  })
})
