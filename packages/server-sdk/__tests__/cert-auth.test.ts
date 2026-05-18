// Exercises the server-sdk cert-auth handshake against an in-memory user
// store. Covers happy path + the three rejection branches (unknown user,
// revoked client, used challenge).

import {
  buildClientCert,
  buildSessionAssertion,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { beginChallenge, completeChallenge } from '../src/cert-auth.js'
import {
  MemoryIdentityClientStore,
  MemoryIdentityUserStore,
  MemorySessionChallengeStore,
} from '../src/stores.js'

describe('cert-auth handshake', () => {
  function makeFixtures () {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const client = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const nowSec = Math.floor(Date.now() / 1000)

    const cert = buildClientCert({
      masterPrivKey: user.privateKey,
      payload: {
        appId: 'aviato-web',
        clientEncPubKey: hexEncode(clientEnc.publicKey),
        clientId: '00000000-0000-4000-8000-000000000001',
        clientPubKey: hexEncode(client.publicKey),
        deviceName: 'Test',
        exp: nowSec + 86400,
        iat: nowSec,
        scope: ['identity'],
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })

    const userStore = new MemoryIdentityUserStore()
    userStore.seed({
      id: 'user_test',
      towerUserId: 'tower_uid',
      userEncPubKey: hexEncode(userEnc.publicKey),
      userPubKey: hexEncode(user.publicKey),
    })
    return {
      cert,
      challengeStore: new MemorySessionChallengeStore(),
      client,
      clientStore: new MemoryIdentityClientStore(),
      server,
      serverPubHex: hexEncode(server.publicKey),
      userStore,
    }
  }

  test('happy path', async () => {
    const f = makeFixtures()
    const beg = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(beg.ok).toBe(true)
    if (!beg.ok) {
      return
    }
    const assertion = buildSessionAssertion({
      cert: f.cert,
      challenge: beg.challenge,
      clientPrivKey: f.client.privateKey,
      serverPubKey: f.server.publicKey,
    })
    const comp = await completeChallenge({
      assertion,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(comp.ok).toBe(true)
    if (comp.ok) {
      expect(comp.userId).toBe('user_test')
    }
  })

  test('replayed challenge rejected', async () => {
    const f = makeFixtures()
    const beg = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    if (!beg.ok) {
      throw new Error('begin failed')
    }
    const assertion = buildSessionAssertion({
      cert: f.cert,
      challenge: beg.challenge,
      clientPrivKey: f.client.privateKey,
      serverPubKey: f.server.publicKey,
    })
    await completeChallenge({
      assertion,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    const second = await completeChallenge({
      assertion,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(second.ok).toBe(false)
    if (!second.ok) {
      expect(second.error).toBe('challenge_unknown_or_consumed')
    }
  })

  test('revoke(clientId) flips isRevoked to true', async () => {
    const store = new MemoryIdentityClientStore()
    await store.upsert({
      certExpiresAt: '2099-01-01T00:00:00.000Z',
      clientEncPubKey: '1'.repeat(64),
      clientId: 'cid_test',
      clientPubKey: '2'.repeat(64),
      deviceName: 'Test',
      lastSeenAt: '2026-01-01T00:00:00.000Z',
      revoked: false,
      userId: 'user_test',
    })
    expect(await store.isRevoked('cid_test')).toBe(false)
    await store.revoke('cid_test')
    expect(await store.isRevoked('cid_test')).toBe(true)
    const row = await store.get('cid_test')
    expect(row?.revoked).toBe(true)
  })

  test('unknown user rejected at begin', async () => {
    const f = makeFixtures()
    const empty = new MemoryIdentityUserStore()
    const result = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: empty,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error).toBe('user_not_registered')
      expect(result.status).toBe(403)
    }
  })

  test('cert_invalid (bad signature) rejected at begin with status 400', async () => {
    const f = makeFixtures()
    const badCert = {
      ...f.cert,
      // 64-byte junk signature
      sig: 'A'.repeat(86), // base64url length for 64 random-ish bytes
    }
    const result = await beginChallenge({
      cert: badCert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.status).toBe(400)
    }
  })

  test('client_revoked rejected at begin with status 403', async () => {
    const f = makeFixtures()
    // Pre-revoke the cert's clientId before begin.
    await f.clientStore.upsert({
      certExpiresAt: '2099-01-01T00:00:00.000Z',
      clientEncPubKey: '1'.repeat(64),
      clientId: '00000000-0000-4000-8000-000000000001',
      clientPubKey: '2'.repeat(64),
      deviceName: 'X',
      lastSeenAt: '2026-01-01T00:00:00.000Z',
      revoked: true,
      userId: 'user_test',
    })
    const result = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error).toBe('client_revoked')
      expect(result.status).toBe(403)
    }
  })

  test('user_not_registered at complete (user removed between begin and complete)', async () => {
    const f = makeFixtures()
    const beg = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(beg.ok).toBe(true)
    if (!beg.ok) {
      return
    }
    // Swap to an empty user store before complete.
    const emptyUsers = new MemoryIdentityUserStore()
    const assertion = buildSessionAssertion({
      cert: f.cert,
      challenge: beg.challenge,
      clientPrivKey: f.client.privateKey,
      serverPubKey: f.server.publicKey,
    })
    const comp = await completeChallenge({
      assertion,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: emptyUsers,
    })
    expect(comp.ok).toBe(false)
    if (!comp.ok) {
      expect(comp.error).toBe('user_not_registered')
      expect(comp.status).toBe(403)
    }
  })

  test('client_revoked at complete (revoked between begin and complete)', async () => {
    const f = makeFixtures()
    const beg = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(beg.ok).toBe(true)
    if (!beg.ok) {
      return
    }
    // Now revoke the client and try to complete.
    await f.clientStore.upsert({
      certExpiresAt: '2099-01-01T00:00:00.000Z',
      clientEncPubKey: '1'.repeat(64),
      clientId: '00000000-0000-4000-8000-000000000001',
      clientPubKey: '2'.repeat(64),
      deviceName: 'X',
      lastSeenAt: '2026-01-01T00:00:00.000Z',
      revoked: true,
      userId: 'user_test',
    })
    const assertion = buildSessionAssertion({
      cert: f.cert,
      challenge: beg.challenge,
      clientPrivKey: f.client.privateKey,
      serverPubKey: f.server.publicKey,
    })
    const comp = await completeChallenge({
      assertion,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(comp.ok).toBe(false)
    if (!comp.ok) {
      expect(comp.error).toBe('client_revoked')
      expect(comp.status).toBe(403)
    }
  })

  test('signature_invalid at complete returns 401', async () => {
    const f = makeFixtures()
    const beg = await beginChallenge({
      cert: f.cert,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(beg.ok).toBe(true)
    if (!beg.ok) {
      return
    }
    // Build an assertion signed by a DIFFERENT client privkey — the cert
    // declares the original client pub, so sig verification fails.
    const fakeClient = generateEd25519Keypair()
    const tampered = buildSessionAssertion({
      cert: f.cert,
      challenge: beg.challenge,
      clientPrivKey: fakeClient.privateKey,
      serverPubKey: f.server.publicKey,
    })
    const comp = await completeChallenge({
      assertion: tampered,
      challengeStore: f.challengeStore,
      clientStore: f.clientStore,
      serverPubKey: f.server.publicKey,
      userStore: f.userStore,
    })
    expect(comp.ok).toBe(false)
    if (!comp.ok) {
      expect(comp.status).toBe(401)
    }
  })
})
