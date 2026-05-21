// Coverage for server-sdk verify.ts: verifyServerSignInAssertion and the
// verifyAndPersist sugar.

import {
  buildPairingAssertion,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { MemoryIdentityUserStore } from '../src/stores.js'
import {
  verifyAndPersist,
  verifyOperatorLinkAssertion,
  verifyServerLinkAssertion,
  verifyServerSignInAssertion,
} from '../src/verify.js'

function makeServerSignInEnvelope (opts: { user?: { privateKey: Uint8Array,
  publicKey: Uint8Array },
userEnc?: { privateKey: Uint8Array,
  publicKey: Uint8Array },
server?: { privateKey: Uint8Array,
  publicKey: Uint8Array },
requestId?: string,
ts?: number } = {}) {
  const user = opts.user ?? generateEd25519Keypair()
  const userEnc = opts.userEnc ?? generateX25519Keypair()
  const server = opts.server ?? generateEd25519Keypair()
  const requestId = opts.requestId ?? 'req_signin'
  const env = buildPairingAssertion({
    masterPrivKey: user.privateKey,
    payload: {
      kind: 'server-sign-in',
      requestId,
      serverPubKey: hexEncode(server.publicKey),
      ts: opts.ts ?? Date.now(),
      userEncPubKey: hexEncode(userEnc.publicKey),
      userId: 'user_test',
      userPubKey: hexEncode(user.publicKey),
      v: 1,
    },
  })
  return {
    env,
    requestId,
    server,
    user,
    userEnc,
  }
}

describe('verifyServerSignInAssertion', () => {
  test('round-trip succeeds and surfaces userPubKey/userEncPubKey', () => {
    const f = makeServerSignInEnvelope()
    const r = verifyServerSignInAssertion({
      envelope: f.env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.userPubKey).toBe(hexEncode(f.user.publicKey))
      expect(r.userEncPubKey).toBe(hexEncode(f.userEnc.publicKey))
      expect(r.userId).toBe('user_test')
    }
  })
  test('wrong expectedUserPubKey returns user_pubkey_mismatch', () => {
    const f = makeServerSignInEnvelope()
    const other = generateEd25519Keypair()
    const r = verifyServerSignInAssertion({
      envelope: f.env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
      expectedUserPubKey: other.publicKey,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('user_pubkey_mismatch')
    }
  })
  test('wrong expectedServerPubKey returns wrong_server', () => {
    const f = makeServerSignInEnvelope()
    const other = generateEd25519Keypair()
    const r = verifyServerSignInAssertion({
      envelope: f.env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: other.publicKey,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('wrong_server')
    }
  })
  test('rejects server-link envelope when sign-in expected (schema rejects)', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const env = buildPairingAssertion({
      masterPrivKey: user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: 'r',
        serverPubKey: hexEncode(server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'u',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    const r = verifyServerSignInAssertion({
      envelope: env,
      expectedRequestId: 'r',
      expectedServerPubKey: server.publicKey,
    })
    expect(r.ok).toBe(false)
  })
})

describe('verifyAndPersist', () => {
  test('default kind=server-link: upserts userEncPubKey when user exists', async () => {
    const f = makeServerSignInEnvelope()
    // Re-build as server-link, not sign-in, since default kind is link.
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const userStore = new MemoryIdentityUserStore()
    const stalePubHex = hexEncode(new Uint8Array(32).fill(0xaa))
    userStore.seed({
      id: 'user_test',
      towerUserId: 'tower_uid',
      userEncPubKey: stalePubHex,
      userPubKey: hexEncode(f.user.publicKey),
    })
    const result = await verifyAndPersist({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
      userStore,
    })
    expect(result.ok).toBe(true)
    // Confirm the upsert happened.
    const row = await userStore.getByPublicKey(hexEncode(f.user.publicKey))
    expect(row).not.toBeNull()
    expect(row!.userEncPubKey).toBe(hexEncode(f.userEnc.publicKey))
  })
  test('kind=server-sign-in dispatches to the sign-in verifier', async () => {
    const f = makeServerSignInEnvelope()
    const userStore = new MemoryIdentityUserStore()
    userStore.seed({
      id: 'user_test',
      towerUserId: 'tower_uid',
      userEncPubKey: hexEncode(f.userEnc.publicKey),
      userPubKey: hexEncode(f.user.publicKey),
    })
    const result = await verifyAndPersist({
      envelope: f.env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
      kind: 'server-sign-in',
      userStore,
    })
    expect(result.ok).toBe(true)
  })
  test('no-op upsert when user does not exist in the store yet', async () => {
    const f = makeServerSignInEnvelope()
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const userStore = new MemoryIdentityUserStore()
    // Don't seed — verifyAndPersist should still succeed (the registration
    // table insert is the host's job, this is the upsert path for repeats).
    const result = await verifyAndPersist({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
      userStore,
    })
    expect(result.ok).toBe(true)
  })
  test('returns error when verify fails (wrong serverPubKey)', async () => {
    const f = makeServerSignInEnvelope()
    const userStore = new MemoryIdentityUserStore()
    const result = await verifyAndPersist({
      envelope: f.env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: generateEd25519Keypair().publicKey,
      kind: 'server-sign-in',
      userStore,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.error).toBe('wrong_server')
    }
  })
  test('kind=operator-link dispatches to operator verifier and does NOT upsert userEncPubKey', async () => {
    const f = makeServerSignInEnvelope()
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'operator-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const existingEnc = generateX25519Keypair()
    const userStore = new MemoryIdentityUserStore()
    userStore.seed({
      id: 'user_test',
      towerUserId: 'tower_uid',
      userEncPubKey: hexEncode(existingEnc.publicKey),
      userPubKey: hexEncode(f.user.publicKey),
    })
    const result = await verifyAndPersist({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
      kind: 'operator-link',
      userStore,
    })
    expect(result.ok).toBe(true)
    const row = await userStore.getByPublicKey(hexEncode(f.user.publicKey))
    expect(row).not.toBeNull()
    expect(row!.userEncPubKey).toBe(hexEncode(existingEnc.publicKey))
  })
})

describe('verifyServerLinkAssertion (the wrapper)', () => {
  test('round-trip', () => {
    const f = makeServerSignInEnvelope()
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'u',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const r = verifyServerLinkAssertion({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
    })
    expect(r.ok).toBe(true)
  })
})

describe('verifyOperatorLinkAssertion', () => {
  test('round-trip surfaces user identity', () => {
    const f = makeServerSignInEnvelope()
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'operator-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'operator_user',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const r = verifyOperatorLinkAssertion({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.userId).toBe('operator_user')
      expect(r.userPubKey).toBe(hexEncode(f.user.publicKey))
    }
  })
  test('rejects a server-link envelope', () => {
    const f = makeServerSignInEnvelope()
    const env = buildPairingAssertion({
      masterPrivKey: f.user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: f.requestId,
        serverPubKey: hexEncode(f.server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(f.userEnc.publicKey),
        userId: 'u',
        userPubKey: hexEncode(f.user.publicKey),
        v: 1,
      },
    })
    const r = verifyOperatorLinkAssertion({
      envelope: env,
      expectedRequestId: f.requestId,
      expectedServerPubKey: f.server.publicKey,
    })
    expect(r.ok).toBe(false)
  })
})
