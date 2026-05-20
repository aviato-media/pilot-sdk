// Coverage for tower-sdk: conn-info.ts (resolveConnInfo + deriveConnInfoHash),
// assertions.approveServerSignIn, and pairing-response.claimConnInfoKey
// error branches.

import {
  base64urlDecode,
  base64urlEncode,
  buildPairingResponse,
  type Ed25519Keypair,
  generateEd25519Keypair,
  generateX25519Keypair,
  randomAesKey,
  sealServerConnInfo,
  sha256Bytes,
  verifyPairingAssertion,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { approveServerLink, approveServerSignIn } from '../src/assertions.js'
import { deriveConnInfoHash, resolveConnInfo } from '../src/conn-info.js'
import { claimConnInfoKey } from '../src/pairing-response.js'

describe('resolveConnInfo', () => {
  async function makeRecord (server: Ed25519Keypair, K: Uint8Array) {
    const sealed = await sealServerConnInfo({
      connInfoKey: K,
      payload: {
        issuedAtSec: Math.floor(Date.now() / 1000),
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
    return {
      ...sealed,
      lastUpdatedAtSec: Math.floor(Date.now() / 1000),
    }
  }

  test('round-trip', async () => {
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const record = await makeRecord(server, K)
    const r = await resolveConnInfo({
      connInfoKey: K,
      record,
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.payload.publicHost).toBe('media.test')
      expect(r.payload.port).toBe(443)
    }
  })

  test('sig_invalid when sig is tampered', async () => {
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const record = await makeRecord(server, K)
    const sigBytes = base64urlDecode(record.sig)
    sigBytes[0] = sigBytes[0]! ^ 0xff
    const tampered = {
      ...record,
      sig: base64urlEncode(sigBytes),
    }
    const r = await resolveConnInfo({
      connInfoKey: K,
      record: tampered,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('sig_invalid')
    }
  })

  test('aead_decrypt_failed when K is wrong (sig is still valid)', async () => {
    const server = generateEd25519Keypair()
    const K = randomAesKey()
    const wrongK = randomAesKey()
    const record = await makeRecord(server, K)
    const r = await resolveConnInfo({
      connInfoKey: wrongK,
      record,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('aead_decrypt_failed')
    }
  })
})

describe('deriveConnInfoHash', () => {
  test('matches base64url(sha256(serverPubKey))', () => {
    const server = generateEd25519Keypair()
    const expected = base64urlEncode(sha256Bytes(server.publicKey.toRaw()))
    expect(deriveConnInfoHash(server.publicKey.toRaw())).toBe(expected)
  })
})

describe('approveServerSignIn', () => {
  test('produces a server-sign-in envelope verifiable by verifyPairingAssertion', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const env = approveServerSignIn({
      requestId: 'req_signin_tower',
      serverPubKey: server.publicKey.toRaw(),
      userEncPubKey: userEnc.publicKey.toRaw(),
      userId: 'user_test',
      userKey: user,
    })
    const r = verifyPairingAssertion(env, {
      expectedKind: 'server-sign-in',
      expectedRequestId: 'req_signin_tower',
      expectedServerPubKey: server.publicKey,
    })
    expect(r.ok).toBe(true)
  })
  test('approveServerLink (sister fn) round-trip', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const env = approveServerLink({
      requestId: 'req_link_tower',
      serverPubKey: server.publicKey.toRaw(),
      userEncPubKey: userEnc.publicKey.toRaw(),
      userId: 'user_test',
      userKey: user,
    })
    const r = verifyPairingAssertion(env, {
      expectedKind: 'server-link',
      expectedRequestId: 'req_link_tower',
      expectedServerPubKey: server.publicKey,
    })
    expect(r.ok).toBe(true)
  })
})

describe('claimConnInfoKey', () => {
  test('round-trip', async () => {
    const server = generateEd25519Keypair()
    const userMaster = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const K = randomAesKey()
    const payload = await buildPairingResponse({
      connInfoKey: K,
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      userEncPubKey: userEnc.publicKey,
      userPubKey: userMaster.publicKey,
    })
    const r = await claimConnInfoKey({
      expectedServerPubKey: server.publicKey,
      record: {
        payload,
        postedAtSec: 1,
      },
      userEncPrivKey: userEnc.privateKey.toRaw(),
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(base64urlDecode(r.sealed.connInfoKey)).toEqual(K)
    }
  })

  test('sig_invalid when expectedServerPubKey is wrong', async () => {
    const server = generateEd25519Keypair()
    const other = generateEd25519Keypair()
    const userMaster = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const payload = await buildPairingResponse({
      connInfoKey: randomAesKey(),
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      userEncPubKey: userEnc.publicKey,
      userPubKey: userMaster.publicKey,
    })
    const r = await claimConnInfoKey({
      expectedServerPubKey: other.publicKey,
      record: {
        payload,
        postedAtSec: 1,
      },
      userEncPrivKey: userEnc.privateKey.toRaw(),
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('sig_invalid')
    }
  })

  test('decrypt_failed when userEncPrivKey is wrong (but sig still verifies)', async () => {
    const server = generateEd25519Keypair()
    const userMaster = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const wrong = generateX25519Keypair()
    const payload = await buildPairingResponse({
      connInfoKey: randomAesKey(),
      serverPrivKey: server.privateKey,
      serverPubKey: server.publicKey,
      userEncPubKey: userEnc.publicKey,
      userPubKey: userMaster.publicKey,
    })
    const r = await claimConnInfoKey({
      expectedServerPubKey: server.publicKey,
      record: {
        payload,
        postedAtSec: 1,
      },
      userEncPrivKey: wrong.privateKey.toRaw(),
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('decrypt_failed')
    }
  })
})
