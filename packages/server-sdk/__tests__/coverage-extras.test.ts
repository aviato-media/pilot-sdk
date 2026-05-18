// Coverage-targeted tests for branches the happy-path PairingService
// e2e test doesn't exercise.

import {
  base64urlEncode,
  buildPairingAssertion,
  generateEd25519Keypair,
  generateX25519Keypair,
  hexEncode,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { TowerHttpError } from '../src/tower-client.js'
import { verifyServerLinkAssertion, verifyServerSignInAssertion } from '../src/verify.js'

describe('TowerHttpError', () => {
  test('carries status + body alongside the message', () => {
    const err = new TowerHttpError('rate limited', 429, { detail: 'slow down' })
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('TowerHttpError')
    expect(err.message).toBe('rate limited')
    expect(err.status).toBe(429)
    expect(err.body).toEqual({ detail: 'slow down' })
  })

  test('body is optional', () => {
    const err = new TowerHttpError('boom', 500)
    expect(err.status).toBe(500)
    expect(err.body).toBeUndefined()
  })
})

describe('verifyServerLinkAssertion error branches', () => {
  test('returns ok:false with the inner error code when the assertion fails verification', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const other = generateEd25519Keypair()
    const env = buildPairingAssertion({
      masterPrivKey: user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: 'req_x',
        serverPubKey: hexEncode(server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    // Wrong expected server — the inner verifier returns wrong_server.
    const r = verifyServerLinkAssertion({
      envelope: env,
      expectedRequestId: 'req_x',
      expectedServerPubKey: other.publicKey,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('wrong_server')
    }
  })

  test('returns ok:false on signature tamper', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const env = buildPairingAssertion({
      masterPrivKey: user.privateKey,
      payload: {
        kind: 'server-link',
        requestId: 'req_y',
        serverPubKey: hexEncode(server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    // Flip a bit in the sig.
    const sigBytes = Buffer.from(env.assertionSignature, 'base64url')
    sigBytes[0] = sigBytes[0]! ^ 0xff
    const tampered = {
      ...env,
      assertionSignature: base64urlEncode(new Uint8Array(sigBytes)),
    }
    const r = verifyServerLinkAssertion({
      envelope: tampered,
      expectedRequestId: 'req_y',
      expectedServerPubKey: server.publicKey,
    })
    expect(r.ok).toBe(false)
  })
})

describe('verifyServerSignInAssertion happy + mismatch', () => {
  test('happy path passes with expectedUserPubKey set', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const env = buildPairingAssertion({
      masterPrivKey: user.privateKey,
      payload: {
        kind: 'server-sign-in',
        requestId: 'req_s',
        serverPubKey: hexEncode(server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    const r = verifyServerSignInAssertion({
      envelope: env,
      expectedRequestId: 'req_s',
      expectedServerPubKey: server.publicKey,
      expectedUserPubKey: user.publicKey,
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.userPubKey).toBe(hexEncode(user.publicKey))
    }
  })

  test('rejected when expectedUserPubKey mismatches', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const server = generateEd25519Keypair()
    const other = generateEd25519Keypair()
    const env = buildPairingAssertion({
      masterPrivKey: user.privateKey,
      payload: {
        kind: 'server-sign-in',
        requestId: 'req_s2',
        serverPubKey: hexEncode(server.publicKey),
        ts: Date.now(),
        userEncPubKey: hexEncode(userEnc.publicKey),
        userId: 'user_test',
        userPubKey: hexEncode(user.publicKey),
        v: 1,
      },
    })
    const r = verifyServerSignInAssertion({
      envelope: env,
      expectedRequestId: 'req_s2',
      expectedServerPubKey: server.publicKey,
      expectedUserPubKey: other.publicKey,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error).toBe('user_pubkey_mismatch')
    }
  })
})
