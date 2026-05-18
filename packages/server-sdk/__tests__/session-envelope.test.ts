// Coverage for server-sdk session-envelope.ts: sealSessionConnInfoEnvelope
// produces a sealedbox the client can open into a SessionConnInfoEnvelope.

import {
  aviatoSealedBoxDecryptJson,
  generateX25519Keypair,
  randomAesKey,
  SessionConnInfoEnvelopeSchema,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { sealSessionConnInfoEnvelope } from '../src/session-envelope.js'

describe('sealSessionConnInfoEnvelope', () => {
  test('round-trip: client decrypts and the shape matches the schema', async () => {
    const client = generateX25519Keypair()
    const K = randomAesKey()
    const sealed = await sealSessionConnInfoEnvelope({
      clientEncPubKey: client.publicKey.toRaw(),
      connInfoKey: K,
      issuedAtSec: 1234,
    })
    const decoded = await aviatoSealedBoxDecryptJson<unknown>({
      box: sealed,
      recipientPriv: client.privateKey,
    })
    expect(decoded).not.toBeNull()
    const parsed = SessionConnInfoEnvelopeSchema.safeParse(decoded)
    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.issuedAtSec).toBe(1234)
      // connInfoKey is base64url-encoded inside the envelope.
      expect(parsed.data.connInfoKey).toMatch(/^[A-Za-z0-9_-]+$/)
    }
  })
  test('defaults issuedAtSec when not provided', async () => {
    const client = generateX25519Keypair()
    const before = Math.floor(Date.now() / 1000)
    const sealed = await sealSessionConnInfoEnvelope({
      clientEncPubKey: client.publicKey.toRaw(),
      connInfoKey: randomAesKey(),
    })
    const after = Math.floor(Date.now() / 1000)
    const decoded = await aviatoSealedBoxDecryptJson<{ issuedAtSec: number }>({
      box: sealed,
      recipientPriv: client.privateKey,
    })
    expect(decoded).not.toBeNull()
    expect(decoded!.issuedAtSec).toBeGreaterThanOrEqual(before)
    expect(decoded!.issuedAtSec).toBeLessThanOrEqual(after)
  })
  test('wrong recipient cannot open', async () => {
    const realClient = generateX25519Keypair()
    const eve = generateX25519Keypair()
    const sealed = await sealSessionConnInfoEnvelope({
      clientEncPubKey: realClient.publicKey.toRaw(),
      connInfoKey: randomAesKey(),
    })
    const decoded = await aviatoSealedBoxDecryptJson<unknown>({
      box: sealed,
      recipientPriv: eve.privateKey,
    })
    expect(decoded).toBeNull()
  })
})
