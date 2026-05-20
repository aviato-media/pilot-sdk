// Tower-side: build cert + sealed K bundle for a client-pair approval.
// Verify the SDK's outputs round-trip through pilot-core verifiers.

import {
  base64urlDecode,
  generateEd25519Keypair,
  generateX25519Keypair,
  openClientBundle,
  randomAesKey,
  verifyClientCert,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { buildClientPairBundle, buildClientPairCert } from '../src/client-pair.js'

describe('client-pair builders', () => {
  test('cert verifies against userPubKey', () => {
    const user = generateEd25519Keypair()
    const userEnc = generateX25519Keypair()
    const client = generateEd25519Keypair()
    const clientEnc = generateX25519Keypair()
    const cert = buildClientPairCert({
      appId: 'aviato-web',
      clientEncPubKey: clientEnc.publicKey.toRaw(),
      clientId: '00000000-0000-4000-8000-000000000010',
      clientPubKey: client.publicKey.toRaw(),
      deviceName: 'Test',
      scope: ['identity'],
      userEncPubKey: userEnc.publicKey.toRaw(),
      userId: 'user_test',
      userKey: user,
    })
    const verified = verifyClientCert(cert, { expectedUserPubKey: user.publicKey })
    expect(verified.ok).toBe(true)
    if (verified.ok) {
      expect(verified.payload.appId).toBe('aviato-web')
    }
  })

  test('sealed bundle opens for the right client', async () => {
    const client = generateX25519Keypair()
    const K = randomAesKey()
    const bundle = await buildClientPairBundle({
      clientEncPubKey: client.publicKey.toRaw(),
      servers: [{
        connInfoKey: K,
        serverPubKey: new Uint8Array(32).fill(0xaa),
      }],
    })
    const opened = await openClientBundle({
      box: bundle,
      clientEncPrivKey: client.privateKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.bundle.servers).toHaveLength(1)
      expect(base64urlDecode(opened.bundle.servers[0]!.connInfoKey)).toEqual(K)
    }
  })
})
