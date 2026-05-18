// Vault round-trip + multi-passkey wrap/unwrap tests.

import { generateEd25519Keypair, generateX25519Keypair, hexEncode } from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import {
  addPasskeyToVault,
  bytesToB64u,
  createVault,
  generateVaultKey,
  openVault,
  removePasskeyFromVault,
  replaceVaultPayload,
} from '../src/vault.js'

async function fakePrfWrappingKey (seed: number): Promise<CryptoKey> {
  // Use a deterministic 32-byte input to derive an AES-GCM key — mimics
  // what derivePrfWrappingKey produces from real PRF output, without
  // needing a real authenticator.
  const raw = new Uint8Array(32).fill(seed)
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

function samplePayload () {
  const user = generateEd25519Keypair()
  const userEnc = generateX25519Keypair()
  return {
    masterPrivKey: bytesToB64u(user.privateKey.toRaw()),
    masterPubKey: hexEncode(user.publicKey),
    servers: [],
    userEncPrivKey: bytesToB64u(userEnc.privateKey.toRaw()),
    userEncPubKey: hexEncode(userEnc.publicKey),
    v: 1 as const,
  }
}

describe('vault', () => {
  test('create → open round-trip', async () => {
    const wrappingKey = await fakePrfWrappingKey(1)
    const payload = samplePayload()
    const { blob } = await createVault({
      credentialId: 'cred_1',
      payload,
      prfSalt: 'salt_1',
      prfWrappingKey: wrappingKey,
    })
    const opened = await openVault({
      blob,
      credentialId: 'cred_1',
      prfWrappingKey: wrappingKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.payload.masterPubKey).toBe(payload.masterPubKey)
    }
  })

  test('wrong wrapping key fails unwrap', async () => {
    const wk1 = await fakePrfWrappingKey(1)
    const wk2 = await fakePrfWrappingKey(2)
    const { blob } = await createVault({
      credentialId: 'cred_1',
      payload: samplePayload(),
      prfSalt: 'salt_1',
      prfWrappingKey: wk1,
    })
    const opened = await openVault({
      blob,
      credentialId: 'cred_1',
      prfWrappingKey: wk2,
    })
    expect(opened.ok).toBe(false)
    if (!opened.ok) {
      expect(opened.error).toBe('unwrap_failed')
    }
  })

  test('add second passkey, open with either', async () => {
    const wk1 = await fakePrfWrappingKey(1)
    const wk2 = await fakePrfWrappingKey(2)
    const { blob: blob1, vk } = await createVault({
      credentialId: 'cred_1',
      payload: samplePayload(),
      prfSalt: 'salt_1',
      prfWrappingKey: wk1,
    })
    const blob2 = await addPasskeyToVault({
      blob: blob1,
      credentialId: 'cred_2',
      newPrfWrappingKey: wk2,
      prfSalt: 'salt_2',
      vk,
    })
    expect(blob2.wraps).toHaveLength(2)

    const opened1 = await openVault({
      blob: blob2,
      credentialId: 'cred_1',
      prfWrappingKey: wk1,
    })
    const opened2 = await openVault({
      blob: blob2,
      credentialId: 'cred_2',
      prfWrappingKey: wk2,
    })
    expect(opened1.ok).toBe(true)
    expect(opened2.ok).toBe(true)
  })

  test('removePasskeyFromVault drops the wrap', async () => {
    const wk1 = await fakePrfWrappingKey(1)
    const wk2 = await fakePrfWrappingKey(2)
    const { blob, vk } = await createVault({
      credentialId: 'cred_1',
      payload: samplePayload(),
      prfSalt: 'salt_1',
      prfWrappingKey: wk1,
    })
    const blob2 = await addPasskeyToVault({
      blob,
      credentialId: 'cred_2',
      newPrfWrappingKey: wk2,
      prfSalt: 'salt_2',
      vk,
    })
    const blob3 = removePasskeyFromVault(blob2, 'cred_1')
    expect(blob3.wraps).toHaveLength(1)
    expect(blob3.wraps[0]!.credentialId).toBe('cred_2')

    const reopen = await openVault({
      blob: blob3,
      credentialId: 'cred_1',
      prfWrappingKey: wk1,
    })
    expect(reopen.ok).toBe(false)
    if (!reopen.ok) {
      expect(reopen.error).toBe('wrap_not_found')
    }
  })

  test('replaceVaultPayload preserves wraps', async () => {
    const wk = await fakePrfWrappingKey(1)
    const { blob, vk } = await createVault({
      credentialId: 'cred_1',
      payload: samplePayload(),
      prfSalt: 'salt_1',
      prfWrappingKey: wk,
    })
    const newPayload = {
      ...samplePayload(),
      servers: [],
    }
    const blob2 = await replaceVaultPayload({
      blob,
      payload: newPayload,
      vk,
    })
    expect(blob2.wraps).toEqual(blob.wraps)
    const opened = await openVault({
      blob: blob2,
      credentialId: 'cred_1',
      prfWrappingKey: wk,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.payload.masterPubKey).toBe(newPayload.masterPubKey)
    }
  })

  test('vault payload survives a null connInfoKey on a server entry', async () => {
    const wk = await fakePrfWrappingKey(1)
    const base = samplePayload()
    const payload = {
      ...base,
      servers: [{
        addedAt: '2026-01-01T00:00:00.000Z',
        connInfoKey: null,
        displayName: 'Pending Server',
        serverPubKey: 'a'.repeat(64),
      }],
    }
    const { blob } = await createVault({
      credentialId: 'cred_1',
      payload,
      prfSalt: 'salt_1',
      prfWrappingKey: wk,
    })
    const opened = await openVault({
      blob,
      credentialId: 'cred_1',
      prfWrappingKey: wk,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.payload.servers).toHaveLength(1)
      expect(opened.payload.servers[0]!.connInfoKey).toBeNull()
    }
  })

  test('generateVaultKey produces a usable AES-GCM key', async () => {
    const vk = await generateVaultKey()
    const data = new TextEncoder().encode('hello')
    const ct = await crypto.subtle.encrypt({
      iv: new Uint8Array(12),
      name: 'AES-GCM',
    }, vk, data.buffer as ArrayBuffer)
    expect(ct.byteLength).toBeGreaterThan(0)
  })
})
