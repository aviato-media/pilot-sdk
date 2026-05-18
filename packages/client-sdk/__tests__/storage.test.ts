import { describe, expect, test } from 'bun:test'

import { MemoryStorageBackend } from '../src/storage.js'

describe('MemoryStorageBackend', () => {
  test('identity round-trip', async () => {
    const s = new MemoryStorageBackend()
    expect(await s.getIdentity()).toBeNull()
    await s.setIdentity({
      certSignature: 'sig',
      clientEncPrivBase64url: 'priv',
      clientId: 'cid',
      clientPrivBase64url: 'priv',
      exp: 100,
      iat: 0,
      signedCertBytes: 'bytes',
      userPubKey: 'a'.repeat(64),
    })
    const got = await s.getIdentity()
    expect(got?.clientId).toBe('cid')
    await s.setIdentity(null)
    expect(await s.getIdentity()).toBeNull()
  })

  test('upsertServerKey replaces matching server in place', async () => {
    const s = new MemoryStorageBackend()
    await s.upsertServerKey({
      connInfoKey: 'k1',
      serverPubKey: 'a',
    })
    await s.upsertServerKey({
      connInfoKey: 'k2',
      serverPubKey: 'a',
    })
    await s.upsertServerKey({
      connInfoKey: 'k3',
      serverPubKey: 'b',
    })
    const bundle = await s.getBundle()
    expect(bundle?.servers).toHaveLength(2)
    expect(bundle?.servers.find((x) => x.serverPubKey === 'a')?.connInfoKey).toBe('k2')
  })

  test('setServerToken(null) deletes', async () => {
    const s = new MemoryStorageBackend()
    await s.setServerToken('a', {
      expiresAt: 'iso',
      token: 't',
    })
    expect(await s.getServerToken('a')).not.toBeNull()
    await s.setServerToken('a', null)
    expect(await s.getServerToken('a')).toBeNull()
  })
})
