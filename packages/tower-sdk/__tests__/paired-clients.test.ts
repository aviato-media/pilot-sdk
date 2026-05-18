// Tests for the paired-clients registry surface: store CRUD, the
// row→view mapper, and the null-K filter in client-pair bundle building.

import {
  base64urlDecode,
  generateX25519Keypair,
  openClientBundle,
  type PairedClientRow,
  randomAesKey,
} from '@aviato-media/pilot-core'
import { describe, expect, test } from 'bun:test'

import { buildClientPairBundle } from '../src/client-pair.js'
import {
  MemoryPairedClientStore,
  toPairedClientView,
} from '../src/stores.js'

function sampleRow (overrides: Partial<PairedClientRow> = {}): PairedClientRow {
  return {
    appId: 'aviato-web',
    certExpiresAt: '2099-01-01T00:00:00.000Z',
    clientEncPubKey: '1'.repeat(64),
    clientId: '00000000-0000-4000-8000-000000000001',
    clientPubKey: '2'.repeat(64),
    deviceName: 'Test Device',
    lastSeenAt: null,
    pairedAt: '2026-01-01T00:00:00.000Z',
    revoked: false,
    scope: ['identity'],
    servers: ['a'.repeat(64), 'b'.repeat(64)],
    userId: 'user_test',
    ...overrides,
  }
}

describe('MemoryPairedClientStore', () => {
  test('upsert + get + listByUser round-trip', async () => {
    const store = new MemoryPairedClientStore()
    await store.upsert(sampleRow({ clientId: '00000000-0000-4000-8000-000000000001' }))
    await store.upsert(sampleRow({
      clientId: '00000000-0000-4000-8000-000000000002',
      deviceName: 'Phone',
    }))
    await store.upsert(sampleRow({
      clientId: '00000000-0000-4000-8000-000000000003',
      userId: 'other_user',
    }))

    expect(await store.get('00000000-0000-4000-8000-000000000001')).not.toBeNull()
    expect((await store.get('00000000-0000-4000-8000-000000000002'))?.deviceName).toBe('Phone')

    const list = await store.listByUser('user_test')
    expect(list).toHaveLength(2)
    expect(list.every((r) => r.userId === 'user_test')).toBe(true)
  })

  test('revoke flips the flag', async () => {
    const store = new MemoryPairedClientStore()
    await store.upsert(sampleRow())
    expect((await store.get('00000000-0000-4000-8000-000000000001'))?.revoked).toBe(false)
    await store.revoke('00000000-0000-4000-8000-000000000001')
    expect((await store.get('00000000-0000-4000-8000-000000000001'))?.revoked).toBe(true)
  })

  test('markSeen updates lastSeenAt', async () => {
    const store = new MemoryPairedClientStore()
    await store.upsert(sampleRow())
    expect((await store.get('00000000-0000-4000-8000-000000000001'))?.lastSeenAt).toBeNull()
    await store.markSeen('00000000-0000-4000-8000-000000000001', '2026-06-01T12:00:00.000Z')
    expect((await store.get('00000000-0000-4000-8000-000000000001'))?.lastSeenAt).toBe('2026-06-01T12:00:00.000Z')
  })
})

describe('PairedClientDetailListResponse (renewal context wire shape)', () => {
  test('parses a list of full rows', async () => {
    const { PairedClientDetailListResponseSchema } = await import('@aviato-media/pilot-core')
    const wire = { clients: [sampleRow(), sampleRow({ clientId: '00000000-0000-4000-8000-000000000002' })] }
    const parsed = PairedClientDetailListResponseSchema.safeParse(wire)
    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.clients).toHaveLength(2)
      // Critical: cert pubs MUST be present so cert-preissue can build a new cert.
      expect(parsed.data.clients[0]!.clientPubKey).toBe('2'.repeat(64))
      expect(parsed.data.clients[0]!.clientEncPubKey).toBe('1'.repeat(64))
      expect(parsed.data.clients[0]!.scope).toEqual(['identity'])
      expect(parsed.data.clients[0]!.servers).toEqual(['a'.repeat(64), 'b'.repeat(64)])
    }
  })

  test('rejects a wire body missing cert pubs', async () => {
    const { PairedClientDetailListResponseSchema } = await import('@aviato-media/pilot-core')
    const { clientPubKey: _omit, ...rowWithoutPub } = sampleRow()
    const parsed = PairedClientDetailListResponseSchema.safeParse({ clients: [rowWithoutPub] })
    expect(parsed.success).toBe(false)
  })
})

describe('toPairedClientView', () => {
  test('strips internal fields and computes serverCount', () => {
    const view = toPairedClientView(sampleRow())
    expect(view.serverCount).toBe(2)
    expect(view.clientId).toBe('00000000-0000-4000-8000-000000000001')
    expect(view.deviceName).toBe('Test Device')
    expect(view.revoked).toBe(false)
    // Internal fields not present on the view:
    expect((view as unknown as Record<string, unknown>).clientPubKey).toBeUndefined()
    expect((view as unknown as Record<string, unknown>).clientEncPubKey).toBeUndefined()
    expect((view as unknown as Record<string, unknown>).scope).toBeUndefined()
    expect((view as unknown as Record<string, unknown>).servers).toBeUndefined()
  })

  test('enriches with app-registry metadata when provided', () => {
    const view = toPairedClientView(sampleRow(), {
      icon: 'https://example.com/icon.png',
      name: 'Aviato Web',
      verified: true,
    })
    expect(view.appName).toBe('Aviato Web')
    expect(view.appIcon).toBe('https://example.com/icon.png')
    expect(view.appVerified).toBe(true)
  })
})

describe('buildClientPairBundle filters null connInfoKey entries', () => {
  test('skips pending servers (K not yet delivered)', async () => {
    const client = generateX25519Keypair()
    const K = randomAesKey()
    const serverWithK = new Uint8Array(32).fill(0xcc)
    const serverPending = new Uint8Array(32).fill(0xdd)

    const sealed = await buildClientPairBundle({
      clientEncPubKey: client.publicKey.toRaw(),
      servers: [
        {
          connInfoKey: K,
          serverPubKey: serverWithK,
        },
        {
          connInfoKey: null,
          serverPubKey: serverPending,
        },
      ],
    })
    const opened = await openClientBundle({
      box: sealed,
      clientEncPrivKey: client.privateKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.bundle.servers).toHaveLength(1)
      expect(opened.bundle.servers[0]!.serverPubKey).toBe('c'.repeat(64))
      expect(base64urlDecode(opened.bundle.servers[0]!.connInfoKey)).toEqual(K)
    }
  })

  test('all-pending input yields an empty server list (sealed bundle still valid)', async () => {
    const client = generateX25519Keypair()
    const sealed = await buildClientPairBundle({
      clientEncPubKey: client.publicKey.toRaw(),
      servers: [{
        connInfoKey: null,
        serverPubKey: new Uint8Array(32).fill(0xee),
      }],
    })
    const opened = await openClientBundle({
      box: sealed,
      clientEncPrivKey: client.privateKey,
    })
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.bundle.servers).toHaveLength(0)
    }
  })
})
