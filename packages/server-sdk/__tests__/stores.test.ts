// Unit coverage for the MemoryStore implementations in stores.ts. The
// integration tests exercise the `put`/`get` happy paths; this file
// covers the `consume` / `list` / `revoke` / `isRevoked` / TTL branches
// the integration test doesn't hit, plus the `upsertUserEncPubKey`
// rebind path.

import { describe, expect, test } from 'bun:test'

import type { IdentityClientRow, IdentityUserRow, PairingRequestRow } from '../src/stores.js'
import {
  MemoryIdentityClientStore,
  MemoryIdentityUserStore,
  MemoryPairingRequestStore,
  MemorySessionChallengeStore,
} from '../src/stores.js'

describe('MemoryPairingRequestStore', () => {
  test('put + get round-trip; get returns null for unknown', async () => {
    const s = new MemoryPairingRequestStore()
    const row: PairingRequestRow = {
      code: '12345678',
      inviteToken: null,
      localUserId: null,
      purpose: 'invite',
      requestId: 'req_a',
      towerExpiresAt: '2099-01-01T00:00:00.000Z',
    }
    await s.put(row)
    expect(await s.get('req_a')).toEqual(row)
    expect(await s.get('does-not-exist')).toBeNull()
  })

  test('consume returns + deletes the row; second consume returns null', async () => {
    const s = new MemoryPairingRequestStore()
    const row: PairingRequestRow = {
      code: '12345678',
      inviteToken: null,
      localUserId: null,
      purpose: 'invite',
      requestId: 'req_b',
      towerExpiresAt: '2099-01-01T00:00:00.000Z',
    }
    await s.put(row)
    const first = await s.consume('req_b')
    expect(first).toEqual(row)
    const second = await s.consume('req_b')
    expect(second).toBeNull()
  })

  test('consume on unknown id returns null without throwing', async () => {
    const s = new MemoryPairingRequestStore()
    expect(await s.consume('nope')).toBeNull()
  })
})

describe('MemoryIdentityClientStore', () => {
  const makeRow = (overrides: Partial<IdentityClientRow> = {}): IdentityClientRow => ({
    certExpiresAt: '2099-01-01T00:00:00.000Z',
    clientEncPubKey: 'a'.repeat(64),
    clientId: '00000000-0000-4000-8000-000000000001',
    clientPubKey: 'b'.repeat(64),
    deviceName: 'Test',
    lastSeenAt: '2025-01-01T00:00:00.000Z',
    revoked: false,
    userId: 'user_test',
    ...overrides,
  })

  test('upsert + get round-trip; get returns null for unknown', async () => {
    const s = new MemoryIdentityClientStore()
    const row = makeRow()
    await s.upsert(row)
    expect(await s.get(row.clientId)).toEqual(row)
    expect(await s.get('00000000-0000-4000-8000-ffffffffffff')).toBeNull()
  })

  test('list filters by userId', async () => {
    const s = new MemoryIdentityClientStore()
    await s.upsert(makeRow({
      clientId: '00000000-0000-4000-8000-00000000000a',
      userId: 'alice',
    }))
    await s.upsert(makeRow({
      clientId: '00000000-0000-4000-8000-00000000000b',
      userId: 'bob',
    }))
    await s.upsert(makeRow({
      clientId: '00000000-0000-4000-8000-00000000000c',
      userId: 'alice',
    }))
    const alices = await s.list('alice')
    expect(alices).toHaveLength(2)
    expect(alices.every((r) => r.userId === 'alice')).toBe(true)
    expect(await s.list('charlie')).toHaveLength(0)
  })

  test('revoke flips the flag; isRevoked reflects it', async () => {
    const s = new MemoryIdentityClientStore()
    const row = makeRow()
    await s.upsert(row)
    expect(await s.isRevoked(row.clientId)).toBe(false)
    await s.revoke(row.clientId)
    expect(await s.isRevoked(row.clientId)).toBe(true)
    // The row's other fields are preserved (only `revoked` changes).
    const after = await s.get(row.clientId)
    expect(after?.deviceName).toBe('Test')
  })

  test('revoke on unknown clientId is a no-op (no throw)', async () => {
    const s = new MemoryIdentityClientStore()
    await s.revoke('not-there')
    expect(await s.isRevoked('not-there')).toBe(false)
  })

  test('isRevoked returns false for unknown clientId', async () => {
    const s = new MemoryIdentityClientStore()
    expect(await s.isRevoked('unknown')).toBe(false)
  })
})

describe('MemorySessionChallengeStore', () => {
  test('create returns a hex challenge with timestamp; consume removes it', async () => {
    const s = new MemorySessionChallengeStore()
    const issued = await s.create()
    expect(issued.challenge).toMatch(/^[0-9a-f]{32}$/)
    expect(issued.issuedAtMs).toBeGreaterThan(0)
    const consumed = await s.consume(issued.challenge)
    expect(consumed?.challenge).toBe(issued.challenge)
    expect(await s.consume(issued.challenge)).toBeNull()
  })

  test('consume on unknown challenge returns null', async () => {
    const s = new MemorySessionChallengeStore()
    expect(await s.consume('aabbccdd'.repeat(4))).toBeNull()
  })

  test('TTL cleanup eventually drops the challenge', async () => {
    const s = new MemorySessionChallengeStore()
    const issued = await s.create(5)
    // Wait past the TTL.
    await new Promise((r) => setTimeout(r, 20))
    expect(await s.consume(issued.challenge)).toBeNull()
  })
})

describe('MemoryIdentityUserStore', () => {
  const userRow: IdentityUserRow = {
    id: 'user_xyz',
    towerUserId: 'tower_user_xyz',
    userEncPubKey: 'a'.repeat(64),
    userPubKey: 'b'.repeat(64),
  }

  test('seed + getByPublicKey round-trip', async () => {
    const s = new MemoryIdentityUserStore()
    s.seed(userRow)
    expect(await s.getByPublicKey(userRow.userPubKey)).toEqual(userRow)
    expect(await s.getByPublicKey('c'.repeat(64))).toBeNull()
  })

  test('upsertUserEncPubKey rebinds the encryption key on every matching row', async () => {
    const s = new MemoryIdentityUserStore()
    s.seed(userRow)
    const fresh = 'd'.repeat(64)
    await s.upsertUserEncPubKey(userRow.id, fresh)
    const after = await s.getByPublicKey(userRow.userPubKey)
    expect(after?.userEncPubKey).toBe(fresh)
  })

  test('upsertUserEncPubKey is a no-op for unknown userId', async () => {
    const s = new MemoryIdentityUserStore()
    s.seed(userRow)
    await s.upsertUserEncPubKey('unknown', 'e'.repeat(64))
    const after = await s.getByPublicKey(userRow.userPubKey)
    expect(after?.userEncPubKey).toBe(userRow.userEncPubKey) // unchanged
  })
})
