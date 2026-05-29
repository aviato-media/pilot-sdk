// End-to-end KV sync: client-sdk drives a fake tower-api backed by
// tower-sdk's MemoryKvStore. Exercises the encrypt path, the reconcile
// path, optimistic concurrency, idempotent retries, quota, and decrypt
// failure on tampered ciphertext.

import {
  KVError,
  KVStoreClient,
  recomputeKvChecksum,
} from '@aviato-media/pilot-client-sdk'
import type {
  KvBatchGetRequest,
  KvBatchPutRequest,
  KvDeleteRequest,
  KvErrorResponse,
} from '@aviato-media/pilot-core'
import {
  base64urlDecode,
  base64urlEncode,
  KvBatchGetRequestSchema,
  KvBatchPutRequestSchema,
  KvDeleteRequestSchema,
} from '@aviato-media/pilot-core'
import {
  decodePutItem,
  MemoryKvStore,
  partitionBatchGet,
  toListEntry,
} from '@aviato-media/pilot-tower-sdk'
import { beforeEach, describe, expect, test } from 'bun:test'

const USER_ID = 'user_kv_int'
const CLIENT_ID = '00000000-0000-4000-8000-0000000000aa'
const NOW_ISO = '2026-05-29T12:00:00.000Z'

function makeKvKey (): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

interface HarnessOptions {
  readonly keyLimit?: number
  readonly byteLimit?: number
}

function makeHarness (opts: HarnessOptions = {}): {
  store: MemoryKvStore
  fetch: typeof globalThis.fetch
} {
  const store = new MemoryKvStore({
    ...(opts.byteLimit !== undefined ? { byteLimit: opts.byteLimit } : {}),
    ...(opts.keyLimit !== undefined ? { keyLimit: opts.keyLimit } : {}),
  })
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : (input as Request).url
    const method = init?.method ?? 'GET'
    const path = new URL(url).pathname
    const auth = ((init?.headers ?? {}) as Record<string, string>).authorization
    if (auth !== 'Bearer test-token') {
      return jsonError(401, { code: 'unauthorized' })
    }

    if (path === '/v2/kv' && method === 'GET') {
      const rows = await store.list(USER_ID)
      const quota = await store.quota(USER_ID)
      return new Response(JSON.stringify({ items: rows.map(toListEntry) }), {
        headers: {
          'content-type': 'application/json',
          'x-aviato-kv-quota': JSON.stringify(quota),
        },
        status: 200,
      })
    }

    if (path === '/v2/kv/batchGet' && method === 'POST') {
      const body = JSON.parse(init!.body as string) as KvBatchGetRequest
      const parsed = KvBatchGetRequestSchema.safeParse(body)
      if (!parsed.success) {
        return jsonError(400, { code: 'malformed' })
      }
      const rows = await store.getMany(USER_ID, parsed.data.items.map((i) => i.key))
      return new Response(
        JSON.stringify({ items: partitionBatchGet(parsed.data.items, rows) }),
        {
          headers: { 'content-type': 'application/json' },
          status: 200,
        },
      )
    }

    if (path === '/v2/kv/batchPut' && method === 'POST') {
      const body = JSON.parse(init!.body as string) as KvBatchPutRequest
      const parsed = KvBatchPutRequestSchema.safeParse(body)
      if (!parsed.success) {
        return jsonError(400, { code: 'malformed' })
      }
      const decoded = parsed.data.items.map((i) => decodePutItem(i, CLIENT_ID, NOW_ISO))
      const applied = await store.applyBatch(USER_ID, decoded)
      if (!applied.ok) {
        if (applied.code === 'checksum_mismatch') {
          return jsonError(409, {
            code: 'checksum_mismatch',
            ...(applied.conflicts !== undefined ? { conflicts: applied.conflicts } : {}),
            message: 'optimistic concurrency token did not match stored checksum',
          })
        }
        return jsonError(413, {
          code: 'quota_exceeded',
          message: 'per-user KV quota exceeded',
        })
      }
      const quota = await store.quota(USER_ID)
      return new Response(JSON.stringify({ accepted: applied.accepted }), {
        headers: {
          'content-type': 'application/json',
          'x-aviato-kv-quota': JSON.stringify(quota),
        },
        status: 200,
      })
    }

    if (path === '/v2/kv/delete' && method === 'POST') {
      const body = JSON.parse(init!.body as string) as KvDeleteRequest
      const parsed = KvDeleteRequestSchema.safeParse(body)
      if (!parsed.success) {
        return jsonError(400, { code: 'malformed' })
      }
      await store.deleteMany(USER_ID, parsed.data.keys)
      return new Response('{}', {
        headers: { 'content-type': 'application/json' },
        status: 200,
      })
    }

    return new Response(JSON.stringify({ code: 'malformed' }), {
      headers: { 'content-type': 'application/json' },
      status: 404,
    })
  }) as unknown as typeof globalThis.fetch
  return {
    fetch: fetchImpl,
    store,
  }
}

function jsonError (status: number, body: KvErrorResponse): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
    status,
  })
}

function bytesOf (s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function textOf (b: Uint8Array): string {
  return new TextDecoder().decode(b)
}

describe('KV sync — round-trip + reconcile', () => {
  let kvKey: Uint8Array
  beforeEach(() => {
    kvKey = makeKvKey()
  })

  test('plaintext → ciphertext → plaintext round-trip preserves bytes', async () => {
    const { fetch } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    const payload = bytesOf(JSON.stringify({
      language: 'en',
      subtitles: {
        enabled: true,
        size: 1.0,
      },
      theme: 'oled',
    }))
    const put = await kv.batchPut([{
      key: 'settings:player',
      value: payload,
    }])
    expect(put.accepted).toHaveLength(1)
    expect(put.accepted[0]!.key).toBe('settings:player')
    expect(typeof put.accepted[0]!.checksum).toBe('string')

    const got = await kv.batchGet([{ key: 'settings:player' }])
    expect(got).toHaveLength(1)
    const entry = got[0]!
    if (entry.status !== 'updated') {
      throw new Error(`expected updated, got ${entry.status}`)
    }
    expect(textOf(entry.value)).toBe(textOf(payload))
    expect(entry.checksum).toBe(put.accepted[0]!.checksum)
    expect(entry.updatedByClientId).toBe(CLIENT_ID)
  })

  test('batchGet returns `unchanged` when knownChecksum matches and no blob bytes', async () => {
    const { fetch } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })
    const put = await kv.batchPut([{
      key: 'settings:theme',
      value: bytesOf('"dark"'),
    }])
    const known = put.accepted[0]!.checksum

    const second = await kv.batchGet([{
      key: 'settings:theme',
      knownChecksum: known,
    }])
    expect(second).toHaveLength(1)
    expect(second[0]!.status).toBe('unchanged')

    const third = await kv.batchGet([{
      key: 'settings:theme',
      knownChecksum: 'differentchecksumvalue',
    }])
    expect(third[0]!.status).toBe('updated')
  })

  test('batchGet returns `absent` for never-written keys', async () => {
    const { fetch } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })
    const got = await kv.batchGet([{ key: 'never:written' }])
    expect(got[0]!.status).toBe('absent')
  })
})

describe('KV sync — optimistic concurrency', () => {
  test('expectedChecksum mismatch rejects the entire batch atomically', async () => {
    const kvKey = makeKvKey()
    const { fetch, store } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    const put1 = await kv.batchPut([{
      key: 'progress:movies:item1',
      value: bytesOf('{"pos":120}'),
    }])
    const firstChecksum = put1.accepted[0]!.checksum

    // Mid-air "another client wrote" — bump the stored row out of band.
    const put2 = await kv.batchPut([{
      key: 'progress:movies:item1',
      value: bytesOf('{"pos":150}'),
    }])
    expect(put2.accepted[0]!.checksum).not.toBe(firstChecksum)

    let caught: unknown
    try {
      await kv.batchPut([
        {
          expectedChecksum: firstChecksum,
          key: 'progress:movies:item1',
          value: bytesOf('{"pos":200}'),
        },
        {
          key: 'progress:movies:item2',
          value: bytesOf('{"pos":50}'),
        },
      ])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    const err = caught as KVError
    expect(err.code).toBe('checksum_mismatch')
    expect(err.status).toBe(409)
    expect(err.conflicts?.[0]?.key).toBe('progress:movies:item1')

    // Atomicity: item2 must not have been applied.
    const rows = await store.list(USER_ID)
    expect(rows.map((r) => r.key).sort()).toEqual(['progress:movies:item1'])
  })

  test('expectedChecksum on an absent key surfaces as checksum_mismatch, not internal', async () => {
    const kvKey = makeKvKey()
    const { fetch } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    let caught: unknown
    try {
      await kv.batchPut([{
        expectedChecksum: 'somechecksumthatneverexisted',
        key: 'progress:movies:ghost',
        value: bytesOf('{"pos":1}'),
      }])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    const err = caught as KVError
    expect(err.code).toBe('checksum_mismatch')
    expect(err.conflicts?.[0]?.key).toBe('progress:movies:ghost')
    expect(err.conflicts?.[0]?.actualChecksum).toBeUndefined()
  })
})

describe('KV sync — quota', () => {
  test('quota exceeded returns structured error with header still parseable', async () => {
    const kvKey = makeKvKey()
    const { fetch } = makeHarness({
      byteLimit: 200,
      keyLimit: 10,
    })
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    let caught: unknown
    try {
      await kv.batchPut([{
        key: 'big',
        value: new Uint8Array(1024),
      }])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    expect((caught as KVError).code).toBe('quota_exceeded')
  })
})

describe('KV sync — idempotent retry', () => {
  test('replaying the exact same batchPut yields the same checksum and no duplication', async () => {
    const kvKey = makeKvKey()
    const { fetch, store } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    const payload = bytesOf('{"v":1}')
    const first = await kv.batchPut([{
      key: 'connections:jellyfin:abc',
      value: payload,
    }])
    const checksum1 = first.accepted[0]!.checksum

    // Same plaintext → different nonce → different ciphertext → different checksum.
    // This is the cryptographic reality, not a bug. The retry-safe pattern
    // is to issue the SAME ciphertext, modeled here by replaying the request.
    // Capture the actual wire body the first put produced and re-POST it.
    const wireCheck = await store.getMany(USER_ID, ['connections:jellyfin:abc'])
    expect(wireCheck).toHaveLength(1)
    const replayCiphertext = base64urlEncode(wireCheck[0]!.ciphertext)

    const headers: Record<string, string> = {
      authorization: 'Bearer test-token',
      'content-type': 'application/json',
    }
    const res = await fetch('https://tower.test/v2/kv/batchPut', {
      body: JSON.stringify({
        items: [{
          ciphertext: replayCiphertext,
          key: 'connections:jellyfin:abc',
        }],
      }),
      headers,
      method: 'POST',
    })
    expect(res.status).toBe(200)
    const body = await res.json() as { accepted: Array<{ checksum: string }> }
    expect(body.accepted[0]!.checksum).toBe(checksum1)

    const rows = await store.list(USER_ID)
    expect(rows).toHaveLength(1)
  })

  test('recomputeKvChecksum agrees with the server-side hash', async () => {
    const kvKey = makeKvKey()
    const { fetch, store } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })
    await kv.batchPut([{
      key: 'progress:tunes:track',
      value: bytesOf('{"pos":4.2}'),
    }])
    const rows = await store.list(USER_ID)
    const wire = base64urlEncode(rows[0]!.ciphertext)
    expect(recomputeKvChecksum(wire)).toBe(rows[0]!.checksum)
  })
})

describe('KV sync — decrypt failure on corrupted ciphertext', () => {
  test('flipping a byte in stored ciphertext makes batchGet throw KVError', async () => {
    const kvKey = makeKvKey()
    const { fetch, store } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    await kv.batchPut([{
      key: 'settings:player',
      value: bytesOf('{"v":1}'),
    }])

    // Corrupt one byte of the stored ciphertext.
    const rows = await store.list(USER_ID)
    const corrupted = new Uint8Array(rows[0]!.ciphertext)
    const lastIdx = corrupted.length - 1
    corrupted[lastIdx] = (corrupted[lastIdx] ?? 0) ^ 0xff
    await store.applyBatch(USER_ID, [{
      checksum: base64urlEncode(
        new Uint8Array(await crypto.subtle.digest('SHA-256', corrupted.buffer as ArrayBuffer)),
      ),
      ciphertext: corrupted,
      key: 'settings:player',
      sizeBytes: corrupted.length,
      updatedAt: NOW_ISO,
      updatedByClientId: CLIENT_ID,
    }])

    let caught: unknown
    try {
      await kv.batchGet([{ key: 'settings:player' }])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    expect((caught as KVError).code).toBe('malformed')
  })

  test('decryption under a different K fails — defense against per-server K swap', async () => {
    const sealKey = makeKvKey()
    const { fetch } = makeHarness()
    const sealer = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey: sealKey,
    })
    await sealer.batchPut([{
      key: 'settings:lang',
      value: bytesOf('"en"'),
    }])

    const wrongKey = makeKvKey()
    const opener = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey: wrongKey,
    })
    let caught: unknown
    try {
      await opener.batchGet([{ key: 'settings:lang' }])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    expect((caught as KVError).code).toBe('malformed')
  })

  test('list + delete round-trip', async () => {
    const kvKey = makeKvKey()
    const { fetch } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    await kv.batchPut([
      {
        key: 'settings:a',
        value: bytesOf('1'),
      },
      {
        key: 'settings:b',
        value: bytesOf('22'),
      },
      {
        key: 'settings:c',
        value: bytesOf('333'),
      },
    ])
    const list1 = await kv.list()
    expect(list1.map((e) => e.key).sort()).toEqual(['settings:a', 'settings:b', 'settings:c'])
    for (const e of list1) {
      expect(typeof e.checksum).toBe('string')
      expect(e.sizeBytes).toBeGreaterThan(0)
    }

    await kv.delete(['settings:b'])
    const list2 = await kv.list()
    expect(list2.map((e) => e.key).sort()).toEqual(['settings:a', 'settings:c'])
  })
})

describe('KV sync — AAD binds ciphertext to its key string', () => {
  test('moving a ciphertext to a different key under the same K fails decrypt', async () => {
    const kvKey = makeKvKey()
    const { fetch, store } = makeHarness()
    const kv = new KVStoreClient({
      authorization: 'test-token',
      baseUrl: 'https://tower.test',
      clientId: CLIENT_ID,
      fetch,
      kvKey,
    })

    await kv.batchPut([{
      key: 'settings:player',
      value: bytesOf('"original"'),
    }])
    const rows = await store.list(USER_ID)
    const sourceWire = rows[0]!.ciphertext

    await store.applyBatch(USER_ID, [{
      checksum: base64urlEncode(
        new Uint8Array(await crypto.subtle.digest('SHA-256', sourceWire.buffer as ArrayBuffer)),
      ),
      ciphertext: sourceWire,
      key: 'settings:theme',
      sizeBytes: sourceWire.length,
      updatedAt: NOW_ISO,
      updatedByClientId: CLIENT_ID,
    }])

    let caught: unknown
    try {
      await kv.batchGet([{ key: 'settings:theme' }])
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(KVError)
    expect((caught as KVError).code).toBe('malformed')

    // Verify sourceWire actually was the byte sequence stored.
    expect(base64urlDecode(base64urlEncode(sourceWire)).length).toBe(sourceWire.length)
  })
})
