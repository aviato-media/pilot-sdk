// Tower-mediated KV — client-side surface.
//
// Tower stores opaque ciphertext keyed by (userId, key). Callers pass
// plaintext bytes; this module seals/opens them under a per-user K and
// reconciles via the SHA-256 of the ciphertext bytes Tower stores.
//
// Wire envelope per blob is `nonce(12) ‖ aesGcmCiphertext`, base64url-
// encoded. AAD is `aviato-kv-blob-v1 ‖ utf8(keyString)` so a stolen
// ciphertext cannot be replayed under a different key.

import type {
  KvBatchGetItem,
  KvBatchGetRequest,
  KvBatchPutAccepted,
  KvBatchPutItem,
  KvBatchPutRequest,
  KvDeleteRequest,
  KvErrorCode,
  KvErrorResponse,
  KvListEntry,
  KvQuota,
} from '@aviato-media/pilot-core'
import {
  checksumKvBlob,
  KV_MAX_BLOB_BYTES,
  KV_MAX_KEY_LENGTH,
  KvBatchGetResponseSchema,
  KvBatchPutResponseSchema,
  KvErrorResponseSchema,
  KvListResponseSchema,
  KvQuotaSchema,
  openKvBlob,
  sealKvBlob,
} from '@aviato-media/pilot-core'

export class KVError extends Error {
  readonly code: KvErrorCode
  readonly status: number
  readonly conflicts?: KvErrorResponse['conflicts']
  readonly retryAfterMs?: number

  constructor (
    code: KvErrorCode,
    message: string,
    status: number,
    extras?: { conflicts?: KvErrorResponse['conflicts'],
      retryAfterMs?: number },
  ) {
    super(message)
    this.name = 'KVError'
    this.code = code
    this.status = status
    this.conflicts = extras?.conflicts
    this.retryAfterMs = extras?.retryAfterMs
  }
}

export interface KVStoreOptions {
  /** Tower base URL, no trailing slash. */
  readonly baseUrl: string
  /** Per-user 32-byte K used to AEAD-seal every blob. */
  readonly kvKey: Uint8Array
  /** Bearer presented as `Authorization: Bearer <token>`. Static or async. */
  readonly authorization: string | (() => Promise<string>)
  /** Optional fetch override (tests). */
  readonly fetch?: typeof globalThis.fetch
  /**
   * Optional client identifier surfaced in `updatedByClientId` audit
   * metadata. Tower also reads this from the cert it authenticates, so
   * this is purely a hint for the test fetch adapter.
   */
  readonly clientId?: string
}

export type KVGetResult
  = | { key: string,
    status: 'unchanged' }
  | { key: string,
    status: 'absent' }
  | { key: string,
    status: 'updated',
    value: Uint8Array,
    checksum: string,
    updatedAt: string,
    updatedByClientId: string | null }

export interface KVPutItem {
  readonly key: string
  readonly value: Uint8Array
  /** Optimistic-concurrency token — last known `checksum` from a prior get. */
  readonly expectedChecksum?: string
}

export interface KVPutAcceptedEntry {
  readonly key: string
  readonly checksum: string
  readonly updatedAt: string
}

export interface KVPutResult {
  readonly accepted: ReadonlyArray<KVPutAcceptedEntry>
  readonly quota?: KvQuota
}

export interface KVListEntry {
  readonly key: string
  readonly checksum: string
  readonly sizeBytes: number
  readonly updatedAt: string
  readonly updatedByClientId: string | null
}

export interface PilotKVStore {
  batchGet (items: ReadonlyArray<KvBatchGetItem>): Promise<KVGetResult[]>
  batchPut (items: ReadonlyArray<KVPutItem>): Promise<KVPutResult>
  delete (keys: ReadonlyArray<string>): Promise<void>
  list (): Promise<KVListEntry[]>
}

const KV_PATH = '/v2/kv'

export class KVStoreClient implements PilotKVStore {
  private readonly opts: KVStoreOptions
  private readonly fetchImpl: typeof globalThis.fetch
  private readonly baseUrl: string

  constructor (opts: KVStoreOptions) {
    if (opts.kvKey.length !== 32) {
      throw new Error(`KVStoreClient: kvKey must be 32 bytes, got ${opts.kvKey.length}`)
    }
    this.opts = opts
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  async batchGet (items: ReadonlyArray<KvBatchGetItem>): Promise<KVGetResult[]> {
    for (const item of items) {
      this.assertKeyLength(item.key)
    }
    const body: KvBatchGetRequest = { items: [...items] }
    const res = await this.request('POST', `${KV_PATH}/batchGet`, body)
    const parsed = await parseJsonOrThrow(res, KvBatchGetResponseSchema, 'batchGet')
    const out: KVGetResult[] = []
    for (const r of parsed.items) {
      if (r.status === 'unchanged' || r.status === 'absent') {
        out.push({
          key: r.key,
          status: r.status,
        })
        continue
      }
      const opened = await openKvBlob({
        ciphertext: r.ciphertext,
        key: r.key,
        kvKey: this.opts.kvKey,
      })
      if (!opened.ok) {
        throw new KVError(
          'malformed',
          `decrypt failed for key "${r.key}" (${opened.error}) — possible K mismatch or tamper`,
          200,
        )
      }
      out.push({
        checksum: r.checksum,
        key: r.key,
        status: 'updated',
        updatedAt: r.updatedAt,
        updatedByClientId: r.updatedByClientId,
        value: opened.value,
      })
    }
    return out
  }

  async batchPut (items: ReadonlyArray<KVPutItem>): Promise<KVPutResult> {
    const wireItems: KvBatchPutItem[] = []
    for (const item of items) {
      this.assertKeyLength(item.key)
      if (item.value.length > KV_MAX_BLOB_BYTES) {
        throw new KVError(
          'blob_too_large',
          `key "${item.key}" value is ${item.value.length} bytes (max ${KV_MAX_BLOB_BYTES})`,
          413,
        )
      }
      const sealed = await sealKvBlob({
        key: item.key,
        kvKey: this.opts.kvKey,
        value: item.value,
      })
      wireItems.push({
        ciphertext: sealed.ciphertext,
        key: item.key,
        ...(item.expectedChecksum !== undefined ? { expectedChecksum: item.expectedChecksum } : {}),
      })
    }
    const body: KvBatchPutRequest = { items: wireItems }
    const res = await this.request('POST', `${KV_PATH}/batchPut`, body)
    const parsed = await parseJsonOrThrow(res, KvBatchPutResponseSchema, 'batchPut')
    const quota = readQuotaHeader(res)
    const result: KVPutResult = {
      accepted: parsed.accepted.map((a: KvBatchPutAccepted) => ({
        checksum: a.checksum,
        key: a.key,
        updatedAt: a.updatedAt,
      })),
      ...(quota !== undefined ? { quota } : {}),
    }
    return result
  }

  async delete (keys: ReadonlyArray<string>): Promise<void> {
    for (const k of keys) {
      this.assertKeyLength(k)
    }
    const body: KvDeleteRequest = { keys: [...keys] }
    const res = await this.request('POST', `${KV_PATH}/delete`, body)
    if (!res.ok) {
      await throwApiError(res, 'delete')
    }
  }

  async list (): Promise<KVListEntry[]> {
    const res = await this.request('GET', KV_PATH)
    const parsed = await parseJsonOrThrow(res, KvListResponseSchema, 'list')
    return parsed.items.map((e: KvListEntry) => ({
      checksum: e.checksum,
      key: e.key,
      sizeBytes: e.sizeBytes,
      updatedAt: e.updatedAt,
      updatedByClientId: e.updatedByClientId,
    }))
  }

  private async request (method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const auth = typeof this.opts.authorization === 'string'
      ? this.opts.authorization
      : await this.opts.authorization()
    const headers: Record<string, string> = {
      authorization: `Bearer ${auth}`,
    }
    if (this.opts.clientId !== undefined) {
      headers['x-aviato-client-id'] = this.opts.clientId
    }
    if (body !== undefined) {
      headers['content-type'] = 'application/json'
    }
    return this.fetchImpl(`${this.baseUrl}${path}`, {
      headers,
      method,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
  }

  private assertKeyLength (key: string): void {
    if (key.length === 0 || key.length > KV_MAX_KEY_LENGTH) {
      throw new KVError(
        'key_too_long',
        `KV key length ${key.length} out of bounds (1..${KV_MAX_KEY_LENGTH})`,
        400,
      )
    }
  }
}

function readQuotaHeader (res: Response): KvQuota | undefined {
  const raw = res.headers.get('x-aviato-kv-quota')
  if (raw === null) {
    return undefined
  }
  try {
    const parsed = KvQuotaSchema.safeParse(JSON.parse(raw))
    return parsed.success ? parsed.data : undefined
  } catch {
    return undefined
  }
}

async function parseJsonOrThrow<T> (
  res: Response,
  schema: { safeParse: (v: unknown) => { success: boolean,
    data?: T,
    error?: unknown } },
  op: string,
): Promise<T> {
  let json: unknown = null
  try {
    json = await res.json()
  } catch {
    // Body might be empty / non-JSON; let error path surface the http code.
  }
  if (!res.ok) {
    await reportApiError(res, json, op)
  }
  const parsed = schema.safeParse(json)
  if (!parsed.success || parsed.data === undefined) {
    throw new KVError('malformed', `${op}: response shape invalid`, res.status)
  }
  return parsed.data
}

async function throwApiError (res: Response, op: string): Promise<never> {
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    // empty / non-JSON
  }
  await reportApiError(res, body, op)
  // reportApiError throws; satisfy ts:
  throw new KVError('internal', `${op}: ${res.status}`, res.status)
}

async function reportApiError (res: Response, body: unknown, op: string): Promise<never> {
  const parsed = KvErrorResponseSchema.safeParse(body)
  const retryHeader = res.headers.get('retry-after')
  const retryAfterMs = retryHeader !== null && /^\d+$/.test(retryHeader)
    ? Number.parseInt(retryHeader, 10) * 1000
    : undefined
  if (parsed.success) {
    throw new KVError(
      parsed.data.code,
      parsed.data.message ?? `${op}: ${res.status} ${parsed.data.code}`,
      res.status,
      {
        ...(parsed.data.conflicts !== undefined ? { conflicts: parsed.data.conflicts } : {}),
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
      },
    )
  }
  throw new KVError(
    res.status === 401 ? 'unauthorized' : 'internal',
    `${op}: HTTP ${res.status}`,
    res.status,
    retryAfterMs !== undefined ? { retryAfterMs } : undefined,
  )
}

/**
 * Recompute the SHA-256 checksum of an already-sealed wire ciphertext.
 * Useful for callers that persist `(ciphertext, checksum)` pairs locally
 * and want to assert they still agree on the wire bytes after a restore.
 */
export function recomputeKvChecksum (ciphertextB64u: string): string {
  return checksumKvBlob(ciphertextB64u)
}
