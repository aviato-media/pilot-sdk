// Persistence-agnostic Tower KV registry. One row per (towerUserId, key)
// holding an opaque encrypted blob the SDK never tries to decrypt.
//
// The tower-api implementation that will land in a follow-up workstream
// composes the HTTP layer on top of this interface: route validation via
// `KvBatchGet/Put/Delete/ListResponseSchema` from @aviato-media/pilot-core,
// auth via the existing delegation-cert path, persistence via this store.

import type {
  KvBatchGetItem,
  KvBatchGetResult,
  KvBatchPutAccepted,
  KvBatchPutItem,
  KvErrorCode,
  KvListEntry,
  KvQuota,
} from '@aviato-media/pilot-core'
import { base64urlDecode, base64urlEncode, sha256Bytes } from '@aviato-media/pilot-core'

export interface KvRow {
  readonly key: string
  /** Wire bytes Tower stored verbatim — caller never decrypts these. */
  readonly ciphertext: Uint8Array
  /** base64url(sha256(ciphertext)). */
  readonly checksum: string
  readonly sizeBytes: number
  readonly updatedAt: string
  readonly updatedByClientId: string | null
}

export interface KvStorePutInput {
  readonly key: string
  readonly ciphertext: Uint8Array
  readonly checksum: string
  readonly sizeBytes: number
  readonly updatedAt: string
  readonly updatedByClientId: string | null
}

export interface KvStore {
  /** All keys + checksums for a user, in stable order. */
  list (userId: string): Promise<KvRow[]>
  /** Selected rows for a user. Keys absent from storage are simply omitted from the result. */
  getMany (userId: string, keys: ReadonlyArray<string>): Promise<KvRow[]>
  /**
   * Apply a batch atomically — all-or-nothing. Implementations are
   * expected to perform the optimistic-concurrency check inside the
   * transaction: any row where `expectedChecksum` is supplied AND
   * mismatches the stored checksum must cause the whole batch to be
   * rejected with `checksum_mismatch` (no partial writes).
   */
  applyBatch (
    userId: string,
    items: ReadonlyArray<KvStorePutInput & { expectedChecksum?: string }>,
  ): Promise<KvBatchResult>
  deleteMany (userId: string, keys: ReadonlyArray<string>): Promise<void>
  /** Current usage + caps. Routes echo this in `x-aviato-kv-quota` headers. */
  quota (userId: string): Promise<KvQuota>
}

export type KvBatchResult
  = | { ok: true,
    accepted: KvBatchPutAccepted[] }
  | { ok: false,
    code: Extract<KvErrorCode, 'checksum_mismatch' | 'quota_exceeded'>,
    conflicts?: Array<{ key: string,
      expectedChecksum?: string,
      actualChecksum?: string }> }

// ── Helpers shared between in-memory + production stores ──────────────

/** base64url(sha256(ciphertext bytes)). Mirrors the client-side helper. */
export function sha256OfCiphertext (ciphertext: Uint8Array): string {
  return base64urlEncode(sha256Bytes(ciphertext))
}

/**
 * Map a `KvBatchGetItem[]` plus the rows the store returned into the
 * three-status response the wire schema expects. Pull this into the
 * future tower-api handler so the unchanged/updated/absent partitioning
 * is implemented once.
 */
export function partitionBatchGet (
  items: ReadonlyArray<KvBatchGetItem>,
  rows: ReadonlyArray<KvRow>,
): KvBatchGetResult[] {
  const byKey = new Map(rows.map((r) => [r.key, r]))
  return items.map((item) => {
    const row = byKey.get(item.key)
    if (row === undefined) {
      return {
        key: item.key,
        status: 'absent' as const,
      }
    }
    if (item.knownChecksum !== undefined && item.knownChecksum === row.checksum) {
      return {
        key: item.key,
        status: 'unchanged' as const,
      }
    }
    return {
      checksum: row.checksum,
      ciphertext: base64urlEncode(row.ciphertext),
      key: row.key,
      status: 'updated' as const,
      updatedAt: row.updatedAt,
      updatedByClientId: row.updatedByClientId,
    }
  })
}

/** Decode `KvBatchPutItem` ciphertext + compute the matching checksum + size. */
export function decodePutItem (
  item: KvBatchPutItem,
  updatedByClientId: string | null,
  updatedAt: string,
): KvStorePutInput & { expectedChecksum?: string } {
  const ct = base64urlDecode(item.ciphertext)
  return {
    checksum: sha256OfCiphertext(ct),
    ciphertext: ct,
    ...(item.expectedChecksum !== undefined ? { expectedChecksum: item.expectedChecksum } : {}),
    key: item.key,
    sizeBytes: ct.length,
    updatedAt,
    updatedByClientId,
  }
}

export function toListEntry (row: KvRow): KvListEntry {
  return {
    checksum: row.checksum,
    key: row.key,
    sizeBytes: row.sizeBytes,
    updatedAt: row.updatedAt,
    updatedByClientId: row.updatedByClientId,
  }
}

// ── In-memory implementation (tests + the future tower-api unit tests) ─

export interface MemoryKvStoreOptions {
  readonly keyLimit?: number
  readonly byteLimit?: number
}

const DEFAULT_KEY_LIMIT = 10_000
const DEFAULT_BYTE_LIMIT = 10 * 1024 * 1024

export class MemoryKvStore implements KvStore {
  private readonly rowsByUser = new Map<string, Map<string, KvRow>>()
  private readonly keyLimit: number
  private readonly byteLimit: number

  constructor (opts: MemoryKvStoreOptions = {}) {
    this.keyLimit = opts.keyLimit ?? DEFAULT_KEY_LIMIT
    this.byteLimit = opts.byteLimit ?? DEFAULT_BYTE_LIMIT
  }

  private bucket (userId: string): Map<string, KvRow> {
    let m = this.rowsByUser.get(userId)
    if (m === undefined) {
      m = new Map<string, KvRow>()
      this.rowsByUser.set(userId, m)
    }
    return m
  }

  async list (userId: string): Promise<KvRow[]> {
    return [...this.bucket(userId).values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
  }

  async getMany (userId: string, keys: ReadonlyArray<string>): Promise<KvRow[]> {
    const m = this.bucket(userId)
    const out: KvRow[] = []
    for (const k of keys) {
      const row = m.get(k)
      if (row !== undefined) {
        out.push(row)
      }
    }
    return out
  }

  async applyBatch (
    userId: string,
    items: ReadonlyArray<KvStorePutInput & { expectedChecksum?: string }>,
  ): Promise<KvBatchResult> {
    const m = this.bucket(userId)
    const conflicts: Array<{ key: string,
      expectedChecksum?: string,
      actualChecksum?: string }> = []
    for (const item of items) {
      if (item.expectedChecksum !== undefined) {
        const actual = m.get(item.key)?.checksum
        if (actual !== item.expectedChecksum) {
          conflicts.push({
            ...(actual !== undefined ? { actualChecksum: actual } : {}),
            expectedChecksum: item.expectedChecksum,
            key: item.key,
          })
        }
      }
    }
    if (conflicts.length > 0) {
      return {
        code: 'checksum_mismatch',
        conflicts,
        ok: false,
      }
    }

    // Quota check on the post-application size set.
    const projected = new Map(m)
    for (const item of items) {
      projected.set(item.key, {
        checksum: item.checksum,
        ciphertext: item.ciphertext,
        key: item.key,
        sizeBytes: item.sizeBytes,
        updatedAt: item.updatedAt,
        updatedByClientId: item.updatedByClientId,
      })
    }
    let projectedBytes = 0
    for (const r of projected.values()) {
      projectedBytes += r.sizeBytes
    }
    if (projected.size > this.keyLimit || projectedBytes > this.byteLimit) {
      return {
        code: 'quota_exceeded',
        ok: false,
      }
    }

    // Commit atomically.
    for (const item of items) {
      m.set(item.key, {
        checksum: item.checksum,
        ciphertext: item.ciphertext,
        key: item.key,
        sizeBytes: item.sizeBytes,
        updatedAt: item.updatedAt,
        updatedByClientId: item.updatedByClientId,
      })
    }
    return {
      accepted: items.map((i) => ({
        checksum: i.checksum,
        key: i.key,
        updatedAt: i.updatedAt,
      })),
      ok: true,
    }
  }

  async deleteMany (userId: string, keys: ReadonlyArray<string>): Promise<void> {
    const m = this.bucket(userId)
    for (const k of keys) {
      m.delete(k)
    }
  }

  async quota (userId: string): Promise<KvQuota> {
    const m = this.bucket(userId)
    let bytesUsed = 0
    for (const r of m.values()) {
      bytesUsed += r.sizeBytes
    }
    return {
      byteLimit: this.byteLimit,
      bytesUsed,
      keyCount: m.size,
      keyLimit: this.keyLimit,
    }
  }
}
