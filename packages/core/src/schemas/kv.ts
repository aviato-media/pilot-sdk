// Tower-mediated encrypted key/value sync.
//
// Tower stores opaque ciphertext + sha256(ciphertext) per (userId, key).
// Clients encrypt/decrypt locally under a per-user KV-K so Tower never
// sees plaintext. Clients reconcile via SHA-256 of the ciphertext bytes;
// optimistic concurrency uses the same hash as a CAS token.

import { z } from 'zod'

import { BASE64URL, ISO_DATETIME, UUID } from './primitives.js'

/**
 * Hard limits enforced at the wire schema layer. Mirror these on the
 * server side; Tower can return `quota_exceeded` for soft caps on the
 * total bytes / key count per user.
 */
export const KV_MAX_KEY_LENGTH = 256
export const KV_MAX_BLOB_BYTES = 64 * 1024

/** Lowercase ASCII with `:` and `_` separators is recommended for client-owned namespacing. */
export const KvKeyStringSchema = z.string().min(1).max(KV_MAX_KEY_LENGTH)

// ── Per-key get request / response ────────────────────────────────────

export const KvBatchGetItemSchema = z.object({
  key: KvKeyStringSchema,
  knownChecksum: BASE64URL.optional(),
})

export type KvBatchGetItem = z.infer<typeof KvBatchGetItemSchema>

export const KvBatchGetResultUnchangedSchema = z.object({
  key: KvKeyStringSchema,
  status: z.literal('unchanged'),
})

export const KvBatchGetResultAbsentSchema = z.object({
  key: KvKeyStringSchema,
  status: z.literal('absent'),
})

export const KvBatchGetResultUpdatedSchema = z.object({
  checksum: BASE64URL,
  ciphertext: BASE64URL,
  key: KvKeyStringSchema,
  status: z.literal('updated'),
  updatedAt: ISO_DATETIME,
  updatedByClientId: UUID.nullable(),
})

export const KvBatchGetResultSchema = z.discriminatedUnion('status', [
  KvBatchGetResultUnchangedSchema,
  KvBatchGetResultAbsentSchema,
  KvBatchGetResultUpdatedSchema,
])

export type KvBatchGetResult = z.infer<typeof KvBatchGetResultSchema>

export const KvBatchGetRequestSchema = z.object({
  items: z.array(KvBatchGetItemSchema),
})

export type KvBatchGetRequest = z.infer<typeof KvBatchGetRequestSchema>

export const KvBatchGetResponseSchema = z.object({
  items: z.array(KvBatchGetResultSchema),
})

export type KvBatchGetResponse = z.infer<typeof KvBatchGetResponseSchema>

// ── Per-key put request / response ────────────────────────────────────

export const KvBatchPutItemSchema = z.object({
  ciphertext: BASE64URL,
  expectedChecksum: BASE64URL.optional(),
  key: KvKeyStringSchema,
})

export type KvBatchPutItem = z.infer<typeof KvBatchPutItemSchema>

export const KvBatchPutRequestSchema = z.object({
  items: z.array(KvBatchPutItemSchema),
})

export type KvBatchPutRequest = z.infer<typeof KvBatchPutRequestSchema>

export const KvBatchPutAcceptedSchema = z.object({
  checksum: BASE64URL,
  key: KvKeyStringSchema,
  updatedAt: ISO_DATETIME,
})

export type KvBatchPutAccepted = z.infer<typeof KvBatchPutAcceptedSchema>

export const KvBatchPutResponseSchema = z.object({
  accepted: z.array(KvBatchPutAcceptedSchema),
})

export type KvBatchPutResponse = z.infer<typeof KvBatchPutResponseSchema>

// ── List / delete ─────────────────────────────────────────────────────

export const KvListEntrySchema = z.object({
  checksum: BASE64URL,
  key: KvKeyStringSchema,
  sizeBytes: z.number().int().nonnegative(),
  updatedAt: ISO_DATETIME,
  updatedByClientId: UUID.nullable(),
})

export type KvListEntry = z.infer<typeof KvListEntrySchema>

export const KvListResponseSchema = z.object({
  items: z.array(KvListEntrySchema),
})

export type KvListResponse = z.infer<typeof KvListResponseSchema>

export const KvDeleteRequestSchema = z.object({
  keys: z.array(KvKeyStringSchema),
})

export type KvDeleteRequest = z.infer<typeof KvDeleteRequestSchema>

// ── Quota headers (informational; clients warn before hitting them) ───

export const KvQuotaSchema = z.object({
  byteLimit: z.number().int().nonnegative(),
  bytesUsed: z.number().int().nonnegative(),
  keyCount: z.number().int().nonnegative(),
  keyLimit: z.number().int().nonnegative(),
})

export type KvQuota = z.infer<typeof KvQuotaSchema>

// ── Structured server error shape ─────────────────────────────────────

export const KV_ERROR_CODES = [
  'checksum_mismatch',
  'quota_exceeded',
  'key_too_long',
  'blob_too_large',
  'malformed',
  'unauthorized',
  'internal',
] as const

export const KvErrorCodeSchema = z.enum(KV_ERROR_CODES)

export type KvErrorCode = z.infer<typeof KvErrorCodeSchema>

export const KvErrorResponseSchema = z.object({
  code: KvErrorCodeSchema,
  conflicts: z.array(z.object({
    // Omitted when no row exists for the key — the caller asserted a
    // checksum but the key is absent. Present = the stored checksum.
    actualChecksum: BASE64URL.optional(),
    expectedChecksum: BASE64URL.optional(),
    key: KvKeyStringSchema,
  })).optional(),
  message: z.string().optional(),
})

export type KvErrorResponse = z.infer<typeof KvErrorResponseSchema>
