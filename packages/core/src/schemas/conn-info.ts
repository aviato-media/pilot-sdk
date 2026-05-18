// Server connection info — published to Tower encrypted under K, fetched
// by paired clients with K to learn each server's host/port/protocol.

import { z } from 'zod'

import { BASE64URL, HEX_32, UNIX_SEC } from './primitives.js'
import { SealedBoxSchema } from './sealedbox.js'

export const ServerConnInfoPayloadSchema = z.object({
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  issuedAtSec: UNIX_SEC,
  paths: z.record(z.string(), z.string()).optional(),
  port: z.number().int().positive(),
  protocol: z.enum(['http', 'https']),
  publicHost: z.string().min(1),
  rotationCounter: z.number().int(),
  v: z.literal(1),
})

export type ServerConnInfoPayload = z.infer<typeof ServerConnInfoPayloadSchema>

export const ServerConnInfoPublishSchema = z.object({
  ct: BASE64URL,
  nonce: BASE64URL,
  serverPubKey: HEX_32,
  sig: BASE64URL,
  version: z.number().int(),
})

export type ServerConnInfoPublish = z.infer<typeof ServerConnInfoPublishSchema>

export const ServerConnInfoRecordSchema = z.object({
  ct: BASE64URL,
  lastUpdatedAtSec: UNIX_SEC,
  nonce: BASE64URL,
  serverPubKey: HEX_32,
  sig: BASE64URL,
  version: z.number().int(),
})

export type ServerConnInfoRecord = z.infer<typeof ServerConnInfoRecordSchema>

// Sealed (to userEncPubKey) reply the media server returns to Tower
// containing the per-server K for the user who just signed the assertion.
export const PairingResponseSealedSchema = z.object({
  connInfoKey: BASE64URL,
  issuedAtSec: UNIX_SEC,
  serverPubKey: HEX_32,
  v: z.literal(1),
})

export type PairingResponseSealed = z.infer<typeof PairingResponseSealedSchema>

export const PairingResponsePayloadSchema = z.object({
  sealed: SealedBoxSchema,
  sig: BASE64URL,
})

export type PairingResponsePayload = z.infer<typeof PairingResponsePayloadSchema>

export const PairingResponseRecordSchema = z.object({
  payload: PairingResponsePayloadSchema,
  postedAtSec: UNIX_SEC,
})

export type PairingResponseRecord = z.infer<typeof PairingResponseRecordSchema>

// Sealed (to clientEncPubKey) K bundle delivered to a client app via the
// client-pair flow. One entry per server the user has linked.
export const ClientKeyBundleServerSchema = z.object({
  connInfoKey: BASE64URL,
  serverPubKey: HEX_32,
})

export type ClientKeyBundleServer = z.infer<typeof ClientKeyBundleServerSchema>

export const ClientKeyBundleContentsSchema = z.object({
  issuedAtSec: UNIX_SEC,
  servers: z.array(ClientKeyBundleServerSchema),
  v: z.literal(1),
})

export type ClientKeyBundleContents = z.infer<typeof ClientKeyBundleContentsSchema>

// In-session K refresh envelope. Returned by the media server's session-auth
// completion response so clients with stale K can recover without re-pairing.
export const SessionConnInfoEnvelopeSchema = z.object({
  connInfoKey: BASE64URL,
  issuedAtSec: UNIX_SEC,
  v: z.literal(1),
})

export type SessionConnInfoEnvelope = z.infer<typeof SessionConnInfoEnvelopeSchema>
