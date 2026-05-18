// Revocation envelopes — signed by M; can revoke a clientId, a server-link,
// or the whole identity. Distributed by the user pushing to each server.

import { z } from 'zod'

import { BASE64URL, HEX_32, UNIX_SEC, UUID } from './primitives.js'

export const RevocationScopeSchema = z.enum(['client', 'server-link', 'identity'])
export type RevocationScope = z.infer<typeof RevocationScopeSchema>

export const RevocationEnvelopePayloadSchema = z.object({
  clientId: UUID.optional(),
  iat: UNIX_SEC,
  reason: z.string().optional(),
  scope: RevocationScopeSchema,
  serverPubKey: HEX_32.optional(),
  userPubKey: HEX_32,
  v: z.literal(1),
})

export type RevocationEnvelopePayload = z.infer<typeof RevocationEnvelopePayloadSchema>

export const RevocationEnvelopeWireSchema = z.object({
  payload: BASE64URL,
  sig: BASE64URL,
})

export type RevocationEnvelopeWire = z.infer<typeof RevocationEnvelopeWireSchema>
