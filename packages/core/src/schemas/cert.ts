// Client delegation cert — short-TTL Ed25519 cert signed by the user's
// master key (M), authorizing a single per-device client keypair (C_n) to
// authenticate on the user's behalf. Carries the X25519 encryption pubkeys
// for both client and user so servers can seal K back to the right places.

import { z } from 'zod'

import { BASE64URL, HEX_32, UNIX_SEC, UUID } from './primitives.js'

export const ClientDelegationCertPayloadSchema = z.object({
  appId: z.string().min(1),
  clientEncPubKey: HEX_32,
  clientId: UUID,
  clientPubKey: HEX_32,
  deviceName: z.string().min(1),
  exp: UNIX_SEC,
  iat: UNIX_SEC,
  scope: z.array(z.string()),
  userEncPubKey: HEX_32,
  userId: z.string().min(1),
  userPubKey: HEX_32,
  v: z.literal(1),
})

export type ClientDelegationCertPayload = z.infer<typeof ClientDelegationCertPayloadSchema>

export const ClientDelegationCertEnvelopeSchema = z.object({
  payload: BASE64URL,
  sig: BASE64URL,
})

export type ClientDelegationCertEnvelope = z.infer<typeof ClientDelegationCertEnvelopeSchema>
