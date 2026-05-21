// Master-signed assertions.
//
// Flavours, distinguished by `kind`:
//   - server-link    : initial registration of a user with a server
//   - server-sign-in : subsequent web sign-in (re-delivers K for rotation)
//   - operator-link  : binds the user as the server's operator. Tower
//                      stores the (userId, serverPubKey) association in
//                      plaintext for license-activation lookups.
//   - session-auth   : per-session cert-based sign-in (client → server)
//
// server-link, server-sign-in, and operator-link are signed by M (the
// user master key) and flow through Tower's pairing-response leg.
// session-auth is signed by C_n (the per-device client key) inside an
// envelope that carries the M-signed cert.

import { z } from 'zod'

import { ClientDelegationCertEnvelopeSchema } from './cert.js'
import { BASE64URL, HEX_32, HEX_ANY, UNIX_SEC } from './primitives.js'

// Common fields on every M-signed assertion.
const MasterSignedAssertionBaseSchema = z.object({
  requestId: z.string().min(1),
  serverPubKey: HEX_32,
  ts: z.number().int(),
  userEncPubKey: HEX_32,
  userId: z.string().min(1),
  userPubKey: HEX_32,
  v: z.literal(1),
})

export const ServerLinkAssertionPayloadSchema = MasterSignedAssertionBaseSchema.extend({
  kind: z.literal('server-link'),
})

export type ServerLinkAssertionPayload = z.infer<typeof ServerLinkAssertionPayloadSchema>

export const ServerSignInAssertionPayloadSchema = MasterSignedAssertionBaseSchema.extend({
  kind: z.literal('server-sign-in'),
})

export type ServerSignInAssertionPayload = z.infer<typeof ServerSignInAssertionPayloadSchema>

export const OperatorLinkAssertionPayloadSchema = MasterSignedAssertionBaseSchema.extend({
  kind: z.literal('operator-link'),
})

export type OperatorLinkAssertionPayload = z.infer<typeof OperatorLinkAssertionPayloadSchema>

// The wire envelope as it travels Tower → media server.
export const MasterSignedAssertionEnvelopeSchema = z.object({
  assertionSignature: BASE64URL,
  signedAssertionBytes: BASE64URL,
})

export type MasterSignedAssertionEnvelope = z.infer<typeof MasterSignedAssertionEnvelopeSchema>

// Per-session cert-auth assertion (client → media server).
export const IdentitySessionAssertionSchema = z.object({
  cert: ClientDelegationCertEnvelopeSchema,
  challenge: HEX_ANY,
  serverId: HEX_32,
  sig: BASE64URL,
  ts: UNIX_SEC,
})

export type IdentitySessionAssertion = z.infer<typeof IdentitySessionAssertionSchema>
