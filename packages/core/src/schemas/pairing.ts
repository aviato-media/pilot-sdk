// Pairing-flow request/response shapes (Tower API).

import { z } from 'zod'

import { BASE64URL, HEX_32, ISO_DATETIME } from './primitives.js'
import { SealedBoxSchema } from './sealedbox.js'

export const PairingKindSchema = z.enum(['server-link', 'server-sign-in', 'client-pair'])
export type PairingKind = z.infer<typeof PairingKindSchema>

/**
 * Wire body for `POST /api/identity/pairing/register` — what
 * pilot-server-sdk's `TowerClient.pairingRegister` sends. Tower-api
 * MUST validate against this schema (via `@hono/zod-openapi`) — do not
 * redefine it locally. A local schema dropping `displayName` is exactly
 * the silent drift the monorepo exists to prevent: the field gets
 * stripped at the route boundary and Tower-web renders "Unnamed server".
 */
export const PairingRegisterRequestSchema = z.object({
  displayName: z.string().min(1).optional(),
  kind: PairingKindSchema,
  scope: z.array(z.string()).optional(),
  serverIcon: z.string().optional(),
  serverId: z.string().min(1),
})

export type PairingRegisterRequest = z.infer<typeof PairingRegisterRequestSchema>

/**
 * Wire body for `GET /api/identity/code/:code/resolve` — Tower's
 * unified pairing-context endpoint that Tower-web's `/pair` page calls
 * after the user enters the code. Returns the kind-specific context so
 * the consent UI can render appropriately.
 *
 * `kind` is the discriminator:
 *   - server-link, server-sign-in: `serverId`, `serverPubKey`, and
 *     (when the host configured them) `displayName`/`serverIcon` are
 *     populated. `scope` carries the requested permissions.
 *   - client-pair: `appId` is populated; the other `app*` fields come
 *     from Tower's app-registry. `scope` lists requested permissions.
 *
 * Tower-api MUST use this schema for the route response — Tower-web
 * MUST use it to validate the fetch result. One canonical shape;
 * "Unnamed server" becomes structurally impossible when the host
 * provided a displayName.
 */
export const PairingCodeResolveResponseSchema = z.object({
  appIcon: z.string().optional(),
  appId: z.string().optional(),
  appName: z.string().optional(),
  appVerified: z.boolean().optional(),
  displayName: z.string().optional(),
  expiresAt: ISO_DATETIME,
  kind: PairingKindSchema,
  requestId: z.string().min(1),
  scope: z.array(z.string()).optional(),
  serverIcon: z.string().optional(),
  serverId: z.string().optional(),
  serverPubKey: HEX_32.optional(),
})

export type PairingCodeResolveResponse = z.infer<typeof PairingCodeResolveResponseSchema>

export const PairingStateSchema = z.enum([
  'pending',
  'claimed_by_user',
  'completed',
  'denied',
  'expired',
])
export type PairingState = z.infer<typeof PairingStateSchema>

export const PairingRegisterResponseSchema = z.object({
  code: z.string().regex(/^\d{8}$/),
  expiresAt: ISO_DATETIME,
  requestId: z.string().min(1),
})

export type PairingRegisterResponse = z.infer<typeof PairingRegisterResponseSchema>

export const ServerLinkPollResponseSchema = z.object({
  assertionSignature: BASE64URL.optional(),
  expiresAt: ISO_DATETIME,
  requestId: z.string().min(1),
  signedAssertionBytes: BASE64URL.optional(),
  state: PairingStateSchema,
})

export type ServerLinkPollResponse = z.infer<typeof ServerLinkPollResponseSchema>

// Client-pair flow (third-party apps paired via app code).

export const ClientPairBeginResponseSchema = z.object({
  code: z.string().regex(/^\d{8}$/),
  expiresAt: ISO_DATETIME,
  requestId: z.string().min(1),
})

export type ClientPairBeginResponse = z.infer<typeof ClientPairBeginResponseSchema>

export const ClientPairPollResponseSchema = z.object({
  certSignature: BASE64URL.optional(),
  expiresAt: ISO_DATETIME,
  requestId: z.string().min(1),
  sealedConnInfoBundle: SealedBoxSchema.nullable().optional(),
  signedCertBytes: BASE64URL.optional(),
  state: PairingStateSchema,
})

export type ClientPairPollResponse = z.infer<typeof ClientPairPollResponseSchema>

export const RenewClientResponseSchema = z.object({
  certSignature: BASE64URL,
  clientId: z.string().min(1),
  expiresAt: ISO_DATETIME,
  signedCertBytes: BASE64URL,
})

export type RenewClientResponse = z.infer<typeof RenewClientResponseSchema>
