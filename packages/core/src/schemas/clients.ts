// Paired-client schemas.
//
// Tower keeps a registry of every client app a user has paired (one row
// per user × app × device). The user sees this list as the "Devices" /
// "Connected Apps" pane in their Tower dashboard and can revoke entries.
//
// These schemas are the cross-system contract for that registry — Tower-
// api returns `PairedClientView` shapes; Tower-web consumes them; the
// persistence layer stores `PairedClientRow` shapes. Both `PairedClient
// Store` (in pilot-tower-sdk) and the Tower-api HTTP responses use them.

import { z } from 'zod'

import { HEX_32, ISO_DATETIME, UUID } from './primitives.js'

/**
 * The persisted shape — what Tower stores in its `paired_clients` table
 * (or equivalent). One row per (userId, clientId). Holds the cert keypair
 * pubs, scope/server allowlist the user approved at /pair time, and the
 * lifecycle timestamps.
 */
export const PairedClientRowSchema = z.object({
  appId: z.string().min(1),
  certExpiresAt: ISO_DATETIME,
  clientEncPubKey: HEX_32,
  clientId: UUID,
  clientPubKey: HEX_32,
  deviceName: z.string().min(1),
  /** ISO 8601 of the most recent cert-auth this client did against any of the user's servers. */
  lastSeenAt: ISO_DATETIME.nullable(),
  pairedAt: ISO_DATETIME,
  revoked: z.boolean(),
  /** Scopes the user approved at /pair time (e.g. ["identity"]). */
  scope: z.array(z.string()),
  /** Hex serverPubKeys the user ticked on the consent screen for this app. */
  servers: z.array(HEX_32),
  userId: z.string().min(1),
})

export type PairedClientRow = z.infer<typeof PairedClientRowSchema>

/**
 * The public-facing view — what Tower-api returns from
 * `GET /api/identity/clients` and what Tower-web renders in the Devices
 * pane. Joins `PairedClientRow` with app-registry metadata (name, icon,
 * verified status) and omits private fields a UI doesn't need (the
 * encryption pubs, the full server allowlist).
 */
export const PairedClientViewSchema = z.object({
  appIcon: z.string().url().optional(),
  appId: z.string().min(1),
  appName: z.string().optional(),
  appVerified: z.boolean().optional(),
  certExpiresAt: ISO_DATETIME,
  clientId: UUID,
  deviceName: z.string().min(1),
  lastSeenAt: ISO_DATETIME.nullable(),
  pairedAt: ISO_DATETIME,
  revoked: z.boolean(),
  /** How many of the user's servers this app has access to. */
  serverCount: z.number().int().min(0),
})

export type PairedClientView = z.infer<typeof PairedClientViewSchema>

/** Wire body for `GET /api/identity/clients`. */
export const PairedClientListResponseSchema = z.object({
  clients: z.array(PairedClientViewSchema),
})

export type PairedClientListResponse = z.infer<typeof PairedClientListResponseSchema>

/**
 * Wire body for `GET /api/identity/clients/details` — the session-auth'd
 * **per-user** endpoint that returns the full persisted shape (including
 * the per-device cert keypair pubs). Use this from Tower-web's cert pre-
 * issuance flow: pre-issue runs client-side (the user's master private
 * key only exists in the open vault), and the renewal call needs
 * `clientPubKey` + `clientEncPubKey` to feed into `buildClientPairCert`.
 *
 * Distinction from `PairedClientListResponse`:
 *   - `/clients`         → `PairedClientView[]` (UI list; no cert pubs).
 *   - `/clients/details` → `PairedClientRow[]`  (renewal/audit; full row).
 *
 * Both endpoints are session-scoped — they return only the requesting
 * user's clients. The cert pubs are not secrets relative to the user
 * (they're already in every cert the user has signed) so exposing them
 * to the session-authenticated owner is safe.
 */
export const PairedClientDetailListResponseSchema = z.object({
  clients: z.array(PairedClientRowSchema),
})

export type PairedClientDetailListResponse = z.infer<typeof PairedClientDetailListResponseSchema>
