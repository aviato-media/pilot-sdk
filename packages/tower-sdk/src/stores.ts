// Persistence-agnostic paired-clients registry. One row per (user,
// paired client app). The SDK never touches a database directly.

import type { PairedClientRow, PairedClientView } from '@aviato-media/pilot-core'

export interface PairedClientStore {
  /** Insert or replace a row. Called when a client-pair flow completes. */
  upsert (row: PairedClientRow): Promise<void>
  get (clientId: string): Promise<PairedClientRow | null>
  /** All non-revoked + revoked clients for a user. Sort/filter is the caller's job. */
  listByUser (userId: string): Promise<PairedClientRow[]>
  /** Mark a client revoked. Future cert-auths against any of the user's servers should be rejected. */
  revoke (clientId: string): Promise<void>
  /** Update lastSeenAt. Called when a session-auth assertion is verified for this client. */
  markSeen (clientId: string, atIso: string): Promise<void>
}

/**
 * Convert a PairedClientRow to its public-facing view, optionally
 * enriching with app-registry metadata. Use this in Tower-api's
 * `GET /api/identity/clients` handler to format response payloads.
 *
 * The persistence layer's row carries internal fields (clientPubKey,
 * clientEncPubKey, scope, server allowlist) that a UI doesn't need to
 * see; this strips them and exposes `serverCount` as the user-facing
 * summary.
 */
export function toPairedClientView (
  row: PairedClientRow,
  appMeta?: {
    readonly name?: string
    readonly icon?: string
    readonly verified?: boolean
  },
): PairedClientView {
  return {
    appId: row.appId,
    certExpiresAt: row.certExpiresAt,
    clientId: row.clientId,
    deviceName: row.deviceName,
    lastSeenAt: row.lastSeenAt,
    pairedAt: row.pairedAt,
    revoked: row.revoked,
    serverCount: row.servers.length,
    ...(appMeta?.name !== undefined ? { appName: appMeta.name } : {}),
    ...(appMeta?.icon !== undefined ? { appIcon: appMeta.icon } : {}),
    ...(appMeta?.verified !== undefined ? { appVerified: appMeta.verified } : {}),
  }
}

// ── In-memory implementation for tests ────────────────────────────────

export class MemoryPairedClientStore implements PairedClientStore {
  private rows = new Map<string, PairedClientRow>()

  async upsert (row: PairedClientRow): Promise<void> {
    this.rows.set(row.clientId, row)
  }

  async get (clientId: string): Promise<PairedClientRow | null> {
    return this.rows.get(clientId) ?? null
  }

  async listByUser (userId: string): Promise<PairedClientRow[]> {
    return [...this.rows.values()].filter((r) => r.userId === userId)
  }

  async revoke (clientId: string): Promise<void> {
    const row = this.rows.get(clientId)
    if (row !== undefined) {
      this.rows.set(clientId, {
        ...row,
        revoked: true,
      })
    }
  }

  async markSeen (clientId: string, atIso: string): Promise<void> {
    const row = this.rows.get(clientId)
    if (row !== undefined) {
      this.rows.set(clientId, {
        ...row,
        lastSeenAt: atIso,
      })
    }
  }
}
