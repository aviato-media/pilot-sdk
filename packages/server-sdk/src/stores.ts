// Persistence-agnostic store interfaces. The media-server host injects
// concrete implementations; the SDK never touches a database directly.

export interface PairingRequestRow {
  readonly requestId: string
  readonly code: string
  readonly inviteToken: string | null
  readonly localUserId: string | null
  readonly purpose: 'invite' | 'link-existing-user' | 'operator-link' | 'server-sign-in'
  readonly towerExpiresAt: string
  /** Tower's bearer used to poll this request. */
  readonly towerBearer?: string
  readonly createdAt?: string
}

export interface PairingRequestStore {
  put (row: PairingRequestRow): Promise<void>
  get (requestId: string): Promise<PairingRequestRow | null>
  consume (requestId: string): Promise<PairingRequestRow | null>
}

export interface IdentityClientRow {
  readonly clientId: string
  readonly userId: string
  /** Hex 64 — per-device Ed25519 pub. */
  readonly clientPubKey: string
  /** Hex 64 — per-device X25519 pub. */
  readonly clientEncPubKey: string
  readonly deviceName: string
  /** ISO 8601 cert expiry. */
  readonly certExpiresAt: string
  readonly lastSeenAt: string
  readonly revoked: boolean
}

export interface IdentityClientStore {
  upsert (row: IdentityClientRow): Promise<void>
  get (clientId: string): Promise<IdentityClientRow | null>
  list (userId: string): Promise<IdentityClientRow[]>
  revoke (clientId: string): Promise<void>
  isRevoked (clientId: string): Promise<boolean>
}

export interface SessionChallenge {
  readonly challenge: string
  readonly issuedAtMs: number
  /** Optional payload bound at issue time (cert digest, etc.). */
  readonly meta?: Record<string, string>
}

export interface SessionChallengeStore {
  create (ttlMs?: number): Promise<SessionChallenge>
  /** Return + delete the challenge atomically. Single-use enforcement. */
  consume (challenge: string): Promise<SessionChallenge | null>
}

export interface IdentityUserRow {
  readonly id: string
  /** Hex 64 — user's Ed25519 master pubkey. */
  readonly userPubKey: string
  /** Hex 64 — user's X25519 vault encryption pubkey. */
  readonly userEncPubKey: string
  readonly towerUserId: string
}

export interface IdentityUserStore {
  getByPublicKey (userPubKey: string): Promise<IdentityUserRow | null>
  upsertUserEncPubKey (userId: string, userEncPubKey: string): Promise<void>
}

// ── In-memory implementations for tests ────────────────────────────────

export class MemoryPairingRequestStore implements PairingRequestStore {
  private rows = new Map<string, PairingRequestRow>()
  async put (row: PairingRequestRow): Promise<void> {
    this.rows.set(row.requestId, row)
  }
  async get (requestId: string): Promise<PairingRequestRow | null> {
    return this.rows.get(requestId) ?? null
  }
  async consume (requestId: string): Promise<PairingRequestRow | null> {
    const row = this.rows.get(requestId) ?? null
    if (row !== null) {
      this.rows.delete(requestId)
    }
    return row
  }
}

export class MemoryIdentityClientStore implements IdentityClientStore {
  private rows = new Map<string, IdentityClientRow>()
  async upsert (row: IdentityClientRow): Promise<void> {
    this.rows.set(row.clientId, row)
  }
  async get (clientId: string): Promise<IdentityClientRow | null> {
    return this.rows.get(clientId) ?? null
  }
  async list (userId: string): Promise<IdentityClientRow[]> {
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
  async isRevoked (clientId: string): Promise<boolean> {
    return this.rows.get(clientId)?.revoked === true
  }
}

export class MemorySessionChallengeStore implements SessionChallengeStore {
  private rows = new Map<string, SessionChallenge>()
  async create (ttlMs = 300_000): Promise<SessionChallenge> {
    const bytes = crypto.getRandomValues(new Uint8Array(16))
    let challenge = ''
    for (let i = 0; i < bytes.length; i++) {
      challenge += bytes[i]!.toString(16).padStart(2, '0')
    }
    const entry: SessionChallenge = {
      challenge,
      issuedAtMs: Date.now(),
    }
    this.rows.set(challenge, entry)
    // Best-effort TTL cleanup.
    const t: unknown = setTimeout(() => {
      this.rows.delete(challenge)
    }, ttlMs)
    const { unref } = t as { unref?: () => void }
    if (typeof unref === 'function') {
      unref.call(t)
    }
    return entry
  }
  async consume (challenge: string): Promise<SessionChallenge | null> {
    const row = this.rows.get(challenge) ?? null
    if (row !== null) {
      this.rows.delete(challenge)
    }
    return row
  }
}

export class MemoryIdentityUserStore implements IdentityUserStore {
  private rowsByPub = new Map<string, IdentityUserRow>()
  async getByPublicKey (userPubKey: string): Promise<IdentityUserRow | null> {
    return this.rowsByPub.get(userPubKey) ?? null
  }
  async upsertUserEncPubKey (userId: string, userEncPubKey: string): Promise<void> {
    for (const [k, v] of this.rowsByPub.entries()) {
      if (v.id === userId) {
        this.rowsByPub.set(k, {
          ...v,
          userEncPubKey,
        })
      }
    }
  }
  /** Test helper — not part of the interface. */
  seed (row: IdentityUserRow): void {
    this.rowsByPub.set(row.userPubKey, row)
  }
}
