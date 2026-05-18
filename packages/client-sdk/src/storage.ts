// Pluggable storage backend. Default is localStorage; native apps inject
// keychain-backed implementations.

import type { ClientKeyBundleServer } from '@aviato-media/pilot-core'

import type { KeyOps } from './key-ops.js'

export interface StoredIdentity {
  /** UUID from the cert payload. */
  readonly clientId: string
  /** base64url Ed25519 device signing key. Omitted when backend uses the handle path. */
  readonly clientPrivBase64url?: string
  /** base64url X25519 device encryption key. Omitted when backend uses the handle path. */
  readonly clientEncPrivBase64url?: string
  /** base64url JCS-canonicalized cert payload bytes. */
  readonly signedCertBytes: string
  /** base64url Ed25519 signature over the cert bytes by the user master key. */
  readonly certSignature: string
  /** Hex 32 — user's Ed25519 master pubkey (lifted from the cert payload after verify). */
  readonly userPubKey: string
  /** Cert expiry unix seconds. */
  readonly exp: number
  /** Cert issued-at unix seconds. */
  readonly iat: number
}

export interface StoredServerKeys {
  /** Per-server K, one entry per linked server. */
  readonly servers: ClientKeyBundleServer[]
  /** Unix seconds the bundle was issued by Tower-web. */
  readonly issuedAtSec: number
}

export interface StoredServerToken {
  readonly token: string
  /** ISO 8601 timestamp. */
  readonly expiresAt: string
}

export interface IdentityStorage {
  getIdentity (): Promise<StoredIdentity | null>
  setIdentity (identity: StoredIdentity | null): Promise<void>

  getBundle (): Promise<StoredServerKeys | null>
  setBundle (bundle: StoredServerKeys | null): Promise<void>

  /** Update one server's K in place. Idempotent. */
  upsertServerKey (entry: ClientKeyBundleServer): Promise<void>

  getServerToken (serverPubKey: string): Promise<StoredServerToken | null>
  setServerToken (serverPubKey: string, token: StoredServerToken | null): Promise<void>

  /**
   * Optional handle-based key path. Backends that implement all three
   * generate device keys inside their secure store and expose them only
   * via `KeyOps` callbacks — the SDK never sees raw private bytes.
   */
  generateClientKeys?(): Promise<KeyOps>
  loadClientKeys?(): Promise<KeyOps | null>
  clearClientKeys?(): Promise<void>
}

const LS_IDENTITY = 'aviato:pilot:identity:v1'
const LS_BUNDLE = 'aviato:pilot:bundle:v1'
const LS_TOKEN_PREFIX = 'aviato:pilot:token:v1:'

/** Default browser-backed storage. Browser-tab-scoped. */
export class LocalStorageBackend implements IdentityStorage {
  async getIdentity (): Promise<StoredIdentity | null> {
    return readJson<StoredIdentity>(LS_IDENTITY)
  }

  async setIdentity (identity: StoredIdentity | null): Promise<void> {
    writeJson(LS_IDENTITY, identity)
  }

  async getBundle (): Promise<StoredServerKeys | null> {
    return readJson<StoredServerKeys>(LS_BUNDLE)
  }

  async setBundle (bundle: StoredServerKeys | null): Promise<void> {
    writeJson(LS_BUNDLE, bundle)
  }

  async upsertServerKey (entry: ClientKeyBundleServer): Promise<void> {
    const existing = await this.getBundle()
    const servers = existing?.servers.filter((s) => s.serverPubKey !== entry.serverPubKey) ?? []
    servers.push(entry)
    await this.setBundle({
      issuedAtSec: existing?.issuedAtSec ?? Math.floor(Date.now() / 1000),
      servers,
    })
  }

  async getServerToken (serverPubKey: string): Promise<StoredServerToken | null> {
    return readJson<StoredServerToken>(LS_TOKEN_PREFIX + serverPubKey)
  }

  async setServerToken (serverPubKey: string, token: StoredServerToken | null): Promise<void> {
    writeJson(LS_TOKEN_PREFIX + serverPubKey, token)
  }
}

function readJson<T> (key: string): T | null {
  try {
    const raw = localStorage.getItem(key)
    if (raw === null) {
      return null
    }
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

function writeJson (key: string, value: unknown): void {
  if (value === null) {
    localStorage.removeItem(key)
    return
  }
  localStorage.setItem(key, JSON.stringify(value))
}

/** In-memory backend for tests and ephemeral sessions. */
export class MemoryStorageBackend implements IdentityStorage {
  private identity: StoredIdentity | null = null
  private bundle: StoredServerKeys | null = null
  private tokens = new Map<string, StoredServerToken>()

  async getIdentity (): Promise<StoredIdentity | null> {
    return this.identity
  }

  async setIdentity (identity: StoredIdentity | null): Promise<void> {
    this.identity = identity
  }

  async getBundle (): Promise<StoredServerKeys | null> {
    return this.bundle
  }

  async setBundle (bundle: StoredServerKeys | null): Promise<void> {
    this.bundle = bundle
  }

  async upsertServerKey (entry: ClientKeyBundleServer): Promise<void> {
    const servers = this.bundle?.servers.filter((s) => s.serverPubKey !== entry.serverPubKey) ?? []
    servers.push(entry)
    this.bundle = {
      issuedAtSec: this.bundle?.issuedAtSec ?? Math.floor(Date.now() / 1000),
      servers,
    }
  }

  async getServerToken (serverPubKey: string): Promise<StoredServerToken | null> {
    return this.tokens.get(serverPubKey) ?? null
  }

  async setServerToken (serverPubKey: string, token: StoredServerToken | null): Promise<void> {
    if (token === null) {
      this.tokens.delete(serverPubKey)
    } else {
      this.tokens.set(serverPubKey, token)
    }
  }
}
