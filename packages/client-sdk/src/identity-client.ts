import type {
  ClientDelegationCertEnvelope,
  ClientDelegationCertPayload,
  Ed25519Keypair,
  PublicKeyLike,
  SealedBox,
  X25519Keypair,
} from '@aviato-media/pilot-core'
import {
  asPublicKey,
  base64urlDecode,
  base64urlEncode,
  ClientDelegationCertPayloadSchema,
  DECODER,
  generateEd25519Keypair,
  generateX25519Keypair,
  openClientBundle,
  openClientBundleHandle,
  PublicKey,
  verifyClientCert,
} from '@aviato-media/pilot-core'

import type { KeyOps } from './key-ops.js'
import { ServerAuthError, serverCertAuth, type ServerCertAuthResult } from './server-cert-auth.js'
import { resolveServerConnInfo } from './server-conninfo.js'
import type { IdentityStorage, StoredIdentity } from './storage.js'
import { LocalStorageBackend } from './storage.js'
import { TowerApiError, TowerClient } from './tower-client.js'

export interface AviatoPilotClientOptions {
  /** Tower API base URL, e.g. "https://tower.aviato.media". */
  readonly towerBaseUrl: string
  /** Tower web base URL (where /pair is served). Defaults to `towerBaseUrl`. */
  readonly towerWebUrl?: string
  readonly storage?: IdentityStorage
  readonly fetch?: typeof globalThis.fetch
  /** App ID registered on Tower (`/developer/apps`). */
  readonly appId: string
  /** Friendly device name surfaced in the user's vault devices list. */
  readonly deviceName: string
}

export type ServerConnectionErrorCode
  = | 'http'
  | 'shape'
  | 'sig'
  | 'no_server_pubkey'
  | 'tower_sig_invalid'
  | 'shape_invalid'
  | 'no_identity'
  | 'unknown'

export type ServerConnectionStatus
  = | { state: 'idle' }
  | { state: 'connecting' }
  | { state: 'online',
    baseUrl: string,
    sessionToken: string,
    expiresAt: string }
  | { state: 'offline' }
  | { state: 'unauthorized',
    httpStatus?: number }
  | { state: 'stale_k' }
  | { state: 'error',
    code: ServerConnectionErrorCode,
    error: string,
    httpStatus?: number }

export interface ServerConnection {
  readonly serverPubKey: PublicKey
  readonly status: ServerConnectionStatus
}

/**
 * State held between `beginPair` and a resumed `pollPair`. Exactly one
 * of `{clientKeypair, clientEncKeypair}` (raw-bytes path) or `{keyOps}`
 * (handle path) is populated.
 */
export interface EphemeralPairState {
  readonly requestId: string
  readonly clientKeypair?: Ed25519Keypair
  readonly clientEncKeypair?: X25519Keypair
  readonly keyOps?: KeyOps
}

export interface PairingHandle {
  readonly requestId: string
  readonly code: string
  readonly expiresAt: string
  /** User-facing URL to render (or QR). `${towerWebUrl ?? towerBaseUrl}/pair?code=<code>`. */
  readonly pairingUrl: string
  readonly ephemeral: EphemeralPairState
  /** Poll Tower until the user completes the flow. */
  await (opts?: { signal?: AbortSignal }): Promise<StoredIdentity>
  cancel (): void
}

export interface PairPollResult {
  readonly state: 'pending' | 'claimed_by_user' | 'completed' | 'denied' | 'expired'
  readonly identity?: StoredIdentity
}

export type Listener = (snapshot: ReadonlyArray<ServerConnection>) => void

export class AviatoPilotClient {
  private readonly tower: TowerClient
  private readonly storage: IdentityStorage
  private readonly opts: AviatoPilotClientOptions
  private readonly connections = new Map<string, ServerConnection>()
  private readonly listeners = new Set<Listener>()
  // Reference-stable snapshot. `useSyncExternalStore` consumers loop
  // forever if `getConnections()` returns a fresh array each call.
  private connectionsSnapshot: ReadonlyArray<ServerConnection> | null = null

  constructor (opts: AviatoPilotClientOptions) {
    this.opts = opts
    this.tower = new TowerClient({
      baseUrl: opts.towerBaseUrl,
      fetch: opts.fetch,
    })
    this.storage = opts.storage ?? new LocalStorageBackend()
  }

  // ── Observability ────────────────────────────────────────────────────

  /** Subscribe to connection-state changes. Returns an unsubscribe fn. */
  subscribe (listener: Listener): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  private emit (): void {
    this.connectionsSnapshot = Object.freeze([...this.connections.values()])
    for (const l of this.listeners) {
      try {
        l(this.connectionsSnapshot)
      } catch {
        // Listener errors must not break sibling listeners.
      }
    }
  }

  private setStatus (serverPubKey: string, status: ServerConnectionStatus): void {
    this.connections.set(serverPubKey, {
      serverPubKey: new PublicKey(serverPubKey),
      status,
    })
    this.emit()
  }

  getConnection (serverPubKey: string): ServerConnection | undefined {
    return this.connections.get(serverPubKey)
  }

  getConnections (): ReadonlyArray<ServerConnection> {
    if (this.connectionsSnapshot === null) {
      this.connectionsSnapshot = Object.freeze([...this.connections.values()])
    }
    return this.connectionsSnapshot
  }

  async hasIdentity (): Promise<boolean> {
    return (await this.storage.getIdentity()) !== null
  }

  async getIdentity (): Promise<StoredIdentity | null> {
    return this.storage.getIdentity()
  }

  /** Seed the connection cache from persisted bundle. Returns true if identity found. */
  async hydrate (): Promise<boolean> {
    const identity = await this.storage.getIdentity()
    if (identity === null) {
      return false
    }
    const bundle = await this.storage.getBundle()
    this.connections.clear()
    for (const s of bundle?.servers ?? []) {
      this.connections.set(s.serverPubKey, {
        serverPubKey: new PublicKey(s.serverPubKey),
        status: { state: 'idle' },
      })
    }
    this.emit()
    return true
  }

  // ── Pairing ──────────────────────────────────────────────────────────

  /** Begin a client-pair flow. The handle's `await()` resolves once the user approves on Tower. */
  async beginPair (opts: { pollIntervalMs?: number,
    maxAttempts?: number } = {}): Promise<PairingHandle> {
    const useOps = typeof this.storage.generateClientKeys === 'function'
    const keyOps = useOps ? await this.storage.generateClientKeys!() : undefined
    const clientKeypair = useOps ? undefined : generateEd25519Keypair()
    const clientEncKeypair = useOps ? undefined : generateX25519Keypair()
    const clientPubKey: PublicKey = keyOps !== undefined
      ? keyOps.clientPubKey
      : clientKeypair!.publicKey
    const clientEncPubKey: PublicKey = keyOps !== undefined
      ? keyOps.clientEncPubKey
      : clientEncKeypair!.publicKey

    const response = await this.tower.clientPairBegin({
      appId: this.opts.appId,
      clientEncPubKey: base64urlEncode(clientEncPubKey.toRaw()),
      clientPubKey: base64urlEncode(clientPubKey.toRaw()),
      deviceName: this.opts.deviceName,
    })

    const ephemeral: EphemeralPairState = {
      clientEncKeypair,
      clientKeypair,
      keyOps,
      requestId: response.requestId,
    }

    let cancelled = false
    const pollIntervalMs = opts.pollIntervalMs ?? 2000
    const maxAttempts = opts.maxAttempts ?? 600 // 20 minutes at 2s intervals

    const awaitFn = async (awaitOpts?: { signal?: AbortSignal }): Promise<StoredIdentity> => {
      for (let i = 0; i < maxAttempts; i++) {
        if (cancelled || awaitOpts?.signal?.aborted === true) {
          throw new Error('pairing cancelled')
        }
        const result = await this.pollPair({
          ephemeral,
          signal: awaitOpts?.signal,
        })
        if (result.state === 'completed' && result.identity !== undefined) {
          return result.identity
        }
        if (result.state === 'denied' || result.state === 'expired') {
          throw new Error(`pairing ${result.state}`)
        }
        await new Promise((r) => setTimeout(r, pollIntervalMs))
      }
      throw new Error('pairing timed out')
    }

    const webBase = (this.opts.towerWebUrl ?? this.opts.towerBaseUrl).replace(/\/+$/, '')
    return {
      await: awaitFn,
      cancel: () => {
        cancelled = true
      },
      code: response.code,
      ephemeral,
      expiresAt: response.expiresAt,
      pairingUrl: `${webBase}/pair?code=${response.code}`,
      requestId: response.requestId,
    }
  }

  /**
   * Single-shot poll of a pairing request. Stash `{requestId, ephemeral}`
   * from `beginPair()` to resume from a different session.
   */
  async pollPair (input: {
    ephemeral: EphemeralPairState
    signal?: AbortSignal
  }): Promise<PairPollResult> {
    if (input.signal?.aborted === true) {
      throw new Error('aborted')
    }
    const poll = await this.tower.clientPairPoll(input.ephemeral.requestId)
    if (poll.state !== 'completed') {
      return { state: poll.state }
    }
    if (
      poll.signedCertBytes === undefined
      || poll.certSignature === undefined
      || poll.sealedConnInfoBundle === undefined
      || poll.sealedConnInfoBundle === null
    ) {
      throw new Error('completed pairing missing cert or bundle')
    }
    const identity = await this.finalizePair({
      certSignature: poll.certSignature,
      clientEncKeypair: input.ephemeral.clientEncKeypair,
      clientKeypair: input.ephemeral.clientKeypair,
      keyOps: input.ephemeral.keyOps,
      sealedBundle: poll.sealedConnInfoBundle,
      signedCertBytes: poll.signedCertBytes,
    })
    return {
      identity,
      state: 'completed',
    }
  }

  private async finalizePair (input: {
    signedCertBytes: string
    certSignature: string
    sealedBundle: SealedBox
    clientKeypair?: Ed25519Keypair
    clientEncKeypair?: X25519Keypair
    keyOps?: KeyOps
  }): Promise<StoredIdentity> {
    if (
      (input.keyOps === undefined && (input.clientKeypair === undefined || input.clientEncKeypair === undefined))
      || (input.keyOps !== undefined && (input.clientKeypair !== undefined || input.clientEncKeypair !== undefined))
    ) {
      throw new Error('finalizePair: exactly one of {clientKeypair+clientEncKeypair} or {keyOps} must be supplied')
    }
    const cert = {
      payload: input.signedCertBytes,
      sig: input.certSignature,
    }
    // First-pair trust root: no expectedUserPubKey to pin against yet —
    // the keypair-binding and appId checks below catch a Tower key swap.
    // Renewals pin via verifyClientCert(..., { expectedUserPubKey }).
    const verified = verifyClientCert(cert)
    if (!verified.ok) {
      throw new Error(`pair: cert verify failed (${verified.error})`)
    }
    const { payload } = verified

    const expectedClientPubKeyHex = input.keyOps !== undefined
      ? input.keyOps.clientPubKey.toHex()
      : input.clientKeypair!.publicKey.toHex()
    const expectedClientEncPubKeyHex = input.keyOps !== undefined
      ? input.keyOps.clientEncPubKey.toHex()
      : input.clientEncKeypair!.publicKey.toHex()
    if (payload.clientPubKey !== expectedClientPubKeyHex) {
      throw new Error('pair: clientPubKey in cert does not match our keypair')
    }
    if (payload.clientEncPubKey !== expectedClientEncPubKeyHex) {
      throw new Error('pair: clientEncPubKey in cert does not match our keypair')
    }
    if (payload.appId !== this.opts.appId) {
      throw new Error(
        `pair: cert appId mismatch — cert is for "${payload.appId}", `
        + `this SDK is configured for "${this.opts.appId}"`,
      )
    }

    const opened = input.keyOps !== undefined
      ? await openClientBundleHandle({
        box: input.sealedBundle,
        deriveShared: (peerPub: Uint8Array) => input.keyOps!.deriveX25519Shared(peerPub),
      })
      : await openClientBundle({
        box: input.sealedBundle,
        clientEncPrivKey: input.clientEncKeypair!.privateKey,
      })
    if (!opened.ok) {
      throw new Error(`pair: bundle decrypt failed (${opened.error})`)
    }

    const identity: StoredIdentity = {
      certSignature: input.certSignature,
      // In handle mode the backend persists private keys non-extractably;
      // StoredIdentity only carries metadata.
      clientEncPrivBase64url: input.clientEncKeypair?.privateKey.toBase64Url(),
      clientId: payload.clientId,
      clientPrivBase64url: input.clientKeypair?.privateKey.toBase64Url(),
      exp: payload.exp,
      iat: payload.iat,
      signedCertBytes: input.signedCertBytes,
      userPubKey: payload.userPubKey,
    }
    await this.storage.setIdentity(identity)
    await this.storage.setBundle({
      issuedAtSec: opened.bundle.issuedAtSec,
      servers: opened.bundle.servers,
    })
    this.connections.clear()
    for (const s of opened.bundle.servers) {
      this.connections.set(s.serverPubKey, {
        serverPubKey: new PublicKey(s.serverPubKey),
        status: { state: 'idle' },
      })
    }
    this.emit()
    return identity
  }

  /**
   * Resolve conn-info, cert-auth against the media server, mint a session
   * token, and persist it. Idempotent — calling again from `online`
   * re-runs the auth flow. `TBody` types the media server's response.
   */
  async signInToServer<TBody = unknown> (input: {
    serverPubKey: PublicKeyLike
    signal?: AbortSignal
  }): Promise<ServerConnection & { body?: TBody }> {
    const serverPubKey = asPublicKey(input.serverPubKey)
    const serverPubKeyHex = serverPubKey.toHex()
    this.setStatus(serverPubKeyHex, { state: 'connecting' })

    const identity = await this.storage.getIdentity()
    if (identity === null) {
      const conn: ServerConnection = {
        serverPubKey,
        status: {
          code: 'no_identity',
          error: 'no identity persisted — call beginPair() first',
          state: 'error',
        },
      }
      this.connections.set(serverPubKeyHex, conn)
      this.emit()
      return conn
    }

    const bundle = await this.storage.getBundle()
    const bundled = bundle?.servers.find((s) => s.serverPubKey === serverPubKeyHex)
    if (bundled === undefined) {
      this.setStatus(serverPubKeyHex, { state: 'unauthorized' })
      return this.connections.get(serverPubKeyHex)!
    }
    const connInfoKey = base64urlDecode(bundled.connInfoKey)

    const resolved = await resolveServerConnInfo({
      connInfoKey,
      serverPubKey: input.serverPubKey,
      tower: this.tower,
    })
    if (!resolved.ok) {
      const status: ServerConnectionStatus = resolved.error === 'stale_k_or_decrypt_failed'
        ? { state: 'stale_k' }
        : resolved.error === 'not_found'
          ? { state: 'offline' }
          : {
            code: resolved.error,
            error: resolved.error,
            state: 'error',
          }
      this.setStatus(serverPubKeyHex, status)
      return this.connections.get(serverPubKeyHex)!
    }

    const cert: ClientDelegationCertEnvelope = {
      payload: identity.signedCertBytes,
      sig: identity.certSignature,
    }
    const baseUrl = `${resolved.payload.protocol}://${resolved.payload.publicHost}:${resolved.payload.port}`

    const loadedOps = typeof this.storage.loadClientKeys === 'function'
      ? await this.storage.loadClientKeys()
      : null
    let auth: ServerCertAuthResult<TBody>
    try {
      if (loadedOps !== null) {
        auth = await serverCertAuth<TBody>({
          baseUrl,
          cert,
          fetch: this.opts.fetch,
          keyOps: loadedOps,
          serverPubKey: input.serverPubKey,
        })
      } else {
        if (identity.clientPrivBase64url === undefined || identity.clientEncPrivBase64url === undefined) {
          throw new ServerAuthError(
            'persisted identity has no raw private keys and the storage backend does not expose `loadClientKeys` — '
            + 'this indicates a backend swap or storage corruption',
            'shape',
          )
        }
        auth = await serverCertAuth<TBody>({
          baseUrl,
          cert,
          clientEncPrivKey: base64urlDecode(identity.clientEncPrivBase64url),
          clientPrivKey: base64urlDecode(identity.clientPrivBase64url),
          fetch: this.opts.fetch,
          serverPubKey: input.serverPubKey,
        })
      }
    } catch (err) {
      if (err instanceof ServerAuthError) {
        if (err.code === 'http' && err.status === 401) {
          this.setStatus(serverPubKeyHex, {
            httpStatus: err.status,
            state: 'unauthorized',
          })
        } else {
          this.setStatus(serverPubKeyHex, {
            code: err.code,
            error: err.message,
            httpStatus: err.status,
            state: 'error',
          })
        }
        return this.connections.get(serverPubKeyHex)!
      }
      const errMsg = err instanceof Error ? err.message : String(err)
      this.setStatus(serverPubKeyHex, {
        code: 'unknown',
        error: errMsg,
        state: 'error',
      })
      return this.connections.get(serverPubKeyHex)!
    }

    await this.storage.setServerToken(serverPubKeyHex, {
      expiresAt: auth.expiresAt,
      token: auth.token,
    })

    if (auth.refreshedConnInfoKey !== undefined) {
      await this.storage.upsertServerKey({
        connInfoKey: auth.refreshedConnInfoKey.connInfoKey,
        serverPubKey: serverPubKeyHex,
      })
    }

    this.setStatus(serverPubKeyHex, {
      baseUrl,
      expiresAt: auth.expiresAt,
      sessionToken: auth.token,
      state: 'online',
    })
    return {
      ...this.connections.get(serverPubKeyHex)!,
      body: auth.body,
    }
  }

  /**
   * Sign in to every server in the bundle in parallel. Per-server
   * failures are recorded on the connection status but don't block siblings.
   */
  async initializeAllConnections (signal?: AbortSignal): Promise<void> {
    const identity = await this.storage.getIdentity()
    const bundle = await this.storage.getBundle()
    if (identity === null || bundle === null) {
      return
    }
    await Promise.all(
      bundle.servers.map((s) =>
        this.signInToServer({
          serverPubKey: s.serverPubKey,
          signal,
        })
          .catch(() => undefined),
      ),
    )
  }

  /**
   * Renew the cert via Tower if it expires within `withinDays`. Failures
   * are non-fatal — the existing cert is still valid until `exp`.
   */
  async renewCertIfNeeded (withinDays = 30): Promise<'renewed' | 'not-needed' | 'unavailable' | 'failed'> {
    const identity = await this.storage.getIdentity()
    if (identity === null) {
      return 'unavailable'
    }
    const remainingMs = identity.exp * 1000 - Date.now()
    if (remainingMs > withinDays * 86400_000) {
      return 'not-needed'
    }
    try {
      const renewed = await this.tower.renewClient({
        cert: {
          payload: identity.signedCertBytes,
          sig: identity.certSignature,
        },
        clientId: identity.clientId,
      })
      const newCert = {
        payload: renewed.signedCertBytes,
        sig: renewed.certSignature,
      }
      const verified = verifyClientCert(newCert, { expectedUserPubKey: identity.userPubKey })
      if (!verified.ok) {
        return 'failed'
      }
      await this.storage.setIdentity({
        ...identity,
        certSignature: renewed.certSignature,
        exp: verified.payload.exp,
        iat: verified.payload.iat,
        signedCertBytes: renewed.signedCertBytes,
      })
      return 'renewed'
    } catch (err) {
      if (err instanceof TowerApiError) {
        return 'failed'
      }
      throw err
    }
  }

  /** Drop all local state. */
  async signOut (): Promise<void> {
    const identity = await this.storage.getIdentity()
    if (identity !== null) {
      const bundle = await this.storage.getBundle()
      for (const s of bundle?.servers ?? []) {
        await this.storage.setServerToken(s.serverPubKey, null)
      }
    }
    await this.storage.setIdentity(null)
    await this.storage.setBundle(null)
    if (typeof this.storage.clearClientKeys === 'function') {
      await this.storage.clearClientKeys()
    }
    this.connections.clear()
    this.emit()
  }

  /** Alias for `signOut()`. */
  async clear (): Promise<void> {
    return this.signOut()
  }

  static parseStoredCertPayload (identity: StoredIdentity): ClientDelegationCertPayload {
    const json = JSON.parse(DECODER.decode(base64urlDecode(identity.signedCertBytes))) as unknown
    return ClientDelegationCertPayloadSchema.parse(json)
  }
}

export { clientIdFromPub } from './util.js'
