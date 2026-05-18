// Per-server cert-auth handshake.
//
// 1. Client POSTs `cert` to /api/auth/identity-session/begin → server returns a hex challenge.
// 2. Client signs (with C_n_priv) the JCS of {cert, challenge, serverId, ts}.
// 3. Client POSTs assertion to /api/auth/identity-session/complete → server returns session token.
//
// Optionally the complete response carries an in-session K refresh envelope
// (sealed to clientEncPub) so a client with stale K can recover.

import type {
  ClientDelegationCertEnvelope,
  PrivateKeyLike,
  PublicKeyLike,
  SealedBox,
  SessionConnInfoEnvelope,
} from '@aviato-media/pilot-core'
import {
  aviatoSealedBoxDecryptJson,
  aviatoSealedBoxDecryptJsonHandle,
  buildSessionAssertion,
  buildSessionAssertionAsync,
  SessionConnInfoEnvelopeSchema,
} from '@aviato-media/pilot-core'

import type { KeyOps } from './key-ops.js'

export class ServerAuthError extends Error {
  constructor (
    message: string,
    readonly code: 'http' | 'shape' | 'sig' | 'no_server_pubkey',
    readonly status?: number,
  ) {
    super(message)
    this.name = 'ServerAuthError'
  }
}

interface ServerCertAuthInputBase {
  /** Base URL for the media server, e.g. "https://media.example.com". */
  readonly baseUrl: string
  /** The user's cert envelope (signed by M). */
  readonly cert: ClientDelegationCertEnvelope
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string) — used as serverId in the assertion. */
  readonly serverPubKey: PublicKeyLike
  /** Optional fetch override. */
  readonly fetch?: typeof globalThis.fetch
}

export interface ServerCertAuthInputRaw extends ServerCertAuthInputBase {
  /** Per-device Ed25519 private key (C_n_priv) — `PrivateKey` or raw bytes. */
  readonly clientPrivKey: PrivateKeyLike
  /** Per-device X25519 private key — for opening the session conn-info envelope. */
  readonly clientEncPrivKey: PrivateKeyLike
}

export interface ServerCertAuthInputOps extends ServerCertAuthInputBase {
  readonly keyOps: KeyOps
}

export type ServerCertAuthInput = ServerCertAuthInputRaw | ServerCertAuthInputOps

export interface ServerCertAuthResult<TBody = unknown> {
  readonly token: string
  readonly expiresAt: string
  /** Fresh K if the server refreshed mid-session. */
  readonly refreshedConnInfoKey?: SessionConnInfoEnvelope
  /** Full /identity-session/complete body. Type with the `TBody` generic. */
  readonly body: TBody
}

export async function serverCertAuth<TBody = unknown> (input: ServerCertAuthInput): Promise<ServerCertAuthResult<TBody>> {
  const fetchImpl = input.fetch ?? globalThis.fetch.bind(globalThis)
  const base = input.baseUrl.replace(/\/+$/, '')

  // Step 1: challenge
  const beginRes = await fetchImpl(`${base}/api/auth/identity-session/begin`, {
    body: JSON.stringify({ cert: input.cert }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  })
  if (!beginRes.ok) {
    throw new ServerAuthError(`identity-session/begin: ${beginRes.status}`, 'http', beginRes.status)
  }
  const beginBody = await beginRes.json().catch(() => null) as { challenge?: string } | null
  const challenge = beginBody?.challenge
  if (typeof challenge !== 'string' || !/^[0-9a-f]+$/.test(challenge)) {
    throw new ServerAuthError('identity-session/begin: missing/invalid challenge', 'shape')
  }

  // Step 2: sign assertion (handle-based when KeyOps supplied, raw-bytes otherwise)
  const assertion = 'keyOps' in input
    ? await buildSessionAssertionAsync({
      cert: input.cert,
      challenge,
      serverPubKey: input.serverPubKey,
      sign: (msg) => input.keyOps.signEd25519(msg),
    })
    : buildSessionAssertion({
      cert: input.cert,
      challenge,
      clientPrivKey: input.clientPrivKey,
      serverPubKey: input.serverPubKey,
    })

  // Step 3: complete
  const completeRes = await fetchImpl(`${base}/api/auth/identity-session/complete`, {
    body: JSON.stringify(assertion),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  })
  if (!completeRes.ok) {
    throw new ServerAuthError(`identity-session/complete: ${completeRes.status}`, 'http', completeRes.status)
  }
  const completeBody = await completeRes.json().catch(() => null) as {
    token?: string
    expiresAt?: string
    aviato_conn_info_key_envelope?: SealedBox
  } | null
  if (
    typeof completeBody?.token !== 'string'
    || typeof completeBody.expiresAt !== 'string'
  ) {
    throw new ServerAuthError('identity-session/complete: missing token/expiresAt', 'shape')
  }

  let refreshedConnInfoKey: SessionConnInfoEnvelope | undefined
  if (completeBody.aviato_conn_info_key_envelope !== undefined) {
    const decoded = 'keyOps' in input
      ? await aviatoSealedBoxDecryptJsonHandle<unknown>({
        box: completeBody.aviato_conn_info_key_envelope,
        deriveShared: (peerPub) => input.keyOps.deriveX25519Shared(peerPub),
      })
      : await aviatoSealedBoxDecryptJson<unknown>({
        box: completeBody.aviato_conn_info_key_envelope,
        recipientPriv: input.clientEncPrivKey,
      })
    const parsed = SessionConnInfoEnvelopeSchema.safeParse(decoded)
    if (parsed.success) {
      refreshedConnInfoKey = parsed.data
    }
  }

  return {
    body: completeBody as TBody,
    expiresAt: completeBody.expiresAt,
    refreshedConnInfoKey,
    token: completeBody.token,
  }
}

/** clientId from a clientPub: lowercase hex of sha256(pub).slice(0, 32) — used by some legacy paths. */
