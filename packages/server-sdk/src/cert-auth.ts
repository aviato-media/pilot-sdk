// Server-side cert-auth handshake (the other half of client-sdk's
// serverCertAuth).
//
// Endpoints to wire up (host's framework — Hono, Express, Fastify, etc.):
//   POST /api/auth/identity-session/begin     → beginChallenge()
//   POST /api/auth/identity-session/complete  → completeChallenge()
//
// The host integrates these into its own routing; this module just provides
// the pure logic so it stays framework-agnostic.

import type {
  ClientDelegationCertEnvelope,
  ClientDelegationCertPayload,
  IdentitySessionAssertion,
  PublicKeyLike,
} from '@aviato-media/pilot-core'
import { verifyClientCert, verifySessionAssertion } from '@aviato-media/pilot-core'

import type {
  IdentityClientStore,
  IdentityUserStore,
  SessionChallengeStore,
} from './stores.js'

export interface BeginChallengeInput {
  readonly cert: ClientDelegationCertEnvelope
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  readonly challengeStore: SessionChallengeStore
  readonly userStore: IdentityUserStore
  readonly clientStore: IdentityClientStore
}

export type BeginChallengeResult
  = | { ok: true,
    challenge: string,
    certPayload: ClientDelegationCertPayload }
  | { ok: false,
    status: 400 | 403,
    error: string }

export async function beginChallenge (input: BeginChallengeInput): Promise<BeginChallengeResult> {
  const certResult = verifyClientCert(input.cert)
  if (!certResult.ok) {
    return {
      error: certResult.error,
      ok: false,
      status: 400,
    }
  }
  const user = await input.userStore.getByPublicKey(certResult.payload.userPubKey)
  if (user === null) {
    return {
      error: 'user_not_registered',
      ok: false,
      status: 403,
    }
  }
  if (await input.clientStore.isRevoked(certResult.payload.clientId)) {
    return {
      error: 'client_revoked',
      ok: false,
      status: 403,
    }
  }
  const issued = await input.challengeStore.create()
  return {
    certPayload: certResult.payload,
    challenge: issued.challenge,
    ok: true,
  }
}

export interface CompleteChallengeInput {
  readonly assertion: IdentitySessionAssertion
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  readonly challengeStore: SessionChallengeStore
  readonly userStore: IdentityUserStore
  readonly clientStore: IdentityClientStore
}

export type CompleteChallengeResult
  = | { ok: true,
    userId: string,
    certPayload: ClientDelegationCertPayload }
  | { ok: false,
    status: 400 | 401 | 403,
    error: string }

export async function completeChallenge (input: CompleteChallengeInput): Promise<CompleteChallengeResult> {
  // Verify FIRST so a forged request cannot burn a legitimate client's
  // single-use challenge nonce.
  const result = verifySessionAssertion(input.assertion, {
    challenge: input.assertion.challenge,
    serverPubKey: input.serverPubKey,
  })
  if (!result.ok) {
    return {
      error: result.error,
      ok: false,
      status: 401,
    }
  }
  // Atomic consume — the verifier already required challenge equality, so
  // consume here is the single-use enforcement point.
  const consumed = await input.challengeStore.consume(input.assertion.challenge)
  if (consumed === null) {
    return {
      error: 'challenge_unknown_or_consumed',
      ok: false,
      status: 401,
    }
  }
  const { certPayload } = result
  const user = await input.userStore.getByPublicKey(certPayload.userPubKey)
  if (user === null) {
    return {
      error: 'user_not_registered',
      ok: false,
      status: 403,
    }
  }
  if (await input.clientStore.isRevoked(certPayload.clientId)) {
    return {
      error: 'client_revoked',
      ok: false,
      status: 403,
    }
  }
  await input.clientStore.upsert({
    certExpiresAt: new Date(certPayload.exp * 1000).toISOString(),
    clientEncPubKey: certPayload.clientEncPubKey,
    clientId: certPayload.clientId,
    clientPubKey: certPayload.clientPubKey,
    deviceName: certPayload.deviceName,
    lastSeenAt: new Date().toISOString(),
    revoked: false,
    userId: user.id,
  })
  return {
    certPayload,
    ok: true,
    userId: user.id,
  }
}
