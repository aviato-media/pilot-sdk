// Verify M-signed pairing assertions returned by the pairing-poll leg.
//
// The verified payload carries userPubKey + userEncPubKey, which the server
// then writes to its identity_users row and uses to seal K back through
// respondWithK().
//
// Success branches are branded VerifiedPairingAssertion values; the brand
// is the only way PairingService.respondWithK accepts them at runtime.

import type { MasterSignedAssertionEnvelope, PublicKeyLike } from '@aviato-media/pilot-core'
import { verifyPairingAssertion } from '@aviato-media/pilot-core'

import type { IdentityUserStore } from './stores.js'
import type { VerifiedPairingAssertion } from './verified-assertion.js'
import { brandVerifiedPairingAssertion } from './verified-assertion.js'

export interface VerifyServerLinkOptions {
  readonly envelope: MasterSignedAssertionEnvelope
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string) — your server's identity. */
  readonly expectedServerPubKey: PublicKeyLike
  readonly expectedRequestId: string
  readonly maxAgeMs?: number
}

export type VerifyServerLinkResult
  = | VerifiedPairingAssertion
  | { ok: false,
    error: string }

export function verifyServerLinkAssertion (opts: VerifyServerLinkOptions): VerifyServerLinkResult {
  const result = verifyPairingAssertion(opts.envelope, {
    expectedKind: 'server-link',
    expectedRequestId: opts.expectedRequestId,
    expectedServerPubKey: opts.expectedServerPubKey,
    maxAgeMs: opts.maxAgeMs,
  })
  if (!result.ok) {
    return {
      error: result.error,
      ok: false,
    }
  }
  return brandVerifiedPairingAssertion({
    userEncPubKey: result.payload.userEncPubKey,
    userId: result.payload.userId,
    userPubKey: result.payload.userPubKey,
  })
}

export type VerifyServerSignInResult = VerifyServerLinkResult

export interface VerifyServerSignInOptions extends VerifyServerLinkOptions {
  readonly expectedUserPubKey?: PublicKeyLike
}

export function verifyServerSignInAssertion (opts: VerifyServerSignInOptions): VerifyServerSignInResult {
  const result = verifyPairingAssertion(opts.envelope, {
    expectedKind: 'server-sign-in',
    expectedRequestId: opts.expectedRequestId,
    expectedServerPubKey: opts.expectedServerPubKey,
    expectedUserPubKey: opts.expectedUserPubKey,
    maxAgeMs: opts.maxAgeMs,
  })
  if (!result.ok) {
    return {
      error: result.error,
      ok: false,
    }
  }
  return brandVerifiedPairingAssertion({
    userEncPubKey: result.payload.userEncPubKey,
    userId: result.payload.userId,
    userPubKey: result.payload.userPubKey,
  })
}

export async function verifyAndPersist (input: {
  envelope: MasterSignedAssertionEnvelope
  expectedServerPubKey: PublicKeyLike
  expectedRequestId: string
  userStore: IdentityUserStore
  kind?: 'server-link' | 'server-sign-in'
}): Promise<VerifyServerLinkResult> {
  const verified = (input.kind === 'server-sign-in')
    ? verifyServerSignInAssertion({
      envelope: input.envelope,
      expectedRequestId: input.expectedRequestId,
      expectedServerPubKey: input.expectedServerPubKey,
    })
    : verifyServerLinkAssertion({
      envelope: input.envelope,
      expectedRequestId: input.expectedRequestId,
      expectedServerPubKey: input.expectedServerPubKey,
    })
  if (!verified.ok) {
    return verified
  }
  const existing = await input.userStore.getByPublicKey(verified.userPubKey)
  if (existing !== null) {
    await input.userStore.upsertUserEncPubKey(existing.id, verified.userEncPubKey)
  }
  return verified
}
