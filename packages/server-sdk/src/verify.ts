// Verify M-signed pairing assertions returned by the pairing-poll leg.
//
// The verified payload carries userPubKey + userEncPubKey, which the server
// then writes to its identity_users row and uses to seal K back through
// respondWithK().

import type { MasterSignedAssertionEnvelope, PublicKeyLike } from '@aviato-media/pilot-core'
import { verifyPairingAssertion } from '@aviato-media/pilot-core'

import type { IdentityUserStore } from './stores.js'

export interface VerifyServerLinkOptions {
  readonly envelope: MasterSignedAssertionEnvelope
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string) — your server's identity. */
  readonly expectedServerPubKey: PublicKeyLike
  readonly expectedRequestId: string
  readonly maxAgeMs?: number
}

export type VerifyServerLinkResult
  = | { ok: true,
    userPubKey: string,
    userEncPubKey: string,
    userId: string }
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
  return {
    ok: true,
    userEncPubKey: result.payload.userEncPubKey,
    userId: result.payload.userId,
    userPubKey: result.payload.userPubKey,
  }
}

export type VerifyServerSignInResult = VerifyServerLinkResult

export interface VerifyServerSignInOptions extends VerifyServerLinkOptions {
  /** If set, payload.userPubKey must equal this key (`PublicKey`, raw bytes, or hex string). */
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
  return {
    ok: true,
    userEncPubKey: result.payload.userEncPubKey,
    userId: result.payload.userId,
    userPubKey: result.payload.userPubKey,
  }
}

/** Sugar: verify assertion AND upsert userEncPubKey on the local user row. */
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
