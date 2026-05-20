// Branded VerifiedPairingAssertion: runtime tag (non-exported unique symbol)
// makes it impossible to hand-construct one outside this module. Only
// verifyServerLinkAssertion / verifyServerSignInAssertion call the brander.
// PairingService.respondWithK runtime-checks the brand before sealing K.

const VERIFIED_PAIRING_ASSERTION_BRAND: unique symbol = Symbol('VerifiedPairingAssertion')

export interface VerifiedPairingAssertion {
  readonly ok: true
  readonly userPubKey: string
  readonly userEncPubKey: string
  readonly userId: string
  readonly [VERIFIED_PAIRING_ASSERTION_BRAND]: true
}

export function brandVerifiedPairingAssertion (inner: {
  readonly userPubKey: string
  readonly userEncPubKey: string
  readonly userId: string
}): VerifiedPairingAssertion {
  return Object.freeze({
    [VERIFIED_PAIRING_ASSERTION_BRAND]: true as const,
    ok: true as const,
    userEncPubKey: inner.userEncPubKey,
    userId: inner.userId,
    userPubKey: inner.userPubKey,
  })
}

export function isVerifiedPairingAssertion (x: unknown): x is VerifiedPairingAssertion {
  if (typeof x !== 'object' || x === null) {
    return false
  }
  return (x as Record<symbol, unknown>)[VERIFIED_PAIRING_ASSERTION_BRAND] === true
}
