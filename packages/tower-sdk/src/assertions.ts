// Build M-signed assertions from inside the user's browser. Callers
// supply M.priv from openVault() and should drop the reference after
// signing.

import type {
  MasterSignedAssertionEnvelope,
  PrivateKeyLike,
  PublicKeyLike,
  ServerLinkAssertionPayload,
  ServerSignInAssertionPayload,
} from '@aviato-media/pilot-core'
import { asPublicKey, buildPairingAssertion } from '@aviato-media/pilot-core'

export interface ApproveServerLinkInput {
  readonly requestId: string
  /** Ed25519 server pubkey. */
  readonly serverPubKey: PublicKeyLike
  readonly userId: string
  /** Ed25519 user master pubkey. */
  readonly userPubKey: PublicKeyLike
  /** X25519 user encryption pubkey. */
  readonly userEncPubKey: PublicKeyLike
  /** Ed25519 user master private key. */
  readonly masterPrivKey: PrivateKeyLike
  /** Defaults to Date.now() (ms). */
  readonly ts?: number
}

export function approveServerLink (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const payload: ServerLinkAssertionPayload = {
    kind: 'server-link',
    requestId: input.requestId,
    serverPubKey: asPublicKey(input.serverPubKey).toHex(),
    ts: input.ts ?? Date.now(),
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: asPublicKey(input.userPubKey).toHex(),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: input.masterPrivKey,
    payload,
  })
}

export function approveServerSignIn (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const payload: ServerSignInAssertionPayload = {
    kind: 'server-sign-in',
    requestId: input.requestId,
    serverPubKey: asPublicKey(input.serverPubKey).toHex(),
    ts: input.ts ?? Date.now(),
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: asPublicKey(input.userPubKey).toHex(),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: input.masterPrivKey,
    payload,
  })
}
