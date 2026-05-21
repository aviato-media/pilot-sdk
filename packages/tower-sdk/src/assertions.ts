// Build M-signed assertions from inside the user's browser. Callers
// supply M.priv from openVault() and should drop the reference after
// signing.

import type {
  MasterSignedAssertionEnvelope,
  OperatorLinkAssertionPayload,
  PublicKeyLike,
  PublicPrivateKeyLike,
  ServerLinkAssertionPayload,
  ServerSignInAssertionPayload,
} from '@aviato-media/pilot-core'
import { asPublicKey, asPublicPrivateKey, buildPairingAssertion } from '@aviato-media/pilot-core'

export interface ApproveServerLinkInput {
  readonly requestId: string
  /** Ed25519 server pubkey. */
  readonly serverPubKey: PublicKeyLike
  readonly userId: string
  /** Ed25519 user master key. */
  readonly userKey: PublicPrivateKeyLike
  /** X25519 user encryption pubkey. */
  readonly userEncPubKey: PublicKeyLike
  /** Defaults to Date.now() (ms). */
  readonly ts?: number
}

export function approveServerLink (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const userKey = asPublicPrivateKey(input.userKey, 'Ed25519')
  const payload: ServerLinkAssertionPayload = {
    kind: 'server-link',
    requestId: input.requestId,
    serverPubKey: asPublicKey(input.serverPubKey).toHex(),
    ts: input.ts ?? Date.now(),
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: userKey.publicKey.toHex(),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: userKey.privateKey,
    payload,
  })
}

export function approveServerSignIn (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const userKey = asPublicPrivateKey(input.userKey, 'Ed25519')
  const payload: ServerSignInAssertionPayload = {
    kind: 'server-sign-in',
    requestId: input.requestId,
    serverPubKey: asPublicKey(input.serverPubKey).toHex(),
    ts: input.ts ?? Date.now(),
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: userKey.publicKey.toHex(),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: userKey.privateKey,
    payload,
  })
}

export function approveOperatorLink (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const userKey = asPublicPrivateKey(input.userKey, 'Ed25519')
  const payload: OperatorLinkAssertionPayload = {
    kind: 'operator-link',
    requestId: input.requestId,
    serverPubKey: asPublicKey(input.serverPubKey).toHex(),
    ts: input.ts ?? Date.now(),
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: userKey.publicKey.toHex(),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: userKey.privateKey,
    payload,
  })
}
