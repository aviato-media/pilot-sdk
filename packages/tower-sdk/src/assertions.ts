// Build M-signed assertions from inside the user's browser. Callers
// supply M.priv from openVault() and should drop the reference after
// signing.

import type {
  MasterSignedAssertionEnvelope,
  ServerLinkAssertionPayload,
  ServerSignInAssertionPayload,
} from '@aviato-media/pilot-core'
import { buildPairingAssertion, hexEncode } from '@aviato-media/pilot-core'

export interface ApproveServerLinkInput {
  readonly requestId: string
  /** Raw 32-byte Ed25519 server pubkey. */
  readonly serverPubKey: Uint8Array
  readonly userId: string
  /** Raw 32-byte Ed25519 user master pubkey. */
  readonly userPubKey: Uint8Array
  /** Raw 32-byte X25519 user encryption pubkey. */
  readonly userEncPubKey: Uint8Array
  /** Raw 32-byte Ed25519 user master private key. */
  readonly masterPrivKey: Uint8Array
  /** Defaults to Date.now() (ms). */
  readonly ts?: number
}

export function approveServerLink (input: ApproveServerLinkInput): MasterSignedAssertionEnvelope {
  const payload: ServerLinkAssertionPayload = {
    kind: 'server-link',
    requestId: input.requestId,
    serverPubKey: hexEncode(input.serverPubKey),
    ts: input.ts ?? Date.now(),
    userEncPubKey: hexEncode(input.userEncPubKey),
    userId: input.userId,
    userPubKey: hexEncode(input.userPubKey),
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
    serverPubKey: hexEncode(input.serverPubKey),
    ts: input.ts ?? Date.now(),
    userEncPubKey: hexEncode(input.userEncPubKey),
    userId: input.userId,
    userPubKey: hexEncode(input.userPubKey),
    v: 1,
  }
  return buildPairingAssertion({
    masterPrivKey: input.masterPrivKey,
    payload,
  })
}
