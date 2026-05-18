// In-session K refresh envelope.
//
// When a client completes cert-auth, the server's response can include a
// sealed envelope carrying current K — so a client with stale K can refresh
// without re-pairing.

import type { SealedBox, SessionConnInfoEnvelope } from '@aviato-media/pilot-core'
import {
  aviatoSealedBoxEncrypt,
  base64urlEncode,
  jcs,
} from '@aviato-media/pilot-core'

export interface SealSessionConnInfoInput {
  readonly connInfoKey: Uint8Array
  /** Raw 32-byte client X25519 encryption pubkey (recipient). */
  readonly clientEncPubKey: Uint8Array
  readonly issuedAtSec?: number
}

export async function sealSessionConnInfoEnvelope (input: SealSessionConnInfoInput): Promise<SealedBox> {
  const envelope: SessionConnInfoEnvelope = {
    connInfoKey: base64urlEncode(input.connInfoKey),
    issuedAtSec: input.issuedAtSec ?? Math.floor(Date.now() / 1000),
    v: 1,
  }
  return aviatoSealedBoxEncrypt({
    plaintext: jcs(envelope),
    recipientPub: input.clientEncPubKey,
  })
}
