// Browser-side handling of the pairing-response leg.
//
// After approveServerLink → POST /complete, the user's browser polls Tower
// /pairing-response/:requestId. When the media server has attached a
// sealed payload, this module verifies the server's signature and decrypts
// the sealed K — writing it into vault.servers[i].connInfoKey.

import type {
  OpenPairingResponseError,
  PairingResponseRecord,
  PairingResponseSealed,
  PublicKeyLike,
} from '@aviato-media/pilot-core'
import { openPairingResponse } from '@aviato-media/pilot-core'

export interface ClaimConnInfoKeyInput {
  readonly record: PairingResponseRecord
  readonly userEncPrivKey: Uint8Array
  /** Expected server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly expectedServerPubKey: PublicKeyLike
}

export type ClaimConnInfoKeyResult
  = | { ok: true,
    sealed: PairingResponseSealed }
  | { ok: false,
    error: OpenPairingResponseError }

export async function claimConnInfoKey (input: ClaimConnInfoKeyInput): Promise<ClaimConnInfoKeyResult> {
  const opened = await openPairingResponse({
    expectedServerPubKey: input.expectedServerPubKey,
    payload: input.record.payload,
    userEncPrivKey: input.userEncPrivKey,
  })
  if (!opened.ok) {
    return {
      error: opened.error,
      ok: false,
    }
  }
  return {
    ok: true,
    sealed: opened.payload,
  }
}
