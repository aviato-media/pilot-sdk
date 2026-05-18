// Fetch + verify + decrypt a ServerConnInfo record.
//
// Three layers of defense:
//   1. Tower verified the publish sig before storing (server-enforced).
//   2. We verify it again here against a tampered cache (defense in depth).
//   3. AEAD decrypt fails if K is stale → caller must trigger re-pair.

import type {
  PublicKeyLike,
  ServerConnInfoPayload,
  ServerConnInfoRecord,
} from '@aviato-media/pilot-core'
import {
  asPublicKey,
  base64urlEncode,
  openServerConnInfo,
  sha256Bytes,
  verifyConnInfoRecordSig,
} from '@aviato-media/pilot-core'

import type { TowerClient } from './tower-client.js'

export interface ResolveServerConnInfoInput {
  readonly tower: TowerClient
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  /** Per-server K (32 bytes). */
  readonly connInfoKey: Uint8Array
}

export type ResolveServerConnInfoResult
  = | { ok: true,
    payload: ServerConnInfoPayload,
    record: ServerConnInfoRecord }
  | { ok: false,
    error: ResolveServerConnInfoError }

export type ResolveServerConnInfoError
  = | 'not_found'
  | 'tower_sig_invalid'
  | 'stale_k_or_decrypt_failed'
  | 'shape_invalid'

export async function resolveServerConnInfo (
  input: ResolveServerConnInfoInput,
): Promise<ResolveServerConnInfoResult> {
  const hash = deriveServerConnInfoHash(input.serverPubKey)
  const record = await input.tower.fetchServerConnInfo(hash)
  if (record === null) {
    return {
      error: 'not_found',
      ok: false,
    }
  }
  if (!verifyConnInfoRecordSig(record)) {
    return {
      error: 'tower_sig_invalid',
      ok: false,
    }
  }
  const opened = await openServerConnInfo({
    connInfoKey: input.connInfoKey,
    record,
  })
  if (!opened.ok) {
    if (opened.error === 'aead_decrypt_failed') {
      return {
        error: 'stale_k_or_decrypt_failed',
        ok: false,
      }
    }
    return {
      error: 'shape_invalid',
      ok: false,
    }
  }
  return {
    ok: true,
    payload: opened.payload,
    record,
  }
}

/** base64url(sha256(serverPubKeyBytes)) — the hash Tower uses as the conn-info partition key. */
export function deriveServerConnInfoHash (serverPubKey: PublicKeyLike): string {
  return base64urlEncode(sha256Bytes(asPublicKey(serverPubKey).toRaw()))
}
