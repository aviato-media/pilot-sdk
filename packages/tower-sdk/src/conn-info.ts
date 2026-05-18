// Browser-side fetch+verify+decrypt of a ServerConnInfo record, for the
// Tower /pair page previews + "your servers" dashboard.
//
// Mirrors what pilot-client-sdk does — but Tower-web has K available in
// memory from the open vault, so it can resolve and display conn info
// before any client app pairs.

import type { ServerConnInfoPayload, ServerConnInfoRecord } from '@aviato-media/pilot-core'
import {
  base64urlEncode,
  openServerConnInfo,
  sha256Bytes,
  verifyConnInfoRecordSig,
} from '@aviato-media/pilot-core'

export interface ResolveConnInfoInput {
  readonly record: ServerConnInfoRecord
  readonly connInfoKey: Uint8Array
}

export type ResolveConnInfoResult
  = | { ok: true,
    payload: ServerConnInfoPayload }
  | { ok: false,
    error: 'sig_invalid' | 'aead_decrypt_failed' | 'payload_shape_invalid' | 'rotation_counter_mismatch' }

export async function resolveConnInfo (input: ResolveConnInfoInput): Promise<ResolveConnInfoResult> {
  if (!verifyConnInfoRecordSig(input.record)) {
    return {
      error: 'sig_invalid',
      ok: false,
    }
  }
  const opened = await openServerConnInfo({
    connInfoKey: input.connInfoKey,
    record: input.record,
  })
  if (!opened.ok) {
    return {
      error: opened.error,
      ok: false,
    }
  }
  return {
    ok: true,
    payload: opened.payload,
  }
}

/**
 * Compute the partition-hash that Tower uses to key the per-server
 * conn-info DDB partition. The same hash is the URL slug for
 * `GET /api/identity/server-conninfo/:hash` — Tower-web and pilot-client-
 * sdk use this to fetch a server's published conn info without ever
 * revealing the user↔server linkage on the wire.
 */
export function deriveConnInfoHash (serverPubKey: Uint8Array): string {
  return base64urlEncode(sha256Bytes(serverPubKey))
}
