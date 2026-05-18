// Canonical bytes signed when a media server publishes its ct to Tower.
//
// `JSON.stringify` on a 4-key alphabetical-order object is byte-equivalent
// to JCS for these primitive values. Keeping the explicit object literal
// here documents the key order at the protocol level — do not refactor
// into a generic helper.

import { ENCODER } from '../crypto/encoding.js'

export interface ConnInfoCanonicalInput {
  readonly ct: string
  readonly nonce: string
  readonly serverPubKey: string
  readonly version: number
}

export function buildConnInfoCanonical (input: ConnInfoCanonicalInput): Uint8Array {
  return ENCODER.encode(JSON.stringify({
    ct: input.ct,
    nonce: input.nonce,
    serverPubKey: input.serverPubKey,
    version: input.version,
  }))
}
