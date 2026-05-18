// Small shared helpers internal to the client SDK.

import { hexDecode, hexEncode, sha256Bytes } from '@aviato-media/pilot-core'

/**
 * Derive a stable client-id from the per-device Ed25519 pubkey.
 *
 * Note: passing a SHA-256 digest through `hexEncode` is semantically
 * off-label — `hexEncode` is now typed for `PublicKeyLike` — but
 * runtime-safe because SHA-256 always produces 32 bytes (the PublicKey
 * wrapper's length invariant). If `sha256Bytes` ever returns a different
 * width, this asserts loudly via the PublicKey constructor.
 */
export function clientIdFromPub (clientPubHex: string): string {
  return hexEncode(sha256Bytes(hexDecode(clientPubHex))).slice(0, 32)
}
