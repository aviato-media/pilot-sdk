import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

export function sha256Bytes (input: Uint8Array): Uint8Array {
  return sha256(input)
}

export function hkdfSha256 (
  ikm: Uint8Array,
  info: Uint8Array,
  length = 32,
  salt?: Uint8Array,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length)
}
