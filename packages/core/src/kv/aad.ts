// KV blob AEAD AAD construction — binds a ciphertext to the exact KV key
// string it is stored under, so swapping a blob between keys under the
// same K fails decrypt. The user-scoped K already binds the ciphertext
// to a single user.

import { concatBytes, ENCODER } from '../crypto/encoding.js'

const AAD_PREFIX = ENCODER.encode('aviato-kv-blob-v1')

export function buildKvBlobAad (key: string): Uint8Array {
  return concatBytes(AAD_PREFIX, ENCODER.encode(key))
}
