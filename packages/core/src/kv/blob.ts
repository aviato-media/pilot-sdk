// Encode / decode a KV blob:
//   wireBytes = nonce(12) ‖ aesGcmCiphertext(plaintext, K, AAD=kv-aad).
// The wire layer base64urls this concatenated buffer. The server stores
// the wire bytes verbatim and computes sha256 over them for checksums.

import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aes-gcm.js'
import { base64urlDecode, base64urlEncode, concatBytes } from '../crypto/encoding.js'
import { sha256Bytes } from '../crypto/hashing.js'
import { KV_MAX_BLOB_BYTES, KV_MAX_KEY_LENGTH } from '../schemas/kv.js'
import { buildKvBlobAad } from './aad.js'

const NONCE_LENGTH = 12

export interface SealKvBlobInput {
  /** KV key string this blob will be stored under. Bound into the AAD. */
  readonly key: string
  /** Plaintext bytes the caller wants stored. */
  readonly value: Uint8Array
  /** 32-byte per-user K. */
  readonly kvKey: Uint8Array
}

export interface SealedKvBlob {
  /** base64url(nonce ‖ ct). */
  readonly ciphertext: string
  /** base64url(sha256(nonce ‖ ct)). */
  readonly checksum: string
}

export async function sealKvBlob (input: SealKvBlobInput): Promise<SealedKvBlob> {
  if (input.key.length === 0 || input.key.length > KV_MAX_KEY_LENGTH) {
    throw new Error(`KV key length ${input.key.length} out of bounds (1..${KV_MAX_KEY_LENGTH})`)
  }
  const aad = buildKvBlobAad(input.key)
  const { ct, nonce } = await aesGcmEncrypt(input.kvKey, input.value, aad)
  const wire = concatBytes(nonce, ct)
  if (wire.length > KV_MAX_BLOB_BYTES) {
    throw new Error(`KV blob ${wire.length} bytes exceeds max ${KV_MAX_BLOB_BYTES}`)
  }
  return {
    checksum: base64urlEncode(sha256Bytes(wire)),
    ciphertext: base64urlEncode(wire),
  }
}

export type OpenKvBlobResult
  = | { ok: true,
    value: Uint8Array }
  | { ok: false,
    error: OpenKvBlobError }

export type OpenKvBlobError
  = | 'aead_decrypt_failed'
  | 'malformed_wire'

export interface OpenKvBlobInput {
  /** KV key string this blob is stored under. Must match what `sealKvBlob` used. */
  readonly key: string
  /** base64url(nonce ‖ ct) as returned by Tower. */
  readonly ciphertext: string
  /** 32-byte per-user K. */
  readonly kvKey: Uint8Array
}

export async function openKvBlob (input: OpenKvBlobInput): Promise<OpenKvBlobResult> {
  let wire: Uint8Array
  try {
    wire = base64urlDecode(input.ciphertext)
  } catch {
    return {
      error: 'malformed_wire',
      ok: false,
    }
  }
  if (wire.length <= NONCE_LENGTH) {
    return {
      error: 'malformed_wire',
      ok: false,
    }
  }
  const nonce = wire.subarray(0, NONCE_LENGTH)
  const ct = wire.subarray(NONCE_LENGTH)
  const aad = buildKvBlobAad(input.key)
  const plain = await aesGcmDecrypt(input.kvKey, nonce, ct, aad)
  if (plain === null) {
    return {
      error: 'aead_decrypt_failed',
      ok: false,
    }
  }
  return {
    ok: true,
    value: plain,
  }
}

/** SHA-256 over the wire ciphertext bytes (nonce ‖ ct), base64url-encoded. */
export function checksumKvBlob (ciphertextB64u: string): string {
  return base64urlEncode(sha256Bytes(base64urlDecode(ciphertextB64u)))
}
