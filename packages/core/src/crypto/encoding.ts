import { concatBytes as nobleConcatBytes, hexToBytes as nobleHexToBytes } from '@noble/hashes/utils.js'
import { base64urlnopad } from '@scure/base'
import canonicalize from 'canonicalize'

import type { PublicKeyLike } from './keys.js'
import { PublicKey } from './keys.js'

export const ENCODER = new TextEncoder()
export const DECODER = new TextDecoder()

/** Lowercase 64-char hex form of a 32-byte value. */
export function hexEncode (input: PublicKeyLike): string {
  return new PublicKey(input).toHex()
}

export function hexDecode (hex: string): Uint8Array {
  return nobleHexToBytes(hex)
}

export function base64urlEncode (bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes)
}

export function base64urlDecode (s: string): Uint8Array {
  return base64urlnopad.decode(s)
}

export function jcs (value: unknown): Uint8Array {
  return ENCODER.encode(jcsString(value))
}

export function jcsString (value: unknown): string {
  const s = canonicalize(value)
  if (s === undefined) {
    throw new Error('JCS: value cannot be canonicalized (undefined / function / symbol)')
  }
  return s
}

export function concatBytes (...parts: Uint8Array[]): Uint8Array {
  return nobleConcatBytes(...parts)
}

/** 8-byte big-endian unsigned. */
export function u64BE (n: number): Uint8Array {
  const out = new Uint8Array(8)
  let v = BigInt(n)
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

// WebCrypto's ArrayBufferView<ArrayBuffer> bound rejects Uint8Array
// (its `.buffer` is ArrayBufferLike) — slice into a fresh ArrayBuffer.
export function asBuffer (u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer
}

export function pubkeyFromHex (hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(
      `pubkeyFromHex: expected 64 lowercase hex chars (32-byte pubkey), got "${hex.slice(0, 32)}…" (${hex.length} chars)`,
    )
  }
  return hexDecode(hex)
}

export function pubkeyFromBase64Url (b64u: string): Uint8Array {
  const bytes = base64urlDecode(b64u)
  if (bytes.length !== 32) {
    throw new Error(
      `pubkeyFromBase64Url: expected 32 bytes, got ${bytes.length} bytes`,
    )
  }
  return bytes
}
