// Aviato sealedbox: ephemeral X25519 ECDH → HKDF-SHA-256 (info
// "aviato-sealedbox-v1") → AES-GCM-256.

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { asBuffer, base64urlDecode, base64urlEncode, DECODER, ENCODER } from './encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from './keys.js'
import { asPrivateKey, asPublicKey, X25519Keypair } from './keys.js'

const HKDF_INFO_SEALEDBOX = ENCODER.encode('aviato-sealedbox-v1')

export interface SealedBox {
  readonly ct: string
  readonly ephPub: string
  readonly nonce: string
}

export function generateX25519Keypair (): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(privateKey)
  return new X25519Keypair({
    privateKey,
    publicKey,
  })
}

export function x25519PubFromPriv (privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey)
}

async function deriveSealedboxKey (shared: Uint8Array): Promise<CryptoKey> {
  const keyBytes = hkdf(sha256, shared, undefined, HKDF_INFO_SEALEDBOX, 32)
  return crypto.subtle.importKey('raw', asBuffer(keyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

export interface SealedBoxEncryptInput {
  readonly plaintext: Uint8Array
  readonly recipientPub: PublicKeyLike
  readonly aad?: Uint8Array
}

export async function aviatoSealedBoxEncrypt (input: SealedBoxEncryptInput): Promise<SealedBox> {
  const recipientPub = asPublicKey(input.recipientPub).toRaw()
  const ephPriv = x25519.utils.randomSecretKey()
  const ephPub = x25519.getPublicKey(ephPriv)
  const shared = x25519.getSharedSecret(ephPriv, recipientPub)
  const key = await deriveSealedboxKey(shared)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: asBuffer(nonce),
      additionalData: input.aad ? asBuffer(input.aad) : undefined,
    },
    key,
    asBuffer(input.plaintext),
  ))
  return {
    ct: base64urlEncode(ct),
    ephPub: base64urlEncode(ephPub),
    nonce: base64urlEncode(nonce),
  }
}

export interface SealedBoxDecryptInput {
  readonly box: SealedBox
  readonly recipientPriv: PrivateKeyLike
  readonly aad?: Uint8Array
}

export async function aviatoSealedBoxDecrypt (input: SealedBoxDecryptInput): Promise<Uint8Array | null> {
  try {
    const recipientPriv = asPrivateKey(input.recipientPriv).toRaw()
    const ephPub = base64urlDecode(input.box.ephPub)
    const nonce = base64urlDecode(input.box.nonce)
    const ct = base64urlDecode(input.box.ct)
    const shared = x25519.getSharedSecret(recipientPriv, ephPub)
    const key = await deriveSealedboxKey(shared)
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asBuffer(nonce),
        additionalData: input.aad ? asBuffer(input.aad) : undefined,
      },
      key,
      asBuffer(ct),
    )
    return new Uint8Array(plain)
  } catch {
    return null
  }
}

export async function aviatoSealedBoxDecryptJson<T> (input: SealedBoxDecryptInput): Promise<T | null> {
  const bytes = await aviatoSealedBoxDecrypt(input)
  if (!bytes) {
    return null
  }
  try {
    return JSON.parse(DECODER.decode(bytes)) as T
  } catch {
    return null
  }
}

// Handle-based decrypt: the recipient supplies an ECDH callback so the
// SDK never sees private-key bytes (e.g. non-extractable WebCrypto keys).

export interface SealedBoxDecryptHandleInput {
  readonly box: SealedBox
  /** Compute X25519 shared secret with the box's ephPub (32 bytes). */
  readonly deriveShared: (ephPub: Uint8Array) => Promise<Uint8Array>
  readonly aad?: Uint8Array
}

export async function aviatoSealedBoxDecryptHandle (input: SealedBoxDecryptHandleInput): Promise<Uint8Array | null> {
  try {
    const ephPub = base64urlDecode(input.box.ephPub)
    const nonce = base64urlDecode(input.box.nonce)
    const ct = base64urlDecode(input.box.ct)
    const shared = await input.deriveShared(ephPub)
    if (shared.length !== 32) {
      return null
    }
    const key = await deriveSealedboxKey(shared)
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asBuffer(nonce),
        additionalData: input.aad ? asBuffer(input.aad) : undefined,
      },
      key,
      asBuffer(ct),
    )
    return new Uint8Array(plain)
  } catch {
    return null
  }
}

export async function aviatoSealedBoxDecryptJsonHandle<T> (input: SealedBoxDecryptHandleInput): Promise<T | null> {
  const bytes = await aviatoSealedBoxDecryptHandle(input)
  if (!bytes) {
    return null
  }
  try {
    return JSON.parse(DECODER.decode(bytes)) as T
  } catch {
    return null
  }
}
