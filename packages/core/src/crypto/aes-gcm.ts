// Raw AES-GCM-256 — used for:
//  - SERVER_CONNINFO encrypt/decrypt under the per-server K
//  - Vault wrap/body encrypt (PRF-derived wrap key, random VK)
//
// 12-byte nonce, 16-byte auth tag (WebCrypto default).

import { asBuffer } from './encoding.js'

export interface AesGcmCiphertext {
  readonly nonce: Uint8Array
  readonly ct: Uint8Array
}

async function importKey (key: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (key.length !== 32) {
    throw new Error(`AES-GCM-256 key must be 32 bytes, got ${key.length}`)
  }
  return crypto.subtle.importKey('raw', asBuffer(key), { name: 'AES-GCM' }, false, usages)
}

export async function aesGcmEncrypt (
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
  nonce?: Uint8Array,
): Promise<AesGcmCiphertext> {
  const iv = nonce ?? crypto.getRandomValues(new Uint8Array(12))
  if (iv.length !== 12) {
    throw new Error(`AES-GCM nonce must be 12 bytes, got ${iv.length}`)
  }
  const cryptoKey = await importKey(key, ['encrypt'])
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: asBuffer(iv),
      additionalData: aad ? asBuffer(aad) : undefined,
    },
    cryptoKey,
    asBuffer(plaintext),
  ))
  return {
    ct,
    nonce: iv,
  }
}

export async function aesGcmDecrypt (
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  if (key.length !== 32 || nonce.length !== 12) {
    return null
  }
  try {
    const cryptoKey = await importKey(key, ['decrypt'])
    return new Uint8Array(await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asBuffer(nonce),
        additionalData: aad ? asBuffer(aad) : undefined,
      },
      cryptoKey,
      asBuffer(ciphertext),
    ))
  } catch {
    return null
  }
}

export function randomAesKey (): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}
