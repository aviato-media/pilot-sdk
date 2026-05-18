import { ed25519 } from '@noble/curves/ed25519.js'

import { Ed25519Keypair } from './keys.js'

export function ed25519Sign (message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey)
}

export function ed25519Verify (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

export function generateEd25519Keypair (): Ed25519Keypair {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(privateKey)
  return new Ed25519Keypair({
    privateKey,
    publicKey,
  })
}

export function ed25519PubFromPriv (privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey)
}
