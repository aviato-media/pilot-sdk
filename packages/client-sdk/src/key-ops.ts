// Closure-shaped device-key handle. Storage backends that implement
// `generateClientKeys`/`loadClientKeys` keep private keys opaque
// (non-extractable CryptoKeys, HSMs, keychain handles) and expose only
// these callbacks.

import type { PublicKey, PublicKeyLike } from '@aviato-media/pilot-core'

export interface KeyOps {
  /** Ed25519 device signing public key (`C_n_pub`). Safe to expose. */
  readonly clientPubKey: PublicKey
  /** X25519 device encryption public key. Safe to expose. */
  readonly clientEncPubKey: PublicKey
  /** Sign `message` with the device's Ed25519 private key. */
  signEd25519 (message: Uint8Array): Promise<Uint8Array>
  /** Compute X25519 shared secret with `peerPub` (`PublicKey`, raw bytes, or hex). Returns 32 bytes. */
  deriveX25519Shared (peerPub: PublicKeyLike): Promise<Uint8Array>
}
