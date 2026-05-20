import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { bytesToHex as nobleBytesToHex } from '@noble/hashes/utils.js'

import { base64urlDecode, base64urlEncode, hexDecode } from './encoding.js'

const HEX_64 = /^[0-9a-f]{64}$/

export abstract class Key {
  protected readonly bytes: Uint8Array

  protected constructor (bytes: Uint8Array) {
    this.bytes = new Uint8Array(bytes)
  }

  toRaw (): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  toBinary (): Uint8Array {
    return this.toRaw()
  }

  toBase64Url (): string {
    return base64urlEncode(this.bytes)
  }

  toHex (): string {
    return nobleBytesToHex(this.bytes)
  }

  protected equalsBytes (other: Uint8Array): boolean {
    if (other.length !== this.bytes.length) {
      return false
    }
    for (let i = 0; i < this.bytes.length; i++) {
      if (other[i] !== this.bytes[i]) {
        return false
      }
    }
    return true
  }

  abstract toString (): string
  abstract toJSON (): unknown
}

/** A 32-byte public key (Ed25519 or X25519). */
export class PublicKey extends Key {
  constructor (input: PublicKeyLike) {
    super(PublicKey.#parse(input))
  }

  static #parse (input: PublicKeyLike): Uint8Array {
    if (input instanceof PublicKey) {
      return input.bytes
    }
    if (input instanceof Uint8Array) {
      if (input.length !== 32) {
        throw new Error(`PublicKey: expected 32 bytes, got ${input.length}`)
      }
      return input
    }
    if (typeof input === 'string') {
      if (!HEX_64.test(input)) {
        throw new Error(
          `PublicKey: expected 64 lowercase hex chars (32-byte pubkey), got ${input.length} chars`,
        )
      }
      return hexDecode(input)
    }
    throw new Error(
      `PublicKey: expected PublicKey | Uint8Array | hex string, got ${typeof input === 'object' ? Object.prototype.toString.call(input) : typeof input}`,
    )
  }

  override toString (): string {
    return this.toHex()
  }

  override toJSON (): string {
    return this.toHex()
  }

  equals (other: PublicKeyLike): boolean {
    try {
      const normalized = other instanceof PublicKey ? other : new PublicKey(other)
      return this.equalsBytes(normalized.bytes)
    } catch {
      return false
    }
  }

  static fromHex (hex: string): PublicKey {
    return new PublicKey(hex)
  }

  static fromBytes (bytes: Uint8Array): PublicKey {
    return new PublicKey(bytes)
  }

  static fromBase64Url (b64u: string): PublicKey {
    const bytes = base64urlDecode(b64u)
    if (bytes.length !== 32) {
      throw new Error(`PublicKey.fromBase64Url: expected 32 bytes, got ${bytes.length}`)
    }
    return new PublicKey(bytes)
  }
}

/**
 * A 32-byte private key. `toString()` is redacted; `toJSON()` throws.
 * Extract bytes explicitly via `toRaw()` / `toBase64Url()`.
 */
export class PrivateKey extends Key {
  constructor (input: PrivateKeyLike) {
    super(PrivateKey.#parse(input))
  }

  static #parse (input: PrivateKeyLike): Uint8Array {
    if (input instanceof PrivateKey) {
      return input.bytes
    }
    if (input instanceof Uint8Array) {
      if (input.length !== 32) {
        throw new Error(`PrivateKey: expected 32 bytes, got ${input.length}`)
      }
      return input
    }
    if (typeof input === 'string') {
      if (!HEX_64.test(input)) {
        throw new Error(
          `PrivateKey: expected 64 lowercase hex chars (32-byte pubkey), got ${input.length} chars`,
        )
      }
      return hexDecode(input)
    }
    throw new Error(
      `PrivateKey: expected PrivateKey | Uint8Array (32 bytes), got ${typeof input === 'object' ? Object.prototype.toString.call(input) : typeof input}`,
    )
  }

  override toString (): string {
    return '[PrivateKey]'
  }

  override toJSON (): never {
    throw new Error(
      'PrivateKey: cannot be serialized via JSON.stringify. '
      + 'Call toBase64Url() explicitly if you intend to persist the secret material.',
    )
  }

  equals (other: PrivateKeyLike): boolean {
    try {
      const normalized = other instanceof PrivateKey ? other : new PrivateKey(other)
      return this.equalsBytes(normalized.bytes)
    } catch {
      return false
    }
  }

  static fromHex (hex: string): PrivateKey {
    return new PrivateKey(hex)
  }

  static fromBytes (bytes: Uint8Array): PrivateKey {
    return new PrivateKey(bytes)
  }

  static fromBase64Url (b64u: string): PrivateKey {
    const bytes = base64urlDecode(b64u)
    if (bytes.length !== 32) {
      throw new Error(`PrivateKey.fromBase64Url: expected 32 bytes, got ${bytes.length}`)
    }
    return new PrivateKey(bytes)
  }
}

export class PublicPrivateKey {
  readonly publicKey: PublicKey
  readonly privateKey: PrivateKey

  constructor (opts: {
    publicKey: PublicKeyLike,
    privateKey: PrivateKeyLike,
  }) {
    this.publicKey = new PublicKey(opts.publicKey)
    this.privateKey = new PrivateKey(opts.privateKey)
  }

  static fromBytes (publicKey: Uint8Array, privateKey: Uint8Array): PublicPrivateKey {
    return new PublicPrivateKey({
      privateKey: new PrivateKey(privateKey),
      publicKey: new PublicKey(publicKey),
    })
  }

  static fromPrivate (privateKey: PrivateKeyLike, type: 'Ed25519' | 'X25519'): PublicPrivateKey {
    const privKey = asPrivateKey(privateKey)
    return new PublicPrivateKey({
      privateKey: privKey,
      publicKey: type === 'Ed25519' ? ed25519.getPublicKey(privKey.toRaw()) : x25519.getPublicKey(privKey.toRaw()),
    })
  }

  toPersistableUnsafe (): { publicKeyHex: string,
    privateKeyBase64Url: string } {
    return {
      privateKeyBase64Url: this.privateKey.toBase64Url(),
      publicKeyHex: this.publicKey.toHex(),
    }
  }
}

export class Ed25519Keypair extends PublicPrivateKey {}

export class X25519Keypair extends PublicPrivateKey {}

export type PublicKeyLike = PublicKey | Uint8Array | string

export type PrivateKeyLike = PrivateKey | Uint8Array | string

export type PublicPrivateKeyLike = PublicPrivateKey | {
  publicKey: PublicKeyLike
  privateKey: PrivateKeyLike
} | PrivateKeyLike

export function asPublicKey (input: PublicKeyLike): PublicKey {
  return input instanceof PublicKey ? input : new PublicKey(input)
}

export function asPrivateKey (input: PrivateKeyLike): PrivateKey {
  return input instanceof PrivateKey ? input : new PrivateKey(input)
}

export function asPublicPrivateKey (input: PublicPrivateKeyLike, type: 'Ed25519' | 'X25519'): PublicPrivateKey {
  if (input instanceof PublicPrivateKey) {
    return input
  } else if (input instanceof PrivateKey || input instanceof Uint8Array || typeof input === 'string') {
    return PublicPrivateKey.fromPrivate(input, type)
  } else {
    return new PublicPrivateKey({
      publicKey: asPublicKey(input.publicKey),
      privateKey: asPrivateKey(input.privateKey),
    })
  }
}
