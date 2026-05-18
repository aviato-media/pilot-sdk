// Client-pair sealed K bundle.
//
// User-browser seals K-by-server (one entry per linked server they've
// ticked for this app) to the requesting client app's X25519 pub. The
// client decrypts with its X25519 priv and writes K into local storage.

import { jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import type { SealedBox } from '../crypto/sealedbox.js'
import {
  aviatoSealedBoxDecryptJson,
  aviatoSealedBoxDecryptJsonHandle,
  aviatoSealedBoxEncrypt,
} from '../crypto/sealedbox.js'
import type { ClientKeyBundleContents } from '../schemas/conn-info.js'
import { ClientKeyBundleContentsSchema } from '../schemas/conn-info.js'

export interface SealClientBundleInput {
  readonly bundle: ClientKeyBundleContents
  readonly clientEncPubKey: PublicKeyLike
}

export async function sealClientBundle (input: SealClientBundleInput): Promise<SealedBox> {
  return aviatoSealedBoxEncrypt({
    plaintext: jcs(input.bundle),
    recipientPub: input.clientEncPubKey,
  })
}

export type OpenClientBundleResult
  = | { ok: true,
    bundle: ClientKeyBundleContents }
  | { ok: false,
    error: 'decrypt_failed' | 'shape_invalid' }

export interface OpenClientBundleInput {
  readonly box: SealedBox
  readonly clientEncPrivKey: PrivateKeyLike
}

export async function openClientBundle (input: OpenClientBundleInput): Promise<OpenClientBundleResult> {
  const decoded = await aviatoSealedBoxDecryptJson<unknown>({
    box: input.box,
    recipientPriv: input.clientEncPrivKey,
  })
  return finalizeOpenedBundle(decoded)
}

// ── Handle-based open (non-extractable-key path) ──────────────────────
//
// Same contract as `openClientBundle`, but the caller supplies a
// `deriveShared(ephPub) → Promise<sharedBytes>` callback instead of the
// X25519 private key. Use this when the client app's encryption key is
// held as a non-extractable WebCrypto CryptoKey or hardware-backed token.

export interface OpenClientBundleHandleInput {
  readonly box: SealedBox
  readonly deriveShared: (ephPub: Uint8Array) => Promise<Uint8Array>
}

export async function openClientBundleHandle (input: OpenClientBundleHandleInput): Promise<OpenClientBundleResult> {
  const decoded = await aviatoSealedBoxDecryptJsonHandle<unknown>({
    box: input.box,
    deriveShared: input.deriveShared,
  })
  return finalizeOpenedBundle(decoded)
}

function finalizeOpenedBundle (decoded: unknown): OpenClientBundleResult {
  if (decoded === null) {
    return {
      ok: false,
      error: 'decrypt_failed',
    }
  }
  const parsed = ClientKeyBundleContentsSchema.safeParse(decoded)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'shape_invalid',
    }
  }
  return {
    ok: true,
    bundle: parsed.data,
  }
}
