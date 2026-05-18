// Vault encrypt/decrypt + per-passkey VK wrap/unwrap.
//
// Tower stores VaultBlob opaquely. The wraps[] array carries one entry per
// enrolled passkey, each wrapping the same VK via a PRF-derived AES-GCM
// key. The vault body (the user's keys + servers list) is encrypted under
// VK once.

import type { VaultBlob, VaultPayload, VaultWrap } from '@aviato-media/pilot-core'
import {
  asBuffer,
  base64urlDecode,
  base64urlEncode,
  DECODER,
  jcs,
  VaultPayloadSchema,
} from '@aviato-media/pilot-core'

// ── Low-level helpers (CryptoKey-based) ────────────────────────────────

async function aesGcmEncryptKey (key: CryptoKey, plaintext: Uint8Array): Promise<{ iv: Uint8Array,
  ct: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {
      iv: asBuffer(iv),
      name: 'AES-GCM',
    },
    key,
    asBuffer(plaintext),
  ))
  return {
    ct,
    iv,
  }
}

async function aesGcmDecryptKey (key: CryptoKey, iv: Uint8Array, ct: Uint8Array): Promise<Uint8Array | null> {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      {
        iv: asBuffer(iv),
        name: 'AES-GCM',
      },
      key,
      asBuffer(ct),
    ))
  } catch {
    return null
  }
}

// ── VK lifecycle ───────────────────────────────────────────────────────

export async function generateVaultKey (): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      length: 256,
      name: 'AES-GCM',
    },
    /* extractable */ true,
    ['encrypt', 'decrypt'],
  )
}

async function exportVaultKey (vk: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', vk))
}

async function importVaultKey (raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', asBuffer(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
}

// ── Wrap / unwrap VK under a PRF-derived wrapping key ─────────────────

export async function wrapVaultKey (vk: CryptoKey, prfWrappingKey: CryptoKey): Promise<{ wrappedKey: Uint8Array,
  wrapIv: Uint8Array }> {
  const raw = await exportVaultKey(vk)
  const { ct, iv } = await aesGcmEncryptKey(prfWrappingKey, raw)
  return {
    wrapIv: iv,
    wrappedKey: ct,
  }
}

export async function unwrapVaultKey (
  wrap: { wrappedKey: Uint8Array,
    wrapIv: Uint8Array },
  prfWrappingKey: CryptoKey,
): Promise<CryptoKey | null> {
  const raw = await aesGcmDecryptKey(prfWrappingKey, wrap.wrapIv, wrap.wrappedKey)
  if (raw === null) {
    return null
  }
  return importVaultKey(raw)
}

// ── Vault body encrypt/decrypt under VK ────────────────────────────────

export async function encryptVault (vk: CryptoKey, payload: VaultPayload): Promise<{ ciphertext: Uint8Array,
  iv: Uint8Array }> {
  const plaintext = jcs(payload)
  const { ct, iv } = await aesGcmEncryptKey(vk, plaintext)
  return {
    ciphertext: ct,
    iv,
  }
}

export async function decryptVault (vk: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array): Promise<VaultPayload | null> {
  const raw = await aesGcmDecryptKey(vk, iv, ciphertext)
  if (raw === null) {
    return null
  }
  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(DECODER.decode(raw))
  } catch {
    return null
  }
  const parsed = VaultPayloadSchema.safeParse(parsedJson)
  return parsed.success ? parsed.data : null
}

// ── High-level vault builders / openers ────────────────────────────────

export interface CreateVaultInput {
  readonly payload: VaultPayload
  /** Initial passkey's credentialId (base64url). */
  readonly credentialId: string
  /** Per-passkey PRF salt (base64url). */
  readonly prfSalt: string
  readonly prfWrappingKey: CryptoKey
}

export async function createVault (input: CreateVaultInput): Promise<{ blob: VaultBlob,
  vk: CryptoKey }> {
  const vk = await generateVaultKey()
  const { ciphertext, iv } = await encryptVault(vk, input.payload)
  const { wrappedKey, wrapIv } = await wrapVaultKey(vk, input.prfWrappingKey)
  return {
    blob: {
      ciphertext: base64urlEncode(ciphertext),
      createdAt: Date.now(),
      iv: base64urlEncode(iv),
      v: 1,
      wraps: [{
        credentialId: input.credentialId,
        prfSalt: input.prfSalt,
        wrapIv: base64urlEncode(wrapIv),
        wrappedKey: base64urlEncode(wrappedKey),
      }],
    },
    vk,
  }
}

export interface OpenVaultInput {
  readonly blob: VaultBlob
  /** Which wrap entry (by credentialId) to use. */
  readonly credentialId: string
  readonly prfWrappingKey: CryptoKey
}

export type OpenVaultResult
  = | { ok: true,
    payload: VaultPayload,
    vk: CryptoKey }
  | { ok: false,
    error: 'wrap_not_found' | 'unwrap_failed' | 'payload_decrypt_failed' }

export async function openVault (input: OpenVaultInput): Promise<OpenVaultResult> {
  const wrap = input.blob.wraps.find((w) => w.credentialId === input.credentialId)
  if (wrap === undefined) {
    return {
      error: 'wrap_not_found',
      ok: false,
    }
  }
  const vk = await unwrapVaultKey(
    {
      wrapIv: base64urlDecode(wrap.wrapIv),
      wrappedKey: base64urlDecode(wrap.wrappedKey),
    },
    input.prfWrappingKey,
  )
  if (vk === null) {
    return {
      error: 'unwrap_failed',
      ok: false,
    }
  }
  const payload = await decryptVault(vk, base64urlDecode(input.blob.ciphertext), base64urlDecode(input.blob.iv))
  if (payload === null) {
    return {
      error: 'payload_decrypt_failed',
      ok: false,
    }
  }
  return {
    ok: true,
    payload,
    vk,
  }
}

// ── Mutators: add/remove passkey wraps, replace payload ────────────────

export interface AddPasskeyToVaultInput {
  readonly blob: VaultBlob
  readonly vk: CryptoKey
  readonly credentialId: string
  readonly prfSalt: string
  readonly newPrfWrappingKey: CryptoKey
}

export async function addPasskeyToVault (input: AddPasskeyToVaultInput): Promise<VaultBlob> {
  const { wrappedKey, wrapIv } = await wrapVaultKey(input.vk, input.newPrfWrappingKey)
  const newWrap: VaultWrap = {
    credentialId: input.credentialId,
    prfSalt: input.prfSalt,
    wrapIv: base64urlEncode(wrapIv),
    wrappedKey: base64urlEncode(wrappedKey),
  }
  return {
    ...input.blob,
    updatedAt: Date.now(),
    wraps: [...input.blob.wraps.filter((w) => w.credentialId !== input.credentialId), newWrap],
  }
}

export function removePasskeyFromVault (blob: VaultBlob, credentialId: string): VaultBlob {
  return {
    ...blob,
    updatedAt: Date.now(),
    wraps: blob.wraps.filter((w) => w.credentialId !== credentialId),
  }
}

export async function replaceVaultPayload (input: { blob: VaultBlob,
  vk: CryptoKey,
  payload: VaultPayload }): Promise<VaultBlob> {
  const { ciphertext, iv } = await encryptVault(input.vk, input.payload)
  return {
    ...input.blob,
    ciphertext: base64urlEncode(ciphertext),
    iv: base64urlEncode(iv),
    updatedAt: Date.now(),
  }
}

/** Helper: encode bytes as base64url (matches the wire shapes the schemas expect). */
export function bytesToB64u (b: Uint8Array): string {
  return base64urlEncode(b)
}
