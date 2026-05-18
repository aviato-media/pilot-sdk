// WebAuthn PRF extension helpers. PRF bytes feed straight into HKDF to
// derive the per-passkey vault-wrapping AES-GCM key — they never leave
// this module's call sites.

import { asBuffer, ENCODER } from '@aviato-media/pilot-core'

const HKDF_INFO_VAULT_WRAP = ENCODER.encode('aviato-vault-wrap/v1')
const HKDF_SALT_VAULT_WRAP = new Uint8Array(32) // intentionally empty; per-passkey randomness comes from prfSalt

/** Generate a fresh per-passkey PRF salt. Store alongside the credentialId. */
export function generatePrfSalt (): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

/** Build the PRF eval inputs to send into navigator.credentials.get/create. */
export interface PrfEvalInputs {
  readonly first: Uint8Array
}

export function buildPrfInputs (prfSalt: Uint8Array): PrfEvalInputs {
  return { first: prfSalt }
}

/**
 * Extract the PRF output (`results.first`) from a WebAuthn assertion result.
 * Returns null if the authenticator didn't produce one (no PRF support).
 */
export function extractPrfOutput (
  extensionResults: { prf?: { results?: { first?: BufferSource } } } | null | undefined,
): Uint8Array | null {
  const raw = extensionResults?.prf?.results?.first
  if (raw === undefined) {
    return null
  }
  if (raw instanceof Uint8Array) {
    return raw
  }
  if (raw instanceof ArrayBuffer) {
    return new Uint8Array(raw)
  }
  return new Uint8Array((raw as ArrayBufferView).buffer)
}

/** Derive a non-extractable AES-GCM-256 wrapping key from PRF bytes via HKDF-SHA-256. */
export async function derivePrfWrappingKey (prfBytes: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    asBuffer(prfBytes),
    'HKDF',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: asBuffer(HKDF_SALT_VAULT_WRAP),
      info: asBuffer(HKDF_INFO_VAULT_WRAP),
    },
    base,
    {
      length: 256,
      name: 'AES-GCM',
    },
    /* extractable */ false,
    ['encrypt', 'decrypt'],
  )
}
