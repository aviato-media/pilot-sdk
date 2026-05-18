// Build a ServerConnInfoPublish wire body (server side):
//   1. JCS the payload.
//   2. AES-GCM-256 under K with AAD = aviato-server-conninfo-v1 ‖ pub ‖ ver.
//   3. Sign the 4-key canonical {ct, nonce, serverPubKey, version} object.
//
// Open the AEAD on the client side with the same K + same AAD.

import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aes-gcm.js'
import { base64urlDecode, base64urlEncode, DECODER, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import { asPrivateKey, asPublicKey } from '../crypto/keys.js'
import { ed25519Sign } from '../crypto/signing.js'
import type { ServerConnInfoPayload, ServerConnInfoPublish, ServerConnInfoRecord } from '../schemas/conn-info.js'
import { ServerConnInfoPayloadSchema } from '../schemas/conn-info.js'
import { buildConnInfoAad } from './aad.js'
import { buildConnInfoCanonical } from './publish-sig.js'

export interface SealConnInfoInput {
  readonly payload: ServerConnInfoPayload
  /** 32-byte per-server K. */
  readonly connInfoKey: Uint8Array
  /** Server Ed25519 pubkey. */
  readonly serverPubKey: PublicKeyLike
  /** Server Ed25519 private key. */
  readonly serverPrivKey: PrivateKeyLike
  /** Strict-monotonic version (MUST equal payload.rotationCounter). */
  readonly version: number
}

export async function sealServerConnInfo (input: SealConnInfoInput): Promise<ServerConnInfoPublish> {
  if (input.payload.rotationCounter !== input.version) {
    throw new Error('rotationCounter MUST equal wire version')
  }
  const serverPubKeyHex = asPublicKey(input.serverPubKey).toHex()
  const plaintext = jcs(input.payload)
  const aad = buildConnInfoAad(serverPubKeyHex, input.version)
  const { ct, nonce } = await aesGcmEncrypt(input.connInfoKey, plaintext, aad)
  const ctB64 = base64urlEncode(ct)
  const nonceB64 = base64urlEncode(nonce)
  const canonical = buildConnInfoCanonical({
    ct: ctB64,
    nonce: nonceB64,
    serverPubKey: serverPubKeyHex,
    version: input.version,
  })
  const sig = ed25519Sign(canonical, asPrivateKey(input.serverPrivKey).toRaw())
  return {
    ct: ctB64,
    nonce: nonceB64,
    serverPubKey: serverPubKeyHex,
    sig: base64urlEncode(sig),
    version: input.version,
  }
}

export type OpenConnInfoResult
  = | { ok: true,
    payload: ServerConnInfoPayload }
  | { ok: false,
    error: OpenConnInfoError }

export type OpenConnInfoError
  = | 'aead_decrypt_failed'
  | 'payload_shape_invalid'
  | 'rotation_counter_mismatch'

export interface OpenConnInfoInput {
  readonly record: ServerConnInfoRecord
  readonly connInfoKey: Uint8Array
}

/** Open the AEAD only. Signature verification is a separate step in `verify.ts`. */
export async function openServerConnInfo (input: OpenConnInfoInput): Promise<OpenConnInfoResult> {
  const aad = buildConnInfoAad(input.record.serverPubKey, input.record.version)
  const plain = await aesGcmDecrypt(
    input.connInfoKey,
    base64urlDecode(input.record.nonce),
    base64urlDecode(input.record.ct),
    aad,
  )
  if (!plain) {
    return {
      ok: false,
      error: 'aead_decrypt_failed',
    }
  }
  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(DECODER.decode(plain))
  } catch {
    return {
      ok: false,
      error: 'payload_shape_invalid',
    }
  }
  const parsed = ServerConnInfoPayloadSchema.safeParse(parsedJson)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'payload_shape_invalid',
    }
  }
  if (parsed.data.rotationCounter !== input.record.version) {
    return {
      ok: false,
      error: 'rotation_counter_mismatch',
    }
  }
  return {
    ok: true,
    payload: parsed.data,
  }
}
