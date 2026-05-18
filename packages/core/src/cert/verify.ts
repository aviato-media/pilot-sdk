// Verify + parse a client delegation cert envelope.

import { base64urlDecode, DECODER, hexDecode } from '../crypto/encoding.js'
import type { PublicKeyLike } from '../crypto/keys.js'
import { asPublicKey } from '../crypto/keys.js'
import { ed25519Verify } from '../crypto/signing.js'
import type { ClientDelegationCertEnvelope, ClientDelegationCertPayload } from '../schemas/cert.js'
import { ClientDelegationCertPayloadSchema } from '../schemas/cert.js'

export type CertVerifyResult
  = | { ok: true,
    payload: ClientDelegationCertPayload }
  | { ok: false,
    error: CertVerifyError }

export type CertVerifyError
  = | 'payload_decode_failed'
  | 'payload_shape_invalid'
  | 'signature_invalid'
  | 'expired'
  | 'not_yet_valid'
  | 'user_pubkey_mismatch'

export interface VerifyClientCertOptions {
  /** If provided, the cert's userPubKey must equal this key (`PublicKey`, raw bytes, or hex string). */
  readonly expectedUserPubKey?: PublicKeyLike
  /** Override "now" (unix seconds) for tests. */
  readonly nowSec?: number
  /** Clock-skew tolerance in seconds (default 60). */
  readonly clockSkewSec?: number
}

export function verifyClientCert (
  envelope: ClientDelegationCertEnvelope,
  opts: VerifyClientCertOptions = {},
): CertVerifyResult {
  let payloadBytes: Uint8Array
  let parsedJson: unknown
  try {
    payloadBytes = base64urlDecode(envelope.payload)
    parsedJson = JSON.parse(DECODER.decode(payloadBytes))
  } catch {
    return {
      ok: false,
      error: 'payload_decode_failed',
    }
  }

  const parsed = ClientDelegationCertPayloadSchema.safeParse(parsedJson)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'payload_shape_invalid',
    }
  }
  const payload = parsed.data

  // The cert is master-signed; the signing pubkey is the userPubKey field
  // inside the (just-verified-shape) payload. To prevent attackers from
  // substituting their own userPubKey, callers MUST pass
  // `expectedUserPubKeyHex` whenever they know the user identity in advance
  // (server-side: the user row's stored userPubKey).
  const sig = base64urlDecode(envelope.sig)
  const userPubKey = hexDecode(payload.userPubKey)
  if (!ed25519Verify(payloadBytes, sig, userPubKey)) {
    return {
      ok: false,
      error: 'signature_invalid',
    }
  }

  if (opts.expectedUserPubKey !== undefined && asPublicKey(opts.expectedUserPubKey).toHex() !== payload.userPubKey) {
    return {
      ok: false,
      error: 'user_pubkey_mismatch',
    }
  }

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000)
  const skew = opts.clockSkewSec ?? 60
  if (payload.iat - skew > now) {
    return {
      ok: false,
      error: 'not_yet_valid',
    }
  }
  if (payload.exp + skew < now) {
    return {
      ok: false,
      error: 'expired',
    }
  }

  return {
    ok: true,
    payload,
  }
}
