// Revocation envelopes — M-signed; user-initiated.
//
// `scope=identity` revokes everything tied to userPubKey.
// `scope=server-link` revokes the user↔server link (serverPubKey required).
// `scope=client`      revokes one clientId.

import { base64urlDecode, base64urlEncode, DECODER, hexDecode, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import { asPrivateKey, asPublicKey } from '../crypto/keys.js'
import { ed25519Sign, ed25519Verify } from '../crypto/signing.js'
import type { RevocationEnvelopePayload, RevocationEnvelopeWire } from '../schemas/revocation.js'
import { RevocationEnvelopePayloadSchema } from '../schemas/revocation.js'

export interface BuildRevocationInput {
  readonly payload: RevocationEnvelopePayload
  readonly masterPrivKey: PrivateKeyLike
}

export function buildRevocation (input: BuildRevocationInput): RevocationEnvelopeWire {
  const canonical = jcs(input.payload)
  return {
    payload: base64urlEncode(canonical),
    sig: base64urlEncode(ed25519Sign(canonical, asPrivateKey(input.masterPrivKey).toRaw())),
  }
}

export type VerifyRevocationResult
  = | { ok: true,
    payload: RevocationEnvelopePayload }
  | { ok: false,
    error: VerifyRevocationError }

/**
 * - `decode_failed`            — payload bytes are not valid JSON.
 * - `shape_invalid`            — JSON parses but does not match the schema.
 * - `expected_user_mismatch`   — `opts.expectedUserPubKey` was supplied and
 *                                differs from the envelope's userPubKey.
 *                                The signature may still be valid for the
 *                                user named in the envelope; we just don't
 *                                trust *this* envelope to revoke them.
 * - `signature_invalid`        — Ed25519 verification failed.
 */
export type VerifyRevocationError
  = | 'decode_failed'
  | 'shape_invalid'
  | 'expected_user_mismatch'
  | 'signature_invalid'

export interface VerifyRevocationOptions {
  /** If set, the envelope must revoke this userPubKey (`PublicKey`, raw bytes, or hex string). */
  readonly expectedUserPubKey?: PublicKeyLike
}

export function verifyRevocation (
  wire: RevocationEnvelopeWire,
  opts: VerifyRevocationOptions = {},
): VerifyRevocationResult {
  let canonical: Uint8Array
  let parsedJson: unknown
  try {
    canonical = base64urlDecode(wire.payload)
    parsedJson = JSON.parse(DECODER.decode(canonical))
  } catch {
    return {
      ok: false,
      error: 'decode_failed',
    }
  }
  const parsed = RevocationEnvelopePayloadSchema.safeParse(parsedJson)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'shape_invalid',
    }
  }
  if (opts.expectedUserPubKey !== undefined && parsed.data.userPubKey !== asPublicKey(opts.expectedUserPubKey).toHex()) {
    return {
      ok: false,
      error: 'expected_user_mismatch',
    }
  }
  if (!ed25519Verify(canonical, base64urlDecode(wire.sig), hexDecode(parsed.data.userPubKey))) {
    return {
      ok: false,
      error: 'signature_invalid',
    }
  }
  return {
    ok: true,
    payload: parsed.data,
  }
}
