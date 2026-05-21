// Build + verify M-signed pairing assertions (server-link, server-sign-in,
// operator-link).
//
// Wire shape: { signedAssertionBytes: base64url(JCS(payload)), assertionSignature: base64url(Ed25519(M, JCS)) }.
// Recipient (media server) verifies sig against `payload.userPubKey` lifted
// out of the (just-shape-validated) bytes.

import { base64urlDecode, base64urlEncode, DECODER, hexDecode, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import { asPrivateKey, asPublicKey } from '../crypto/keys.js'
import { ed25519Sign, ed25519Verify } from '../crypto/signing.js'
import type {
  MasterSignedAssertionEnvelope,
  OperatorLinkAssertionPayload,
  ServerLinkAssertionPayload,
  ServerSignInAssertionPayload,
} from '../schemas/assertions.js'
import {
  OperatorLinkAssertionPayloadSchema,
  ServerLinkAssertionPayloadSchema,
  ServerSignInAssertionPayloadSchema,
} from '../schemas/assertions.js'
import type { PairKind } from '../schemas/pairing.js'

export type PairingAssertionPayload
  = | ServerLinkAssertionPayload
    | ServerSignInAssertionPayload
    | OperatorLinkAssertionPayload

export interface BuildAssertionInput {
  readonly payload: PairingAssertionPayload
  readonly masterPrivKey: PrivateKeyLike
}

export function buildPairingAssertion (input: BuildAssertionInput): MasterSignedAssertionEnvelope {
  const canonical = jcs(input.payload)
  const sig = ed25519Sign(canonical, asPrivateKey(input.masterPrivKey).toRaw())
  return {
    assertionSignature: base64urlEncode(sig),
    signedAssertionBytes: base64urlEncode(canonical),
  }
}

export type AssertionVerifyResult<T>
  = | { ok: true,
    payload: T }
  | { ok: false,
    error: AssertionVerifyError }

export type AssertionVerifyError
  = | 'payload_decode_failed'
  | 'payload_shape_invalid'
  | 'wrong_kind'
  | 'wrong_server'
  | 'wrong_request_id'
  | 'signature_invalid'
  | 'user_pubkey_mismatch'
  | 'enc_pubkey_equals_master'
  | 'stale'

export interface VerifyAssertionOptions {
  readonly expectedKind: PairKind
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly expectedServerPubKey: PublicKeyLike
  readonly expectedRequestId?: string
  /** If provided, payload.userPubKey must equal this key (used for re-sign-in). */
  readonly expectedUserPubKey?: PublicKeyLike
  /** Max age in seconds. Default 300. */
  readonly maxAgeMs?: number
  readonly nowMs?: number
}

const ASSERTION_SCHEMA_BY_KIND = {
  'operator-link': OperatorLinkAssertionPayloadSchema,
  'server-link': ServerLinkAssertionPayloadSchema,
  'server-sign-in': ServerSignInAssertionPayloadSchema,
} as const

export function verifyPairingAssertion (
  envelope: MasterSignedAssertionEnvelope,
  opts: VerifyAssertionOptions,
): AssertionVerifyResult<PairingAssertionPayload> {
  let canonical: Uint8Array
  let parsedJson: unknown
  try {
    canonical = base64urlDecode(envelope.signedAssertionBytes)
    parsedJson = JSON.parse(DECODER.decode(canonical))
  } catch {
    return {
      ok: false,
      error: 'payload_decode_failed',
    }
  }

  const schema = ASSERTION_SCHEMA_BY_KIND[opts.expectedKind]
  const parsed = schema.safeParse(parsedJson)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'payload_shape_invalid',
    }
  }
  const payload = parsed.data

  if (payload.kind !== opts.expectedKind) {
    return {
      ok: false,
      error: 'wrong_kind',
    }
  }
  if (payload.serverPubKey !== asPublicKey(opts.expectedServerPubKey).toHex()) {
    return {
      ok: false,
      error: 'wrong_server',
    }
  }
  if (opts.expectedRequestId !== undefined && payload.requestId !== opts.expectedRequestId) {
    return {
      ok: false,
      error: 'wrong_request_id',
    }
  }
  if (opts.expectedUserPubKey !== undefined && payload.userPubKey !== asPublicKey(opts.expectedUserPubKey).toHex()) {
    return {
      ok: false,
      error: 'user_pubkey_mismatch',
    }
  }

  const sig = base64urlDecode(envelope.assertionSignature)
  const userPubKey = hexDecode(payload.userPubKey)
  if (!ed25519Verify(canonical, sig, userPubKey)) {
    return {
      ok: false,
      error: 'signature_invalid',
    }
  }

  // Master Ed25519 (userPubKey) and X25519 encryption key (userEncPubKey)
  // are distinct keys on the wire. If they match, the assertion is malformed
  // and using userEncPubKey as a sealedbox recipient would silently produce
  // a ciphertext only the (non-existent) holder of an X25519 priv for the
  // master can open — i.e. nobody. Reject post-signature so this only fires
  // on authenticated payloads.
  if (payload.userPubKey === payload.userEncPubKey) {
    return {
      ok: false,
      error: 'enc_pubkey_equals_master',
    }
  }

  const now = opts.nowMs ?? Date.now()
  const maxAge = opts.maxAgeMs ?? 300_000
  if (now - payload.ts > maxAge) {
    return {
      ok: false,
      error: 'stale',
    }
  }

  return {
    ok: true,
    payload,
  }
}
