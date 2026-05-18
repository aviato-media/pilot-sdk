// Build + verify the per-session cert-auth assertion (client → media server).
//
// Two signatures stack here: M signs the cert (verified via cert/verify.ts);
// the cert's clientPubKey signs the session assertion. The challenge is
// server-issued and single-use.

import { verifyClientCert } from '../cert/verify.js'
import { base64urlDecode, base64urlEncode, hexDecode, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import { asPrivateKey, asPublicKey } from '../crypto/keys.js'
import { ed25519Sign, ed25519Verify } from '../crypto/signing.js'
import type { IdentitySessionAssertion } from '../schemas/assertions.js'
import type { ClientDelegationCertPayload } from '../schemas/cert.js'

export interface BuildSessionAssertionInput {
  readonly cert: IdentitySessionAssertion['cert']
  readonly challenge: string
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  /** Per-device Ed25519 private key (`PrivateKey` or raw bytes). */
  readonly clientPrivKey: PrivateKeyLike
  /** Defaults to Date.now() (ms since epoch). */
  readonly ts?: number
}

export function buildSessionAssertion (input: BuildSessionAssertionInput): IdentitySessionAssertion {
  const ts = input.ts ?? Date.now()
  const unsigned = {
    cert: input.cert,
    challenge: input.challenge,
    serverId: asPublicKey(input.serverPubKey).toHex(),
    ts,
  }
  const canonical = jcs(unsigned)
  const sig = ed25519Sign(canonical, asPrivateKey(input.clientPrivKey).toRaw())
  return {
    ...unsigned,
    sig: base64urlEncode(sig),
  }
}

// Handle-based variant: `sign` callback replaces a raw private key so
// the SDK never sees private-key bytes (non-extractable CryptoKey, HSM).

export interface BuildSessionAssertionAsyncInput {
  readonly cert: IdentitySessionAssertion['cert']
  readonly challenge: string
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  /** Ed25519 sign over the JCS-canonical bytes of {cert, challenge, serverId, ts}. */
  readonly sign: (message: Uint8Array) => Promise<Uint8Array>
  /** Defaults to Date.now() (ms since epoch). */
  readonly ts?: number
}

export async function buildSessionAssertionAsync (
  input: BuildSessionAssertionAsyncInput,
): Promise<IdentitySessionAssertion> {
  const ts = input.ts ?? Date.now()
  const unsigned = {
    cert: input.cert,
    challenge: input.challenge,
    serverId: asPublicKey(input.serverPubKey).toHex(),
    ts,
  }
  const canonical = jcs(unsigned)
  const sig = await input.sign(canonical)
  return {
    ...unsigned,
    sig: base64urlEncode(sig),
  }
}

export type SessionAssertionVerifyResult
  = | { ok: true,
    certPayload: ClientDelegationCertPayload }
  | { ok: false,
    error: SessionAssertionVerifyError }

export type SessionAssertionVerifyError
  = | 'cert_invalid'
  | 'wrong_server'
  | 'wrong_challenge'
  | 'stale'
  | 'signature_invalid'

export interface VerifySessionAssertionOptions {
  /** Server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly serverPubKey: PublicKeyLike
  readonly challenge: string
  readonly maxAgeMs?: number
  readonly nowMs?: number
  /** Cert validity options forwarded to verifyClientCert. */
  readonly nowSec?: number
  readonly clockSkewSec?: number
}

export function verifySessionAssertion (
  assertion: IdentitySessionAssertion,
  opts: VerifySessionAssertionOptions,
): SessionAssertionVerifyResult {
  const certResult = verifyClientCert(assertion.cert, {
    clockSkewSec: opts.clockSkewSec ?? 60,
    nowSec: opts.nowSec ?? Math.floor(Date.now() / 1000),
  })
  if (!certResult.ok) {
    return {
      ok: false,
      error: 'cert_invalid',
    }
  }

  if (assertion.serverId !== asPublicKey(opts.serverPubKey).toHex()) {
    return {
      ok: false,
      error: 'wrong_server',
    }
  }
  if (assertion.challenge !== opts.challenge) {
    return {
      ok: false,
      error: 'wrong_challenge',
    }
  }

  const now = opts.nowMs ?? Date.now()
  const maxAge = opts.maxAgeMs ?? 300_000
  if (now - assertion.ts > maxAge) {
    return {
      ok: false,
      error: 'stale',
    }
  }

  const { sig, ...unsigned } = assertion
  const canonical = jcs(unsigned)
  const clientPubKey = hexDecode(certResult.payload.clientPubKey)
  if (!ed25519Verify(canonical, base64urlDecode(sig), clientPubKey)) {
    return {
      ok: false,
      error: 'signature_invalid',
    }
  }

  return {
    ok: true,
    certPayload: certResult.payload,
  }
}
