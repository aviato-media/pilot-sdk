// Pairing-response leg: server → Tower → user-browser delivery of K.
// Server sealedboxes K to userEncPubKey and signs the sealed envelope
// (prefixed by hex serverPubKey) with serverPrivKey.

import { base64urlDecode, base64urlEncode, ENCODER, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike, PublicKeyLike } from '../crypto/keys.js'
import { asPrivateKey, asPublicKey } from '../crypto/keys.js'
import { aviatoSealedBoxDecryptJson, aviatoSealedBoxEncrypt } from '../crypto/sealedbox.js'
import { ed25519Sign, ed25519Verify } from '../crypto/signing.js'
import type {
  PairingResponsePayload,
  PairingResponseSealed,
} from '../schemas/conn-info.js'
import { PairingResponseSealedSchema } from '../schemas/conn-info.js'

function buildPairingResponseSigMessage (
  serverPubKeyHex: string,
  sealed: PairingResponsePayload['sealed'],
): Uint8Array {
  const sealedCanonical = JSON.stringify({
    ct: sealed.ct,
    ephPub: sealed.ephPub,
    nonce: sealed.nonce,
  })
  const a = ENCODER.encode(serverPubKeyHex)
  const b = ENCODER.encode(sealedCanonical)
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

export interface BuildPairingResponseInput {
  readonly connInfoKey: Uint8Array
  /** Server Ed25519 pubkey. */
  readonly serverPubKey: PublicKeyLike
  /** Server Ed25519 private key. */
  readonly serverPrivKey: PrivateKeyLike
  /** User X25519 encryption pubkey (recipient). */
  readonly userEncPubKey: PublicKeyLike
  readonly issuedAtSec?: number
  /**
   * Cross-check: when provided, must equal `hexEncode(userEncPubKey)`.
   * Lift from a verified assertion to bind K-seal recipient to it.
   */
  readonly expectedUserEncPubKeyHex?: string
}

function assertValidRecipient (userEncPubKey: Uint8Array, serverPubKey: Uint8Array): void {
  if (userEncPubKey.length !== 32) {
    throw new Error(`buildPairingResponse: userEncPubKey must be 32 bytes (got ${userEncPubKey.length})`)
  }
  let allZero = true
  for (let i = 0; i < 32; i++) {
    if (userEncPubKey[i] !== 0) {
      allZero = false
      break
    }
  }
  if (allZero) {
    throw new Error('buildPairingResponse: userEncPubKey is all zeros')
  }
  if (serverPubKey.length === 32) {
    let equalsServer = true
    for (let i = 0; i < 32; i++) {
      if (userEncPubKey[i] !== serverPubKey[i]) {
        equalsServer = false
        break
      }
    }
    if (equalsServer) {
      throw new Error('buildPairingResponse: userEncPubKey equals serverPubKey')
    }
  }
}

export async function buildPairingResponse (input: BuildPairingResponseInput): Promise<PairingResponsePayload> {
  const serverPubKey = asPublicKey(input.serverPubKey)
  const userEncPubKey = asPublicKey(input.userEncPubKey)
  const serverPrivKey = asPrivateKey(input.serverPrivKey)
  assertValidRecipient(userEncPubKey.toRaw(), serverPubKey.toRaw())
  const serverPubKeyHex = serverPubKey.toHex()
  if (input.expectedUserEncPubKeyHex !== undefined) {
    const actualHex = userEncPubKey.toHex()
    if (actualHex !== input.expectedUserEncPubKeyHex) {
      throw new Error(
        'buildPairingResponse: userEncPubKey does not match expectedUserEncPubKeyHex. '
        + `Got ${actualHex.slice(0, 16)}…, expected ${input.expectedUserEncPubKeyHex.slice(0, 16)}…`,
      )
    }
  }
  const sealedPlain: PairingResponseSealed = {
    connInfoKey: base64urlEncode(input.connInfoKey),
    issuedAtSec: input.issuedAtSec ?? Math.floor(Date.now() / 1000),
    serverPubKey: serverPubKeyHex,
    v: 1,
  }
  const sealed = await aviatoSealedBoxEncrypt({
    plaintext: jcs(sealedPlain),
    recipientPub: userEncPubKey.toRaw(),
  })
  const sigMsg = buildPairingResponseSigMessage(serverPubKeyHex, sealed)
  const sig = ed25519Sign(sigMsg, serverPrivKey.toRaw())
  return {
    sealed,
    sig: base64urlEncode(sig),
  }
}

export type OpenPairingResponseResult
  = | { ok: true,
    payload: PairingResponseSealed }
  | { ok: false,
    error: OpenPairingResponseError }

export type OpenPairingResponseError
  = | 'sig_invalid'
  | 'decrypt_failed'
  | 'shape_invalid'
  | 'inner_server_mismatch'

export interface OpenPairingResponseInput {
  readonly payload: PairingResponsePayload
  readonly userEncPrivKey: PrivateKeyLike
  /** Expected server Ed25519 pubkey (`PublicKey`, raw bytes, or hex string). */
  readonly expectedServerPubKey: PublicKeyLike
}

export async function openPairingResponse (input: OpenPairingResponseInput): Promise<OpenPairingResponseResult> {
  const expectedServerPubKey = asPublicKey(input.expectedServerPubKey)
  const userEncPrivKey = asPrivateKey(input.userEncPrivKey)
  const expectedServerPubKeyHex = expectedServerPubKey.toHex()
  const expectedServerPubKeyBytes = expectedServerPubKey.toRaw()
  const sigMsg = buildPairingResponseSigMessage(expectedServerPubKeyHex, input.payload.sealed)
  if (!ed25519Verify(sigMsg, base64urlDecode(input.payload.sig), expectedServerPubKeyBytes)) {
    return {
      ok: false,
      error: 'sig_invalid',
    }
  }
  const decoded = await aviatoSealedBoxDecryptJson<unknown>({
    box: input.payload.sealed,
    recipientPriv: userEncPrivKey.toRaw(),
  })
  if (decoded === null) {
    return {
      ok: false,
      error: 'decrypt_failed',
    }
  }
  const parsed = PairingResponseSealedSchema.safeParse(decoded)
  if (!parsed.success) {
    return {
      ok: false,
      error: 'shape_invalid',
    }
  }
  if (parsed.data.serverPubKey !== expectedServerPubKeyHex) {
    return {
      ok: false,
      error: 'inner_server_mismatch',
    }
  }
  return {
    ok: true,
    payload: parsed.data,
  }
}
