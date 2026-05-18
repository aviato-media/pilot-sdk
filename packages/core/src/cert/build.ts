// Build + sign a client delegation cert.
//
// Called by the Tower side (the user's browser, when approving a client-pair
// request). Signs the JCS-canonicalized cert payload with M.

import { base64urlEncode, jcs } from '../crypto/encoding.js'
import type { PrivateKeyLike } from '../crypto/keys.js'
import { asPrivateKey } from '../crypto/keys.js'
import { ed25519Sign } from '../crypto/signing.js'
import type { ClientDelegationCertEnvelope, ClientDelegationCertPayload } from '../schemas/cert.js'

export interface BuildClientCertInput {
  readonly payload: ClientDelegationCertPayload
  readonly masterPrivKey: PrivateKeyLike
}

export function buildClientCert (input: BuildClientCertInput): ClientDelegationCertEnvelope {
  const canonical = jcs(input.payload)
  const sig = ed25519Sign(canonical, asPrivateKey(input.masterPrivKey).toRaw())
  return {
    payload: base64urlEncode(canonical),
    sig: base64urlEncode(sig),
  }
}
