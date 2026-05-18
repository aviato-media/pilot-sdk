// Verify the publish signature on a ServerConnInfoRecord. Trust root:
// the signature is checked against the record's embedded serverPubKey,
// which is sound only because callers fetch records keyed by
// sha256(serverPubKey) using bytes from their identity bundle. Body
// tampering is caught here; key substitution is caught by the K-AEAD
// decrypt downstream.

import { base64urlDecode, hexDecode } from '../crypto/encoding.js'
import { ed25519Verify } from '../crypto/signing.js'
import type { ServerConnInfoRecord } from '../schemas/conn-info.js'
import { buildConnInfoCanonical } from './publish-sig.js'

export function verifyConnInfoRecordSig (record: ServerConnInfoRecord): boolean {
  const canonical = buildConnInfoCanonical({
    ct: record.ct,
    nonce: record.nonce,
    serverPubKey: record.serverPubKey,
    version: record.version,
  })
  return ed25519Verify(canonical, base64urlDecode(record.sig), hexDecode(record.serverPubKey))
}
