// SERVER_CONNINFO AEAD AAD construction — binds ct to its (serverPubKey,
// version) slot so an attacker can't replay an old ct under a new version
// number.

import { concatBytes, ENCODER, u64BE } from '../crypto/encoding.js'

const AAD_PREFIX = ENCODER.encode('aviato-server-conninfo-v1')

export function buildConnInfoAad (serverPubKeyHex: string, version: number): Uint8Array {
  return concatBytes(
    AAD_PREFIX,
    ENCODER.encode(serverPubKeyHex),
    u64BE(version),
  )
}
