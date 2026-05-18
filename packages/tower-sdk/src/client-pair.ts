// Tower-web side of the client-pair flow:
//   1. Build an M-signed cert binding clientPubKey + clientEncPubKey to the user.
//   2. Build a sealed K bundle to clientEncPubKey, one entry per server.

import type {
  ClientDelegationCertEnvelope,
  ClientDelegationCertPayload,
  ClientKeyBundleContents,
  ClientKeyBundleServer,
  SealedBox,
} from '@aviato-media/pilot-core'
import { base64urlEncode, buildClientCert, hexEncode, sealClientBundle } from '@aviato-media/pilot-core'

export interface BuildClientPairCertInput {
  readonly appId: string
  readonly clientId: string
  /** Raw 32-byte Ed25519 client signing pubkey. */
  readonly clientPubKey: Uint8Array
  /** Raw 32-byte X25519 client encryption pubkey. */
  readonly clientEncPubKey: Uint8Array
  readonly deviceName: string
  readonly scope: readonly string[]
  readonly userId: string
  /** Raw 32-byte Ed25519 user master pubkey. */
  readonly userPubKey: Uint8Array
  /** Raw 32-byte X25519 user encryption pubkey. */
  readonly userEncPubKey: Uint8Array
  /** Raw 32-byte Ed25519 user master private key. */
  readonly masterPrivKey: Uint8Array
  /** Default 60 days. */
  readonly ttlSec?: number
  readonly nowSec?: number
}

export function buildClientPairCert (input: BuildClientPairCertInput): ClientDelegationCertEnvelope {
  const nowSec = input.nowSec ?? Math.floor(Date.now() / 1000)
  const ttl = input.ttlSec ?? 60 * 60 * 24 * 60
  const payload: ClientDelegationCertPayload = {
    appId: input.appId,
    clientEncPubKey: hexEncode(input.clientEncPubKey),
    clientId: input.clientId,
    clientPubKey: hexEncode(input.clientPubKey),
    deviceName: input.deviceName,
    exp: nowSec + ttl,
    iat: nowSec,
    scope: [...input.scope],
    userEncPubKey: hexEncode(input.userEncPubKey),
    userId: input.userId,
    userPubKey: hexEncode(input.userPubKey),
    v: 1,
  }
  return buildClientCert({
    masterPrivKey: input.masterPrivKey,
    payload,
  })
}

export interface BuildClientPairBundleInput {
  readonly clientEncPubKey: Uint8Array
  /**
   * Servers the user has ticked for this app. Pass entries with bytes —
   * the SDK hex/base64url-encodes for the wire bundle. Entries with a
   * null `connInfoKey` are silently dropped: they represent links where
   * K hasn't been delivered yet (the pairing-response leg is still
   * pending). The user can re-pair the app later for a fresh bundle.
   */
  readonly servers: ReadonlyArray<{
    /** Raw 32-byte server Ed25519 pubkey. */
    readonly serverPubKey: Uint8Array
    /** Raw 32-byte per-server AES-GCM K, or null if K isn't ready yet. */
    readonly connInfoKey: Uint8Array | null
  }>
}

export async function buildClientPairBundle (input: BuildClientPairBundleInput): Promise<SealedBox> {
  const usable: ClientKeyBundleServer[] = input.servers
    .filter((s): s is { serverPubKey: Uint8Array,
      connInfoKey: Uint8Array } => s.connInfoKey !== null)
    .map((s) => ({
      connInfoKey: base64urlEncode(s.connInfoKey),
      serverPubKey: hexEncode(s.serverPubKey),
    }))
  const bundle: ClientKeyBundleContents = {
    issuedAtSec: Math.floor(Date.now() / 1000),
    servers: usable,
    v: 1,
  }
  return sealClientBundle({
    bundle,
    clientEncPubKey: input.clientEncPubKey,
  })
}
