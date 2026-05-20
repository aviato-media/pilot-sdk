// Tower-web side of the client-pair flow:
//   1. Build an M-signed cert binding clientPubKey + clientEncPubKey to the user.
//   2. Build a sealed K bundle to clientEncPubKey, one entry per server.

import type {
  ClientDelegationCertEnvelope,
  ClientDelegationCertPayload,
  ClientKeyBundleContents,
  ClientKeyBundleServer,
  PublicKeyLike,
  PublicPrivateKeyLike,
  SealedBox,
} from '@aviato-media/pilot-core'
import {
  asPublicKey,
  asPublicPrivateKey,
  base64urlEncode,
  buildClientCert,
  sealClientBundle,
} from '@aviato-media/pilot-core'

export interface BuildClientPairCertInput {
  readonly appId: string
  readonly clientId: string
  /** Ed25519 client signing pubkey. */
  readonly clientPubKey: PublicKeyLike
  /** X25519 client encryption pubkey. */
  readonly clientEncPubKey: PublicKeyLike
  readonly deviceName: string
  readonly scope: readonly string[]
  readonly userId: string
  /** Ed25519 user master key. */
  readonly userKey: PublicPrivateKeyLike
  /** X25519 user encryption pubkey. */
  readonly userEncPubKey: PublicKeyLike
  /** Default 60 days. */
  readonly ttlSec?: number
  readonly nowSec?: number
}

export function buildClientPairCert (input: BuildClientPairCertInput): ClientDelegationCertEnvelope {
  const nowSec = input.nowSec ?? Math.floor(Date.now() / 1000)
  const ttl = input.ttlSec ?? 60 * 60 * 24 * 60
  const userKey = asPublicPrivateKey(input.userKey, 'Ed25519')
  const payload: ClientDelegationCertPayload = {
    appId: input.appId,
    clientEncPubKey: asPublicKey(input.clientEncPubKey).toHex(),
    clientId: input.clientId,
    clientPubKey: asPublicKey(input.clientPubKey).toHex(),
    deviceName: input.deviceName,
    exp: nowSec + ttl,
    iat: nowSec,
    scope: [...input.scope],
    userEncPubKey: asPublicKey(input.userEncPubKey).toHex(),
    userId: input.userId,
    userPubKey: userKey.publicKey.toHex(),
    v: 1,
  }
  return buildClientCert({
    masterPrivKey: userKey.privateKey,
    payload,
  })
}

export interface BuildClientPairBundleInput {
  readonly clientEncPubKey: PublicKeyLike
  /**
   * Servers the user has ticked for this app. Entries with a null
   * `connInfoKey` are silently dropped: they represent links where K
   * hasn't been delivered yet (the pairing-response leg is still
   * pending). The user can re-pair the app later for a fresh bundle.
   */
  readonly servers: ReadonlyArray<{
    readonly serverPubKey: PublicKeyLike
    /** Raw 32-byte per-server AES-GCM K, or null if K isn't ready yet. */
    readonly connInfoKey: Uint8Array | null
  }>
}

export async function buildClientPairBundle (input: BuildClientPairBundleInput): Promise<SealedBox> {
  const usable: ClientKeyBundleServer[] = input.servers
    .filter((s): s is { serverPubKey: PublicKeyLike,
      connInfoKey: Uint8Array } => s.connInfoKey !== null)
    .map((s) => ({
      connInfoKey: base64urlEncode(s.connInfoKey),
      serverPubKey: asPublicKey(s.serverPubKey).toHex(),
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
