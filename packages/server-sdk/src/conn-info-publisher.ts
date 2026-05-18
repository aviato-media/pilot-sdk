// K lifecycle + ServerConnInfo publishing.
//
// `K` is the per-server AES-GCM-256 key the server uses to encrypt its
// ServerConnInfo payload before publishing to Tower. Tower never sees K;
// users get K via the pairing-response leg (server-link / server-sign-in)
// or via the client-pair sealed bundle.
//
// `version` is strict-monotonic — every publish bumps it. Persistence is
// outside this SDK's scope; the host injects current `version` per publish.

import type { ServerConnInfoPayload, ServerConnInfoPublish } from '@aviato-media/pilot-core'
import {
  randomAesKey,
  sealServerConnInfo,
} from '@aviato-media/pilot-core'

import type { TowerClient } from './tower-client.js'

export interface ConnInfoPublisherConfig {
  /** Raw 32-byte server Ed25519 pubkey. */
  readonly serverPubKey: Uint8Array
  /** Raw 32-byte server Ed25519 private key. */
  readonly serverPrivKey: Uint8Array
  readonly tower: TowerClient
}

export interface PublishInput {
  readonly payload: Omit<ServerConnInfoPayload, 'rotationCounter' | 'v'>
  readonly connInfoKey: Uint8Array
  /** Strict-monotonic; caller persists this and increments each publish. */
  readonly version: number
}

export class ConnInfoPublisher {
  // In-process monotonicity check. The host is responsible for durable
  // monotonicity across restarts — version is AAD-bound and indexed by
  // Tower, so going backwards causes silent accept of old ciphertexts.
  private lastPublishedVersion = -1

  constructor (private readonly config: ConnInfoPublisherConfig) {}

  /** Generate a fresh 32-byte K. Persist it; do not regenerate per publish. */
  static generateConnInfoKey (): Uint8Array {
    return randomAesKey()
  }

  async publish (input: PublishInput): Promise<ServerConnInfoPublish> {
    if (!Number.isInteger(input.version) || input.version < 0) {
      throw new Error(
        `ConnInfoPublisher.publish: version must be a non-negative integer, got ${input.version}`,
      )
    }
    if (input.version <= this.lastPublishedVersion) {
      throw new Error(
        'ConnInfoPublisher.publish: version must be strictly monotonic — '
        + `got ${input.version}, last published was ${this.lastPublishedVersion}. `
        + 'Persist the last-published version across restarts and inject the next value.',
      )
    }
    const sealed = await sealServerConnInfo({
      connInfoKey: input.connInfoKey,
      payload: {
        ...input.payload,
        rotationCounter: input.version,
        v: 1,
      },
      serverPrivKey: this.config.serverPrivKey,
      serverPubKey: this.config.serverPubKey,
      version: input.version,
    })
    await this.config.tower.publishServerConnInfo(sealed)
    this.lastPublishedVersion = input.version
    return sealed
  }
}
