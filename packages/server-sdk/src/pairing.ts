// Server-link pairing lifecycle.
//
// Flow:
//   1. start()         → call Tower /pairing/register, persist row, return
//                        { requestId, code, pairingUrl }.
//   2. pollUntilDone() → poll Tower /pairing/:id until state=completed or
//                        terminal. Returns the assertion envelope.
//   3. respondWithK()  → seal K to userEncPubKey, sign with serverPrivKey,
//                        POST /pairing/:id/response.

import type {
  MasterSignedAssertionEnvelope,
  PairingResponsePayload,
} from '@aviato-media/pilot-core'
import { buildPairingResponse, pubkeyFromHex } from '@aviato-media/pilot-core'

import type { PairingRequestRow, PairingRequestStore } from './stores.js'
import type { TowerClient } from './tower-client.js'
import type { VerifyServerLinkResult, VerifyServerSignInResult } from './verify.js'

/** Success branch of `verifyServerLinkAssertion` / `verifyServerSignInAssertion`. */
export type VerifiedPairingAssertion
  = | Extract<VerifyServerLinkResult, { ok: true }>
  | Extract<VerifyServerSignInResult, { ok: true }>

export interface PairingHostConfig {
  readonly serverId: string
  /** Raw 32-byte server Ed25519 pubkey. */
  readonly serverPubKey: Uint8Array
  /** Raw 32-byte server Ed25519 private key. */
  readonly serverPrivKey: Uint8Array
  /** Where Tower-web is hosted (used to build the pairingUrl). */
  readonly towerPairingBaseUrl: string
  readonly displayName?: string
  readonly serverIcon?: string
}

export interface StartPairingInput {
  /**
   * Which pairing flow to begin.
   * - `server-link` (default): adding a new server to a user's identity.
   *   Requires exactly one of `inviteToken` or `localUserId`.
   * - `server-sign-in`: re-authenticating an existing user (refreshes the
   *   session + redelivers K). Neither `inviteToken` nor `localUserId` is
   *   required — the host's prior session-auth proves the user identity.
   */
  readonly kind?: 'server-link' | 'server-sign-in'
  readonly inviteToken?: string
  readonly localUserId?: string
  readonly scope?: readonly string[]
}

export interface StartPairingResult {
  readonly requestId: string
  readonly code: string
  readonly expiresAt: string
  readonly pairingUrl: string
}

export class PairingService {
  constructor (
    private readonly tower: TowerClient,
    private readonly store: PairingRequestStore,
    private readonly config: PairingHostConfig,
  ) {}

  async start (input: StartPairingInput): Promise<StartPairingResult> {
    const kind = input.kind ?? 'server-link'
    if (kind === 'server-link') {
      if ((input.inviteToken !== undefined) === (input.localUserId !== undefined)) {
        throw new Error('server-link: exactly one of inviteToken or localUserId must be provided')
      }
    }
    const reg = await this.tower.pairingRegister({
      displayName: this.config.displayName,
      kind,
      scope: input.scope === undefined ? undefined : [...input.scope],
      serverIcon: this.config.serverIcon,
      serverId: this.config.serverId,
    })
    const purpose: PairingRequestRow['purpose'] = kind === 'server-sign-in'
      ? 'server-sign-in'
      : input.inviteToken !== undefined ? 'invite' : 'link-existing-user'
    const row: PairingRequestRow = {
      code: reg.code,
      createdAt: new Date().toISOString(),
      inviteToken: input.inviteToken ?? null,
      localUserId: input.localUserId ?? null,
      purpose,
      requestId: reg.requestId,
      towerExpiresAt: reg.expiresAt,
    }
    await this.store.put(row)
    return {
      code: reg.code,
      expiresAt: reg.expiresAt,
      pairingUrl: `${this.config.towerPairingBaseUrl.replace(/\/+$/, '')}/pair?code=${reg.code}`,
      requestId: reg.requestId,
    }
  }

  async poll (requestId: string): Promise<
    | { state: 'pending' | 'claimed_by_user' }
    | { state: 'completed',
      envelope: MasterSignedAssertionEnvelope }
    | { state: 'denied' | 'expired' }
  > {
    const resp = await this.tower.pollPairing(requestId)
    if (resp.state === 'completed') {
      if (resp.signedAssertionBytes === undefined || resp.assertionSignature === undefined) {
        throw new Error('Tower returned completed pairing without assertion bytes')
      }
      return {
        envelope: {
          assertionSignature: resp.assertionSignature,
          signedAssertionBytes: resp.signedAssertionBytes,
        },
        state: 'completed',
      }
    }
    return { state: resp.state }
  }

  /**
   * Build the sealed K reply and POST it to Tower. The recipient X25519
   * key is derived from `verifiedAssertion` — the only authoritative
   * source for which key K must be sealed to.
   */
  async respondWithK (input: {
    requestId: string
    connInfoKey: Uint8Array
    verifiedAssertion: VerifiedPairingAssertion
  }): Promise<PairingResponsePayload> {
    if ((input.verifiedAssertion as { ok: boolean }).ok !== true) {
      throw new Error('PairingService.respondWithK: verifiedAssertion is not ok')
    }
    const userEncPubKey = pubkeyFromHex(input.verifiedAssertion.userEncPubKey)
    const payload = await buildPairingResponse({
      connInfoKey: input.connInfoKey,
      expectedUserEncPubKeyHex: input.verifiedAssertion.userEncPubKey,
      serverPrivKey: this.config.serverPrivKey,
      serverPubKey: this.config.serverPubKey,
      userEncPubKey,
    })
    await this.tower.postPairingResponse(input.requestId, payload)
    return payload
  }

  /** Convenience: pull the consumed request row (e.g. after handling completion). */
  async consumeRequest (requestId: string): Promise<PairingRequestRow | null> {
    return this.store.consume(requestId)
  }
}
