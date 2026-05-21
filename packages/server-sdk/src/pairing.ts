// Server-link pairing lifecycle.
//
// Flow:
//   1. start()                    → call Tower /pairing/register, persist
//                                   row, return { requestId, code, pairingUrl }.
//   2. pollUntilDone()            → poll Tower /pairing/:id until state=
//                                   completed or terminal. Returns the
//                                   assertion envelope.
//   3. respondWithKFromEnvelope() → recommended. Verify the envelope inline
//                                   against `requestId`, then seal K to the
//                                   just-verified userEncPubKey.
//   4. respondWithK()             → low-level. Takes a branded
//                                   VerifiedPairingAssertion (obtained from
//                                   verifyServerLinkAssertion or
//                                   verifyServerSignInAssertion). Runtime-
//                                   rejects hand-constructed objects.

import type {
  MasterSignedAssertionEnvelope,
  PairingResponsePayload,
  PairKind,
  PublicKeyLike,
  PublicPrivateKey,
} from '@aviato-media/pilot-core'
import { buildPairingResponse } from '@aviato-media/pilot-core'

import type { PairingRequestRow, PairingRequestStore } from './stores.js'
import type { TowerClient } from './tower-client.js'
import type { VerifiedPairingAssertion } from './verified-assertion.js'
import { isVerifiedPairingAssertion } from './verified-assertion.js'
import {
  verifyOperatorLinkAssertion,
  verifyServerLinkAssertion,
  verifyServerSignInAssertion,
} from './verify.js'

export type { VerifiedPairingAssertion } from './verified-assertion.js'

export interface PairingHostConfig {
  readonly serverId: string
  readonly serverKey: PublicPrivateKey
  readonly towerPairingBaseUrl: string
  readonly displayName?: string
  readonly serverIcon?: string
}

export interface StartPairingInput {
  readonly kind?: PairKind
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
      : kind === 'operator-link'
        ? 'operator-link'
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
   * The brand attests that `verifiedAssertion` was produced by a prior
   * `verifyServerLinkAssertion` / `verifyServerSignInAssertion` call. It
   * does NOT attest verification for THIS `requestId` — a verified result
   * for an earlier request would still pass. For that stronger guarantee
   * (recipient bound to the envelope just verified against `requestId`),
   * call `respondWithKFromEnvelope` instead.
   */
  async respondWithK (input: {
    readonly requestId: string
    readonly connInfoKey: Uint8Array
    readonly verifiedAssertion: VerifiedPairingAssertion
  }): Promise<PairingResponsePayload> {
    if (!isVerifiedPairingAssertion(input.verifiedAssertion)) {
      throw new Error(
        'PairingService.respondWithK: verifiedAssertion missing brand. '
        + 'Use verifyServerLinkAssertion / verifyServerSignInAssertion, '
        + 'or respondWithKFromEnvelope to verify inline. '
        + 'If you built this object from a stored user row, that is the bug — '
        + 'the recipient must come from a freshly-verified envelope.',
      )
    }
    const payload = await buildPairingResponse({
      connInfoKey: input.connInfoKey,
      expectedUserEncPubKeyHex: input.verifiedAssertion.userEncPubKey,
      serverKey: this.config.serverKey,
      userEncPubKey: input.verifiedAssertion.userEncPubKey,
      userPubKey: input.verifiedAssertion.userPubKey,
    })
    await this.tower.postPairingResponse(input.requestId, payload)
    return payload
  }

  async respondWithKFromEnvelope (input: {
    readonly requestId: string
    readonly connInfoKey: Uint8Array
    readonly envelope: MasterSignedAssertionEnvelope
    readonly kind?: PairKind
    readonly expectedUserPubKey?: PublicKeyLike
    readonly maxAgeMs?: number
  }): Promise<PairingResponsePayload> {
    const kind = input.kind ?? 'server-link'
    const verifyOpts = {
      envelope: input.envelope,
      expectedRequestId: input.requestId,
      expectedServerPubKey: this.config.serverKey.publicKey,
      maxAgeMs: input.maxAgeMs,
    }
    const verified = kind === 'server-sign-in'
      ? verifyServerSignInAssertion({
        ...verifyOpts,
        expectedUserPubKey: input.expectedUserPubKey,
      })
      : kind === 'operator-link'
        ? verifyOperatorLinkAssertion(verifyOpts)
        : verifyServerLinkAssertion(verifyOpts)
    if (!verified.ok) {
      throw new Error(`PairingService.respondWithKFromEnvelope: assertion verify failed (${verified.error})`)
    }
    return this.respondWithK({
      connInfoKey: input.connInfoKey,
      requestId: input.requestId,
      verifiedAssertion: verified,
    })
  }

  async consumeRequest (requestId: string): Promise<PairingRequestRow | null> {
    return this.store.consume(requestId)
  }
}
