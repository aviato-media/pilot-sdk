// Public surface of @aviato-media/pilot-server-sdk.

export type {
  BeginChallengeInput,
  BeginChallengeResult,
  CompleteChallengeInput,
  CompleteChallengeResult,
} from './cert-auth.js'
export { beginChallenge, completeChallenge } from './cert-auth.js'
export type {
  ConnInfoPublisherConfig,
  PublishInput,
} from './conn-info-publisher.js'
export { ConnInfoPublisher } from './conn-info-publisher.js'
export type {
  PairingHostConfig,
  StartPairingInput,
  StartPairingResult,
  VerifiedPairingAssertion,
} from './pairing.js'
export { PairingService } from './pairing.js'
export type { SealSessionConnInfoInput } from './session-envelope.js'
export { sealSessionConnInfoEnvelope } from './session-envelope.js'
export type {
  IdentityClientRow,
  IdentityClientStore,
  IdentityUserRow,
  IdentityUserStore,
  PairingRequestRow,
  PairingRequestStore,
  SessionChallenge,
  SessionChallengeStore,
} from './stores.js'
export {
  MemoryIdentityClientStore,
  MemoryIdentityUserStore,
  MemoryPairingRequestStore,
  MemorySessionChallengeStore,
} from './stores.js'
export type {
  PairingRegisterRequest,
  TowerClientOptions,
} from './tower-client.js'
export {
  TowerClient,
  TowerHttpError,
} from './tower-client.js'
export { isVerifiedPairingAssertion } from './verified-assertion.js'
export type {
  VerifyServerLinkOptions,
  VerifyServerLinkResult,
  VerifyServerSignInOptions,
  VerifyServerSignInResult,
} from './verify.js'
export {
  verifyAndPersist,
  verifyOperatorLinkAssertion,
  verifyServerLinkAssertion,
  verifyServerSignInAssertion,
} from './verify.js'
