// Public surface of @aviato-media/pilot-client-sdk.
//
// Most apps need only AviatoPilotClient + a storage backend; the lower-level
// pieces (TowerClient, serverCertAuth, resolveServerConnInfo) are exported
// for power users who want to bypass the orchestrator.

export type {
  AviatoPilotClientOptions,
  EphemeralPairState,
  Listener,
  PairingHandle,
  PairPollResult,
  ServerConnection,
  ServerConnectionErrorCode,
  ServerConnectionStatus,
} from './identity-client.js'
export {
  AviatoPilotClient,
  clientIdFromPub,
} from './identity-client.js'
export type { KeyOps } from './key-ops.js'
export type {
  ServerCertAuthInput,
  ServerCertAuthInputOps,
  ServerCertAuthInputRaw,
  ServerCertAuthResult,
} from './server-cert-auth.js'
export { ServerAuthError, serverCertAuth } from './server-cert-auth.js'
export type {
  ResolveServerConnInfoError,
  ResolveServerConnInfoInput,
  ResolveServerConnInfoResult,
} from './server-conninfo.js'
export { deriveServerConnInfoHash, resolveServerConnInfo } from './server-conninfo.js'
export type {
  IdentityStorage,
  StoredIdentity,
  StoredServerKeys,
  StoredServerToken,
} from './storage.js'
export { LocalStorageBackend, MemoryStorageBackend } from './storage.js'
export {
  isSubtleCryptoStorageSupported,
  SubtleCryptoKeyStorageBackend,
} from './subtle-crypto-storage.js'
export type {
  ClientPairBeginRequest,
  TowerClientOptions,
} from './tower-client.js'
export { TowerApiError, TowerClient } from './tower-client.js'
