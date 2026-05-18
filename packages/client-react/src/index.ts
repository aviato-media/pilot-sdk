export {
  PilotProvider,
  type PilotProviderProps,
  useAviatoPilotClient,
} from './context.js'
export {
  type PairingPhase,
  type PilotIdentityState,
  usePairing,
  type UsePairingResult,
  usePilotConnection,
  usePilotConnections,
  usePilotIdentity,
  useSignInToServer,
  type UseSignInToServerResult,
  useSignOut,
  type UseSignOutResult,
} from './hooks.js'

// Re-export the SDK surface that React apps will typically need so they
// don't have to import from two packages.
export {
  AviatoPilotClient,
  type AviatoPilotClientOptions,
  type EphemeralPairState,
  type IdentityStorage,
  LocalStorageBackend,
  MemoryStorageBackend,
  type PairingHandle,
  type ServerConnection,
  type ServerConnectionStatus,
  type StoredIdentity,
} from '@aviato-media/pilot-client-sdk'
