import type {
  EphemeralPairState,
  PairingHandle,
  ServerConnection,
  StoredIdentity,
} from '@aviato-media/pilot-client-sdk'
import type { PublicKeyLike } from '@aviato-media/pilot-core'
import { asPublicKey } from '@aviato-media/pilot-core'
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'

import { useAviatoPilotClient } from './context.js'

/** Snapshot of all known server connections. Re-renders on any change. */
export function usePilotConnections (): ReadonlyArray<ServerConnection> {
  const client = useAviatoPilotClient()
  const subscribe = useCallback((notify: () => void) => client.subscribe(notify), [client])
  const getSnapshot = useCallback(() => client.getConnections(), [client])
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}

/**
 * Snapshot of a single server's connection. Re-renders when that server
 * changes. Pass a `serverPubKey` with stable identity across renders
 * (hex string, `PublicKey`, or memoized bytes) — a fresh `Uint8Array`
 * literal inline rebuilds the needle every render.
 */
export function usePilotConnection (serverPubKey: PublicKeyLike): ServerConnection | undefined {
  const all = usePilotConnections()
  const needleHex = useMemo(() => asPublicKey(serverPubKey).toHex(), [serverPubKey])
  return useMemo(() => all.find((c) => c.serverPubKey.toHex() === needleHex), [all, needleHex])
}

export interface PilotIdentityState {
  readonly identity: StoredIdentity | null
  readonly loading: boolean
}

/** Loads the persisted identity. Re-fetches when the connections snapshot shifts. */
export function usePilotIdentity (): PilotIdentityState {
  const client = useAviatoPilotClient()
  const connections = usePilotConnections()
  const [state, setState] = useState<PilotIdentityState>({
    identity: null,
    loading: true,
  })

  useEffect(() => {
    let cancelled = false
    client.getIdentity().then((identity) => {
      if (!cancelled) {
        setState({
          identity,
          loading: false,
        })
      }
    }).catch(() => {
      if (!cancelled) {
        setState({
          identity: null,
          loading: false,
        })
      }
    })
    return () => {
      cancelled = true
    }
  }, [client, connections])

  return state
}

export type PairingPhase
  = | { phase: 'idle' }
  | { phase: 'starting' }
  | { phase: 'awaiting_user',
    code: string,
    requestId: string,
    expiresAt: string,
    ephemeral: EphemeralPairState }
  | { phase: 'completed',
    identity: StoredIdentity }
  | { phase: 'error',
    error: string }

export interface UsePairingResult {
  readonly phase: PairingPhase
  /** Kick off pairing. The hook drives polling under the hood. */
  begin (): Promise<void>
  /** Cancel an in-flight pairing. */
  cancel (): void
  /** Reset to idle (e.g. after error). */
  reset (): void
}

/** Phases: `idle` → `starting` → `awaiting_user` → `completed`|`error`. */
export function usePairing (opts: { pollIntervalMs?: number } = {}): UsePairingResult {
  const client = useAviatoPilotClient()
  const [phase, setPhase] = useState<PairingPhase>({ phase: 'idle' })
  const [activeHandle, setActiveHandle] = useState<PairingHandle | null>(null)
  // Guards against a fast double-click creating two pairing requests
  // where only the second is cancellable from hook state.
  const inFlightRef = useRef(false)

  useEffect(() => () => {
    activeHandle?.cancel()
  }, [activeHandle])

  const begin = useCallback(async (): Promise<void> => {
    if (inFlightRef.current) {
      return
    }
    inFlightRef.current = true
    setPhase({ phase: 'starting' })
    try {
      const handle = await client.beginPair({ pollIntervalMs: opts.pollIntervalMs })
      setActiveHandle(handle)
      setPhase({
        code: handle.code,
        ephemeral: handle.ephemeral,
        expiresAt: handle.expiresAt,
        phase: 'awaiting_user',
        requestId: handle.requestId,
      })
      // Drive the polling. await() resolves with the identity or throws.
      handle.await().then((identity) => {
        setPhase({
          identity,
          phase: 'completed',
        })
      }).catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err)
        if (msg === 'pairing cancelled') {
          setPhase({ phase: 'idle' })
        } else {
          setPhase({
            error: msg,
            phase: 'error',
          })
        }
      }).finally(() => {
        inFlightRef.current = false
      })
    } catch (err) {
      inFlightRef.current = false
      const msg = err instanceof Error ? err.message : String(err)
      setPhase({
        error: msg,
        phase: 'error',
      })
    }
  }, [client, opts.pollIntervalMs])

  const cancel = useCallback((): void => {
    activeHandle?.cancel()
    setActiveHandle(null)
    setPhase({ phase: 'idle' })
    inFlightRef.current = false
  }, [activeHandle])

  const reset = useCallback((): void => {
    setActiveHandle(null)
    setPhase({ phase: 'idle' })
    inFlightRef.current = false
  }, [])

  return {
    begin,
    cancel,
    phase,
    reset,
  }
}

export interface UseSignInToServerResult {
  signIn (serverPubKey: PublicKeyLike): Promise<ServerConnection>
}

export function useSignInToServer (): UseSignInToServerResult {
  const client = useAviatoPilotClient()
  return useMemo(() => ({
    signIn: (serverPubKey: PublicKeyLike) => client.signInToServer({ serverPubKey }),
  }), [client])
}

export interface UseSignOutResult {
  signOut (): Promise<void>
}

export function useSignOut (): UseSignOutResult {
  const client = useAviatoPilotClient()
  return useMemo(() => ({
    signOut: () => client.signOut(),
  }), [client])
}
