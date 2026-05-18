// Pilot client context. Wrap your app in <PilotProvider client={client}/>
// to make the client available to hooks.

import { createContext, useContext, useEffect, useMemo, type ReactNode } from 'react'

import type { AviatoPilotClient } from '@aviato-media/pilot-client-sdk'

const PilotContext = createContext<AviatoPilotClient | null>(null)

export interface PilotProviderProps {
  readonly client: AviatoPilotClient
  readonly children: ReactNode
  /**
   * If true (default), the provider calls `client.hydrate()` once on mount
   * to seed the connection cache from persisted storage. Set false to
   * defer hydration to your own bootstrap code.
   */
  readonly autoHydrate?: boolean
  /**
   * If true, the provider calls `client.initializeAllConnections()` once
   * after hydration. Default false — most apps want to gate this on user
   * action (e.g. opening the servers pane).
   */
  readonly autoInitializeConnections?: boolean
}

export function PilotProvider (props: PilotProviderProps): ReactNode {
  const value = useMemo(() => props.client, [props.client])
  const autoHydrate = props.autoHydrate ?? true
  const autoInit = props.autoInitializeConnections ?? false

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      if (autoHydrate) {
        const had = await props.client.hydrate()
        if (cancelled) {
          return
        }
        if (had && autoInit) {
          await props.client.initializeAllConnections()
        }
      } else if (autoInit) {
        await props.client.initializeAllConnections()
      }
    }
    run().catch(() => undefined)
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.client])

  return <PilotContext.Provider value={value}>{props.children}</PilotContext.Provider>
}

export function useAviatoPilotClient (): AviatoPilotClient {
  const c = useContext(PilotContext)
  if (c === null) {
    throw new Error('useAviatoPilotClient must be used inside <PilotProvider>')
  }
  return c
}
