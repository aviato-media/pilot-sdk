// Smoke test for the React bindings surface.
//
// Full hook behavior is exercised by the underlying client-sdk's
// orchestration tests. This file confirms the package's exports resolve
// and that the re-exported SDK surface stays in sync (preventing the
// "client-sdk added a method but the React package didn't expose it"
// class of drift).

import { describe, expect, test } from 'bun:test'

import * as react from '../src/index.js'

describe('@aviato-media/pilot-client-react exports', () => {
  test('hooks are exported as functions', () => {
    expect(typeof react.usePilotConnections).toBe('function')
    expect(typeof react.usePilotConnection).toBe('function')
    expect(typeof react.usePilotIdentity).toBe('function')
    expect(typeof react.usePairing).toBe('function')
    expect(typeof react.useSignInToServer).toBe('function')
    expect(typeof react.useSignOut).toBe('function')
    expect(typeof react.useAviatoPilotClient).toBe('function')
  })

  test('provider component is exported', () => {
    expect(typeof react.PilotProvider).toBe('function')
  })

  test('re-exports the core SDK surface for ergonomics', () => {
    expect(typeof react.AviatoPilotClient).toBe('function')
    expect(typeof react.LocalStorageBackend).toBe('function')
    expect(typeof react.MemoryStorageBackend).toBe('function')
  })

  test('MemoryStorageBackend is a working IdentityStorage', async () => {
    const s = new react.MemoryStorageBackend()
    expect(await s.getIdentity()).toBeNull()
    expect(await s.getBundle()).toBeNull()
  })

  test('AviatoPilotClient instantiates with required options', () => {
    const c = new react.AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      storage: new react.MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    expect(typeof c.subscribe).toBe('function')
    expect(typeof c.beginPair).toBe('function')
    expect(typeof c.hydrate).toBe('function')
    expect(typeof c.initializeAllConnections).toBe('function')
    expect(typeof c.renewCertIfNeeded).toBe('function')
    expect(typeof c.signInToServer).toBe('function')
    expect(typeof c.signOut).toBe('function')
    expect(typeof c.getConnection).toBe('function')
    expect(typeof c.getConnections).toBe('function')
  })

  test('subscribe + signOut round-trip works through re-exported SDK', async () => {
    const c = new react.AviatoPilotClient({
      appId: 'aviato-web',
      deviceName: 'Test',
      storage: new react.MemoryStorageBackend(),
      towerBaseUrl: 'https://tower.test',
    })
    let calls = 0
    const unsub = c.subscribe(() => {
      calls += 1
    })
    await c.signOut()
    expect(calls).toBeGreaterThanOrEqual(1)
    unsub()
    const before = calls
    await c.signOut()
    expect(calls).toBe(before)
  })
})
