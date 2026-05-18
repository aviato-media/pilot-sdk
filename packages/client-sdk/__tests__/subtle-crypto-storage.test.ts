// Coverage for SubtleCryptoKeyStorageBackend.
//
// Bun's runtime has WebCrypto Ed25519/X25519 natively but no IndexedDB
// or localStorage — both are stubbed here with minimal in-memory fakes
// sufficient for what the backend touches. The actual WebCrypto sign +
// X25519 deriveBits paths run against the real implementations, so this
// gives end-to-end confidence in the handle-based flow.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test'

// ── Fake IndexedDB ────────────────────────────────────────────────────

type Listener<E = unknown> = ((evt: E) => void) | null

class FakeIDBRequest<T> {
  result: T | undefined = undefined
  error: Error | null = null
  onsuccess: Listener = null
  onerror: Listener = null
  /** Trigger success on next microtask. */
  resolve (value: T): void {
    this.result = value
    queueMicrotask(() => {
      this.onsuccess?.(this)
    })
  }
  reject (err: Error): void {
    this.error = err
    queueMicrotask(() => {
      this.onerror?.(this)
    })
  }
}

class FakeObjectStore {
  constructor (private readonly data: Map<string, unknown>) {}
  get (key: string): FakeIDBRequest<unknown> {
    const req = new FakeIDBRequest<unknown>()
    req.resolve(this.data.get(key) as unknown)
    return req
  }
  put (value: unknown, key: string): FakeIDBRequest<undefined> {
    const req = new FakeIDBRequest<undefined>()
    this.data.set(key, value)
    req.resolve(undefined)
    return req
  }
  clear (): FakeIDBRequest<undefined> {
    const req = new FakeIDBRequest<undefined>()
    this.data.clear()
    req.resolve(undefined)
    return req
  }
}

class FakeTransaction {
  oncomplete: Listener = null
  onerror: Listener = null
  constructor (private readonly store: FakeObjectStore) {
    queueMicrotask(() => {
      this.oncomplete?.(this)
    })
  }
  objectStore (_name: string): FakeObjectStore {
    return this.store
  }
}

class FakeIDBDatabase {
  closed = false
  onversionchange: Listener = null
  objectStoreNames = {
    contains: (name: string) => this.stores.has(name),
  }
  constructor (private readonly stores: Map<string, Map<string, unknown>>) {}
  transaction (storeName: string, _mode: 'readonly' | 'readwrite'): FakeTransaction {
    const data = this.stores.get(storeName)!
    return new FakeTransaction(new FakeObjectStore(data))
  }
  createObjectStore (name: string): void {
    if (!this.stores.has(name)) {
      this.stores.set(name, new Map())
    }
  }
  close (): void {
    this.closed = true
  }
}

class FakeOpenRequest extends FakeIDBRequest<FakeIDBDatabase> {
  onupgradeneeded: Listener = null
}

interface FakeFactoryState {
  stores: Map<string, Map<string, unknown>>
  version: number
}

function installFakeIndexedDB (): FakeFactoryState {
  const state: FakeFactoryState = {
    stores: new Map(),
    version: 0,
  }
  ;(globalThis as { indexedDB?: unknown }).indexedDB = {
    open (_name: string, version: number) {
      const req = new FakeOpenRequest()
      queueMicrotask(() => {
        const isNew = state.version < version
        if (isNew) {
          state.version = version
          const db = new FakeIDBDatabase(state.stores)
          req.result = db
          // Fire onupgradeneeded before onsuccess.
          req.onupgradeneeded?.(req)
        }
        const db = new FakeIDBDatabase(state.stores)
        req.result = db
        req.onsuccess?.(req)
      })
      return req
    },
  }
  return state
}

function uninstallFakeIndexedDB (): void {
  delete (globalThis as { indexedDB?: unknown }).indexedDB
}

// ── localStorage stub ────────────────────────────────────────────────

class FakeLocalStorage implements Storage {
  private store = new Map<string, string>()
  get length () {
    return this.store.size
  }

  clear () {
    this.store.clear()
  }

  getItem (k: string) {
    return this.store.get(k) ?? null
  }

  key (i: number) {
    return Array.from(this.store.keys())[i] ?? null
  }

  removeItem (k: string) {
    this.store.delete(k)
  }

  setItem (k: string, v: string) {
    this.store.set(k, v)
  }
}

// ── Test suite ───────────────────────────────────────────────────────

let fakeLs: FakeLocalStorage
let idbState: FakeFactoryState

beforeAll(() => {
  fakeLs = new FakeLocalStorage()
  ;(globalThis as { localStorage?: Storage }).localStorage = fakeLs
  idbState = installFakeIndexedDB()
})
afterAll(() => {
  delete (globalThis as { localStorage?: Storage }).localStorage
  uninstallFakeIndexedDB()
})
beforeEach(() => {
  fakeLs.clear()
  // Wipe the IDB record contents but preserve the store structure so the
  // module-level cached IDB connection (held by SubtleCryptoKeyStorageBackend)
  // can still resolve transactions across tests. The next test sees an empty
  // 'keys' store, matching what production callers see after clearClientKeys.
  for (const m of idbState.stores.values()) {
    m.clear()
  }
})
afterEach(() => {
  // no-op — kept as a hook for future per-test cleanup
})

describe('isSubtleCryptoStorageSupported', () => {
  test('returns true when WebCrypto + IDB are available', async () => {
    const { isSubtleCryptoStorageSupported } = await import('../src/subtle-crypto-storage.js')
    expect(await isSubtleCryptoStorageSupported()).toBe(true)
  })
  test('returns false when indexedDB is absent', async () => {
    delete (globalThis as { indexedDB?: unknown }).indexedDB
    const { isSubtleCryptoStorageSupported } = await import('../src/subtle-crypto-storage.js')
    expect(await isSubtleCryptoStorageSupported()).toBe(false)
    // Re-install for subsequent tests.
    idbState = installFakeIndexedDB()
  })
})

describe('SubtleCryptoKeyStorageBackend', () => {
  test('generateClientKeys → loadClientKeys round-trip returns usable KeyOps', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const backend = new SubtleCryptoKeyStorageBackend()
    const generated = await backend.generateClientKeys()
    expect(generated.clientPubKey.toRaw().length).toBe(32)
    expect(generated.clientEncPubKey.toRaw().length).toBe(32)
    // sign produces a valid 64-byte Ed25519 signature
    const msg = new TextEncoder().encode('hello')
    const sig = await generated.signEd25519(msg)
    expect(sig.length).toBe(64)
    // After persistence, loadClientKeys returns ops with the same pubs.
    const loaded = await backend.loadClientKeys()
    expect(loaded).not.toBeNull()
    expect(loaded!.clientPubKey.equals(generated.clientPubKey)).toBe(true)
    expect(loaded!.clientEncPubKey.equals(generated.clientEncPubKey)).toBe(true)
    const sig2 = await loaded!.signEd25519(msg)
    expect(sig2.length).toBe(64)
  })

  test('loadClientKeys returns null when no keys persisted', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const backend = new SubtleCryptoKeyStorageBackend()
    expect(await backend.loadClientKeys()).toBeNull()
  })

  test('clearClientKeys wipes the persisted keys', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const backend = new SubtleCryptoKeyStorageBackend()
    await backend.generateClientKeys()
    expect(await backend.loadClientKeys()).not.toBeNull()
    await backend.clearClientKeys()
    expect(await backend.loadClientKeys()).toBeNull()
  })

  test('loadClientKeys throws on partial IDB state', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const backend = new SubtleCryptoKeyStorageBackend()
    await backend.generateClientKeys()
    // Simulate a partial write: delete one of the four keys.
    const keys = idbState.stores.get('keys')!
    keys.delete('client-x25519-pub')
    await expect(backend.loadClientKeys()).rejects.toThrow(/partial key state/)
  })

  test('deriveX25519Shared round-trips a real sealedbox encrypted to the backend\'s pub', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const {
      aviatoSealedBoxDecryptHandle,
      aviatoSealedBoxEncrypt,
    } = await import('@aviato-media/pilot-core')
    const backend = new SubtleCryptoKeyStorageBackend()
    const ops = await backend.generateClientKeys()
    // External party seals a payload to the backend's clientEncPubKey using
    // the production sealedbox primitive; the backend opens it via its
    // handle-based ECDH callback. Round-trip succeeding proves the
    // deriveX25519Shared callback returns the correct ECDH bytes.
    const plaintext = new TextEncoder().encode('handle ECDH round-trip')
    const box = await aviatoSealedBoxEncrypt({
      plaintext,
      recipientPub: ops.clientEncPubKey.toRaw(),
    })
    const decrypted = await aviatoSealedBoxDecryptHandle({
      box,
      deriveShared: (peerPub) => ops.deriveX25519Shared(peerPub),
    })
    expect(decrypted).not.toBeNull()
    expect(new TextDecoder().decode(decrypted!)).toBe('handle ECDH round-trip')
  })

  test('identity / bundle / token methods still use localStorage', async () => {
    const { SubtleCryptoKeyStorageBackend } = await import('../src/subtle-crypto-storage.js')
    const backend = new SubtleCryptoKeyStorageBackend()
    expect(await backend.getIdentity()).toBeNull()
    await backend.setIdentity({
      certSignature: 's',
      clientId: 'c',
      exp: 1,
      iat: 0,
      signedCertBytes: 'b',
      userPubKey: 'a'.repeat(64),
    })
    expect((await backend.getIdentity())?.clientId).toBe('c')
    await backend.setBundle({
      issuedAtSec: 1,
      servers: [],
    })
    expect(await backend.getBundle()).not.toBeNull()
    await backend.setServerToken('a'.repeat(64), {
      expiresAt: 'e',
      token: 't',
    })
    expect((await backend.getServerToken('a'.repeat(64)))?.token).toBe('t')
  })
})
