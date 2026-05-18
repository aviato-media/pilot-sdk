// Browser-secure storage: device Ed25519/X25519 keypairs are generated
// non-extractably via WebCrypto and persisted in IndexedDB. Identity,
// bundle, and tokens still go to localStorage. Probe via
// `isSubtleCryptoStorageSupported()` and fall back to `LocalStorageBackend`
// when Ed25519 / X25519 WebCrypto isn't available.

import type { ClientKeyBundleServer, PublicKeyLike } from '@aviato-media/pilot-core'
import { asPublicKey, PublicKey } from '@aviato-media/pilot-core'

import type { KeyOps } from './key-ops.js'
import type {
  IdentityStorage,
  StoredIdentity,
  StoredServerKeys,
  StoredServerToken,
} from './storage.js'

const IDB_DB = 'aviato:pilot:secure-keys:v1'
const IDB_STORE = 'keys'
const KEY_SIGN = 'client-ed25519-priv'
const KEY_SIGN_PUB = 'client-ed25519-pub'
const KEY_ECDH = 'client-x25519-priv'
const KEY_ECDH_PUB = 'client-x25519-pub'

const LS_IDENTITY = 'aviato:pilot:identity:v1'
const LS_BUNDLE = 'aviato:pilot:bundle:v1'
const LS_TOKEN_PREFIX = 'aviato:pilot:token:v1:'

/** Resolves true when both WebCrypto Ed25519 sign and X25519 deriveBits work. */
export async function isSubtleCryptoStorageSupported (): Promise<boolean> {
  if (typeof crypto?.subtle?.generateKey !== 'function') {
    return false
  }
  if (typeof indexedDB === 'undefined') {
    return false
  }
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
    await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
    return true
  } catch {
    return false
  }
}

interface IDBHandle {
  get<T = unknown>(key: string): Promise<T | null>
  put (key: string, value: unknown): Promise<void>
  deleteAll (): Promise<void>
  close (): void
}

let idbPromise: Promise<IDBHandle> | null = null

function getIdb (): Promise<IDBHandle> {
  if (idbPromise === null) {
    idbPromise = openIdb()
  }
  return idbPromise
}

function resetIdb (): void {
  const previous = idbPromise
  idbPromise = null
  if (previous !== null) {
    previous.then((h) => h.close()).catch(() => undefined)
  }
}

function openIdb (): Promise<IDBHandle> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_DB, 1)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE)
      }
    }
    req.onerror = () => reject(req.error ?? new Error('indexedDB open failed'))
    req.onsuccess = () => {
      const db = req.result
      // Drop our cached connection on `versionchange` so another tab can
      // complete its upgrade.
      db.onversionchange = () => {
        resetIdb()
      }
      resolve({
        close () {
          db.close()
        },
        async deleteAll () {
          await new Promise<void>((res, rej) => {
            const tx = db.transaction(IDB_STORE, 'readwrite')
            tx.objectStore(IDB_STORE).clear()
            tx.oncomplete = () => res()
            tx.onerror = () => rej(tx.error ?? new Error('idb clear failed'))
          })
        },
        async get<T = unknown> (key: string): Promise<T | null> {
          return new Promise((res, rej) => {
            const tx = db.transaction(IDB_STORE, 'readonly')
            const r = tx.objectStore(IDB_STORE).get(key)
            r.onsuccess = () => res((r.result as T | undefined) ?? null)
            r.onerror = () => rej(r.error ?? new Error('idb get failed'))
          })
        },
        async put (key: string, value: unknown) {
          await new Promise<void>((res, rej) => {
            const tx = db.transaction(IDB_STORE, 'readwrite')
            tx.objectStore(IDB_STORE).put(value, key)
            tx.oncomplete = () => res()
            tx.onerror = () => rej(tx.error ?? new Error('idb put failed'))
          })
        },
      })
    }
  })
}

async function exportRawPubKey (key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key))
}

function asBuffer (u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer
}

function buildKeyOpsFromHandles (
  signPriv: CryptoKey,
  ecdhPriv: CryptoKey,
  clientPubKey: Uint8Array,
  clientEncPubKey: Uint8Array,
): KeyOps {
  return {
    clientEncPubKey: new PublicKey(clientEncPubKey),
    clientPubKey: new PublicKey(clientPubKey),
    async deriveX25519Shared (peerPub: PublicKeyLike): Promise<Uint8Array> {
      const peer = await crypto.subtle.importKey(
        'raw',
        asBuffer(asPublicKey(peerPub).toRaw()),
        { name: 'X25519' },
        false,
        [],
      )
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'X25519',
          public: peer,
        },
        ecdhPriv,
        256,
      )
      return new Uint8Array(bits)
    },
    async signEd25519 (message: Uint8Array): Promise<Uint8Array> {
      const sig = await crypto.subtle.sign({ name: 'Ed25519' }, signPriv, asBuffer(message))
      return new Uint8Array(sig)
    },
  }
}

export class SubtleCryptoKeyStorageBackend implements IdentityStorage {
  async getIdentity (): Promise<StoredIdentity | null> {
    return readJson<StoredIdentity>(LS_IDENTITY)
  }

  async setIdentity (identity: StoredIdentity | null): Promise<void> {
    writeJson(LS_IDENTITY, identity)
  }

  async getBundle (): Promise<StoredServerKeys | null> {
    return readJson<StoredServerKeys>(LS_BUNDLE)
  }

  async setBundle (bundle: StoredServerKeys | null): Promise<void> {
    writeJson(LS_BUNDLE, bundle)
  }

  async upsertServerKey (entry: ClientKeyBundleServer): Promise<void> {
    const existing = await this.getBundle()
    const servers = existing?.servers.filter((s) => s.serverPubKey !== entry.serverPubKey) ?? []
    servers.push(entry)
    await this.setBundle({
      issuedAtSec: existing?.issuedAtSec ?? Math.floor(Date.now() / 1000),
      servers,
    })
  }

  async getServerToken (serverPubKey: string): Promise<StoredServerToken | null> {
    return readJson<StoredServerToken>(LS_TOKEN_PREFIX + serverPubKey)
  }

  async setServerToken (serverPubKey: string, token: StoredServerToken | null): Promise<void> {
    writeJson(LS_TOKEN_PREFIX + serverPubKey, token)
  }

  async generateClientKeys (): Promise<KeyOps> {
    const idb = await getIdb()
    const sign = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      /* extractable */ false,
      ['sign', 'verify'],
    ) as CryptoKeyPair
    const ecdh = await crypto.subtle.generateKey(
      { name: 'X25519' },
      /* extractable */ false,
      ['deriveBits'],
    ) as CryptoKeyPair
    const signPub = await exportRawPubKey(sign.publicKey)
    const ecdhPub = await exportRawPubKey(ecdh.publicKey)
    await idb.put(KEY_SIGN, sign.privateKey)
    await idb.put(KEY_SIGN_PUB, signPub)
    await idb.put(KEY_ECDH, ecdh.privateKey)
    await idb.put(KEY_ECDH_PUB, ecdhPub)
    return buildKeyOpsFromHandles(sign.privateKey, ecdh.privateKey, signPub, ecdhPub)
  }

  async loadClientKeys (): Promise<KeyOps | null> {
    const idb = await getIdb()
    const signPriv = await idb.get<CryptoKey>(KEY_SIGN)
    const signPub = await idb.get<Uint8Array>(KEY_SIGN_PUB)
    const ecdhPriv = await idb.get<CryptoKey>(KEY_ECDH)
    const ecdhPub = await idb.get<Uint8Array>(KEY_ECDH_PUB)
    const present = [signPriv, signPub, ecdhPriv, ecdhPub].map((v) => v !== null)
    const presentCount = present.filter(Boolean).length
    if (presentCount === 0) {
      return null
    }
    if (presentCount !== 4) {
      throw new Error(
        'SubtleCryptoKeyStorageBackend: partial key state in IndexedDB — '
        + `expected all four of {${KEY_SIGN}, ${KEY_SIGN_PUB}, ${KEY_ECDH}, ${KEY_ECDH_PUB}} `
        + `to be present or absent; found ${presentCount}/4. `
        + 'Call clearClientKeys() and re-pair to recover.',
      )
    }
    return buildKeyOpsFromHandles(signPriv!, ecdhPriv!, signPub!, ecdhPub!)
  }

  async clearClientKeys (): Promise<void> {
    const idb = await getIdb()
    await idb.deleteAll()
    resetIdb()
  }
}

function readJson<T> (key: string): T | null {
  try {
    const raw = localStorage.getItem(key)
    if (raw === null) {
      return null
    }
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

function writeJson (key: string, value: unknown): void {
  if (value === null) {
    localStorage.removeItem(key)
    return
  }
  localStorage.setItem(key, JSON.stringify(value))
}
