// Public surface of @aviato-media/pilot-tower-sdk.

export type { ApproveServerLinkInput } from './assertions.js'
export { approveOperatorLink, approveServerLink, approveServerSignIn } from './assertions.js'
export type {
  BuildClientPairBundleInput,
  BuildClientPairCertInput,
} from './client-pair.js'
export { buildClientPairBundle, buildClientPairCert } from './client-pair.js'
export type {
  ResolveConnInfoInput,
  ResolveConnInfoResult,
} from './conn-info.js'
export { deriveConnInfoHash, resolveConnInfo } from './conn-info.js'
export type {
  KvBatchResult,
  KvRow,
  KvStore,
  KvStorePutInput,
  MemoryKvStoreOptions,
} from './kv-store.js'
export {
  decodePutItem,
  MemoryKvStore,
  partitionBatchGet,
  sha256OfCiphertext,
  toListEntry,
} from './kv-store.js'
export type {
  ClaimConnInfoKeyInput,
  ClaimConnInfoKeyResult,
} from './pairing-response.js'
export { claimConnInfoKey } from './pairing-response.js'
export type { PrfEvalInputs } from './prf.js'
export {
  buildPrfInputs,
  derivePrfWrappingKey,
  extractPrfOutput,
  generatePrfSalt,
} from './prf.js'
export type { PairedClientStore } from './stores.js'
export { MemoryPairedClientStore, toPairedClientView } from './stores.js'
export type {
  AddPasskeyToVaultInput,
  CreateVaultInput,
  OpenVaultInput,
  OpenVaultResult,
} from './vault.js'
export {
  addPasskeyToVault,
  bytesToB64u,
  createVault,
  decryptVault,
  encryptVault,
  generateVaultKey,
  openVault,
  removePasskeyFromVault,
  replaceVaultPayload,
  unwrapVaultKey,
  wrapVaultKey,
} from './vault.js'
