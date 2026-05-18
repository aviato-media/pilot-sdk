// Tower-side vault shape (opaque to Tower; Tower stores blobs only).
//
// The vault holds the user's M (master Ed25519 private key) and their list
// of linked servers (with each server's per-user K). Encrypted under VK
// (32-byte AES-GCM key), with VK wrapped per-enrolled-passkey via the
// WebAuthn PRF extension.

import { z } from 'zod'

import { BASE64URL, ISO_DATETIME } from './primitives.js'

// Per-passkey wrap of VK.
export const VaultWrapSchema = z.object({
  credentialId: BASE64URL,
  prfSalt: BASE64URL,
  wrapIv: BASE64URL,
  wrappedKey: BASE64URL,
})

export type VaultWrap = z.infer<typeof VaultWrapSchema>

// The blob Tower stores (Tower never decrypts; Tower validates only shape).
export const VaultBlobSchema = z.object({
  ciphertext: BASE64URL,
  createdAt: z.number().int(),
  iv: BASE64URL,
  updatedAt: z.number().int().optional(),
  v: z.literal(1),
  wraps: z.array(VaultWrapSchema).min(1),
})

export type VaultBlob = z.infer<typeof VaultBlobSchema>

// Linked-server vault entry. `connInfoKey` (K) is delivered by the media
// server via the pairing-response leg (asynchronous, post-approval) and
// persisted here for later distribution to client apps via the client-pair
// sealed bundle.
//
// `connInfoKey` is **nullable** to model the pending state: between
// "server-link assertion approved" and "Tower polled /pairing-response/:id
// and received the sealed K", the user has a legitimate link to the server
// but no usable K yet. UI surfaces should render the entry as
// "Connecting…". Once K arrives, Tower-web updates the entry in place.
//
// Entries with `connInfoKey: null` MUST be filtered out when building the
// client-pair sealed bundle (`buildClientPairBundle` handles this) — there
// is no usable K to ship to the requesting app yet.
export const VaultServerEntrySchema = z.object({
  addedAt: ISO_DATETIME,
  connInfoKey: BASE64URL.nullable(),
  displayName: z.string().min(1),
  serverPubKey: z.string().regex(/^[0-9a-f]{64}$/),
})

export type VaultServerEntry = z.infer<typeof VaultServerEntrySchema>

// Vault payload (plaintext, after VK-decrypt).
export const VaultPayloadSchema = z.object({
  masterPrivKey: BASE64URL,
  masterPubKey: z.string().regex(/^[0-9a-f]{64}$/),
  servers: z.array(VaultServerEntrySchema),
  userEncPrivKey: BASE64URL,
  userEncPubKey: z.string().regex(/^[0-9a-f]{64}$/),
  v: z.literal(1),
})

export type VaultPayload = z.infer<typeof VaultPayloadSchema>
