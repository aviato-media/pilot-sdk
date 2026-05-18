// Primitive Zod regex-validated string types reused across schemas.

import { z } from 'zod'

export const HEX_32 = z.string().regex(/^[0-9a-f]{64}$/, 'must be 64 hex chars (32 bytes, lowercase)')
export const HEX_ANY = z.string().regex(/^[0-9a-f]+$/, 'must be lowercase hex')
export const BASE64URL = z.string().regex(/^[A-Za-z0-9_-]+$/, 'must be base64url, no padding')
export const UUID = z.uuid()
export const ISO_DATETIME = z.string().min(1)
export const UNIX_SEC = z.number().int()
