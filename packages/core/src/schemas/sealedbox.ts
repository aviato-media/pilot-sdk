import { z } from 'zod'

import { BASE64URL } from './primitives.js'

export const SealedBoxSchema = z.object({
  ct: BASE64URL,
  ephPub: BASE64URL,
  nonce: BASE64URL,
})

export type SealedBoxWire = z.infer<typeof SealedBoxSchema>
