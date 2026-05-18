// HTTP client for Tower endpoints used by the media server.
//
// The server registers once at boot, then drives a pairing flow per link
// attempt: register → poll → response (sealed K back to user).

import type {
  MasterSignedAssertionEnvelope,
  PairingRegisterRequest,
  PairingRegisterResponse,
  PairingResponsePayload,
  ServerConnInfoPublish,
  ServerLinkPollResponse,
} from '@aviato-media/pilot-core'
import {
  PairingRegisterResponseSchema,
  ServerLinkPollResponseSchema,
} from '@aviato-media/pilot-core'

// Re-export the canonical type so callers can import it from this SDK
// directly if they prefer (e.g. when wiring up the route in their host
// framework). The source of truth is pilot-core/schemas/pairing.ts.
export type { PairingRegisterRequest }

export class TowerHttpError extends Error {
  constructor (
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message)
    this.name = 'TowerHttpError'
  }
}

export interface TowerClientOptions {
  /** Base URL, e.g. "https://tower.aviato.media". No trailing slash. */
  readonly baseUrl: string
  /** Server-registration bearer obtained at boot. */
  readonly bearer: string
  /** Optional fetch override (tests). */
  readonly fetch?: typeof globalThis.fetch
}

export class TowerClient {
  private readonly baseUrl: string
  private readonly fetchImpl: typeof globalThis.fetch
  private readonly bearer: string

  constructor (opts: TowerClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
    this.bearer = opts.bearer
  }

  async pairingRegister (req: PairingRegisterRequest): Promise<PairingRegisterResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/pairing/register`, {
      body: JSON.stringify(req),
      headers: this.headers({ 'content-type': 'application/json' }),
      method: 'POST',
    })
    return parseOrThrow(res, PairingRegisterResponseSchema, 'pairingRegister')
  }

  async pollPairing (requestId: string): Promise<ServerLinkPollResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/pairing/${encodeURIComponent(requestId)}`, {
      headers: this.headers(),
    })
    return parseOrThrow(res, ServerLinkPollResponseSchema, 'pollPairing')
  }

  async postPairingResponse (
    requestId: string,
    payload: PairingResponsePayload,
  ): Promise<void> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/pairing/${encodeURIComponent(requestId)}/response`, {
      body: JSON.stringify(payload),
      headers: this.headers({ 'content-type': 'application/json' }),
      method: 'POST',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as unknown
      throw new TowerHttpError(`postPairingResponse: ${res.status}`, res.status, body)
    }
  }

  async publishServerConnInfo (body: ServerConnInfoPublish): Promise<void> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/server-conninfo`, {
      body: JSON.stringify(body),
      headers: this.headers({ 'content-type': 'application/json' }),
      method: 'POST',
    })
    if (!res.ok) {
      const errBody = await res.json().catch(() => null) as unknown
      throw new TowerHttpError(`publishServerConnInfo: ${res.status}`, res.status, errBody)
    }
  }

  private headers (extra: Record<string, string> = {}): HeadersInit {
    return {
      authorization: `Bearer ${this.bearer}`,
      ...extra,
    }
  }
}

/** Re-export — handy when callers want to thread an assertion envelope through. */
export type { MasterSignedAssertionEnvelope }

async function parseOrThrow<T> (
  res: Response,
  schema: { safeParse: (v: unknown) => { success: boolean,
    data?: T,
    error?: unknown } },
  op: string,
): Promise<T> {
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    // empty / non-JSON
  }
  if (!res.ok) {
    throw new TowerHttpError(`${op}: ${res.status}`, res.status, body)
  }
  const parsed = schema.safeParse(body)
  if (!parsed.success || parsed.data === undefined) {
    throw new TowerHttpError(`${op}: response shape invalid`, res.status, body)
  }
  return parsed.data
}
