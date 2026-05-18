// HTTP client for Tower endpoints used by client apps.
//
// Tower is the only external network surface this SDK talks to before a
// successful pair; after that, all server connections are direct.

import type {
  ClientPairBeginResponse,
  ClientPairPollResponse,
  RenewClientResponse,
  ServerConnInfoRecord,
} from '@aviato-media/pilot-core'
import {
  ClientPairBeginResponseSchema,
  ClientPairPollResponseSchema,
  RenewClientResponseSchema,
  ServerConnInfoRecordSchema,
} from '@aviato-media/pilot-core'

export class TowerApiError extends Error {
  constructor (
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message)
    this.name = 'TowerApiError'
  }
}

export interface TowerClientOptions {
  /** Base URL, e.g. "https://tower.aviato.media". No trailing slash. */
  readonly baseUrl: string
  /** Optional fetch override (testing). */
  readonly fetch?: typeof globalThis.fetch
}

export interface ClientPairBeginRequest {
  readonly appId: string
  readonly deviceName: string
  /** base64url 32B (Ed25519 public key — the SDK's per-device signing key). */
  readonly clientPubKey: string
  /** base64url 32B (X25519 public key — the SDK's per-device encryption key). */
  readonly clientEncPubKey: string
}

export class TowerClient {
  private readonly baseUrl: string
  private readonly fetchImpl: typeof globalThis.fetch

  constructor (opts: TowerClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  async clientPairBegin (req: ClientPairBeginRequest): Promise<ClientPairBeginResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/clients/pair/begin`, {
      body: JSON.stringify(req),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    })
    return parseOrThrow(res, ClientPairBeginResponseSchema, 'clientPairBegin')
  }

  async clientPairPoll (requestId: string): Promise<ClientPairPollResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/clients/pair/${encodeURIComponent(requestId)}`)
    return parseOrThrow(res, ClientPairPollResponseSchema, 'clientPairPoll')
  }

  async renewClient (req: {
    clientId: string
    cert: { payload: string,
      sig: string }
  }): Promise<RenewClientResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/clients/${encodeURIComponent(req.clientId)}/renew`, {
      body: JSON.stringify({ cert: req.cert }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    })
    return parseOrThrow(res, RenewClientResponseSchema, 'renewClient')
  }

  /** Fetch ServerConnInfo by hash. Returns null on 404 (server hasn't reported in 72h). */
  async fetchServerConnInfo (hash: string): Promise<ServerConnInfoRecord | null> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/identity/server-conninfo/${encodeURIComponent(hash)}`)
    if (res.status === 404) {
      return null
    }
    return parseOrThrow(res, ServerConnInfoRecordSchema, 'fetchServerConnInfo')
  }
}

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
    throw new TowerApiError(`${op}: ${res.status}`, res.status, body)
  }
  const parsed = schema.safeParse(body)
  if (!parsed.success || parsed.data === undefined) {
    throw new TowerApiError(`${op}: response shape invalid`, res.status, body)
  }
  return parsed.data
}
