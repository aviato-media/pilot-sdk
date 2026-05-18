# Pilot SDK — Documentation

This directory holds the protocol specifications and implementation plans that this monorepo's four SDKs implement.

> **Terminology note:** Most of these docs were written before the "Aviato Pilot's License" rename. They use the older name **"Aviato Identity"** throughout. The protocol bits (cryptographic recipes, wire schemas, endpoint shapes, flow diagrams) are unchanged — only the user-facing brand changed.
>
> Mapping: *Aviato Identity* → **Aviato Pilot's License**. The on-the-wire constants (`aviato-sealedbox-v1`, `aviato-server-conninfo-v1`, `aviato-vault-wrap/v1`, etc.) keep their original `aviato-*` prefixes for interop with already-deployed code.

## Specs

These are imported verbatim from their origin repos and serve as the source of truth for the wire contract. Where the in-tree code or these specs disagree, the **code is authoritative** — patches to align the docs welcome.

| Document | Origin | Purpose |
|---|---|---|
| [`aviato-identity-v2.md`](specs/aviato-identity-v2.md) | `aviato/docs/specs/` | **Top-level SSO spec.** Threat model, crypto primitives, key/data model, every flow (vault init, passkey add/remove, sign-in, server-link, cert renewal, revocation), Tower + media-server API surfaces, schemas, web UI surfaces. Start here. |
| [`aviato-identity-whitepaper.md`](specs/aviato-identity-whitepaper.md) | `aviato/docs/` | The original v1 whitepaper. Useful for historical context — v2 supersedes it. The v2 spec's §0 lists every divergence. |
| [`aviato-identity-conn-info.md`](specs/aviato-identity-conn-info.md) | `ato.software/` | **Server connection-info distribution.** How K (the per-server AES-GCM key) is generated, how `ServerConnInfo` is AEAD-sealed under K and published to Tower, how clients fetch + decrypt. Defines the SealedBox primitive and the AAD format. The single doc to read for K lifecycle. |
| [`aviato-identity-server-plan.md`](specs/aviato-identity-server-plan.md) | `aviato/docs/specs/` | **Media-server implementation plan.** Files to touch in `aviato/packages/server`, phased build order, web-side changes. Mirrors what `@aviato-media/pilot-server-sdk` packages up. |
| [`aviato-identity-tower-plan.md`](specs/aviato-identity-tower-plan.md) | `ato.software/` | **Tower implementation plan.** What Tower does in v2, files to touch in `ato.software/packages/tower-*`, end-to-end flow walkthroughs, the crypto recipe summary. |
| [`aviato-identity-tower-blueprint.md`](specs/aviato-identity-tower-blueprint.md) | `ato.software/` | **Tower architectural decisions.** Cryptography, PRF login flow, vault key in memory, endpoint naming deviations, data model, rate limiting, CORS, error envelope. Read alongside the Tower plan. |
| [`aviato-server-pairing-response.md`](specs/aviato-server-pairing-response.md) | `ato.software/` | **Pairing-response leg detail.** Deep dive on the server → user K-delivery sealed envelope: build, sign, verify, decrypt. |
| [`tower-api-identity-client-app.md`](specs/tower-api-identity-client-app.md) | `ato.software/packages/tower-api/docs/` | **`/api/identity/clients/*` reference.** The client-pair flow Tower exposes for third-party + first-party app pairing. |
| [`tower-api-identity-server-link.md`](specs/tower-api-identity-server-link.md) | `ato.software/packages/tower-api/docs/` | **`/api/identity/pairing/*` reference.** The server-link + server-sign-in flow Tower exposes for media-server registration. |
| [`tower-api-identity-web.md`](specs/tower-api-identity-web.md) | `ato.software/packages/tower-api/docs/` | **`/api/identity/vault/*` + `/api/identity/code/*` reference.** The vault CRUD + unified `/pair` code-resolve endpoints Tower-web drives. |

## How these map to the packages

```
                pilot-core         (crypto, schemas, assertion/cert/conn-info builders + verifiers)
                  ▲   ▲   ▲
       ┌──────────┘   │   └──────────┐
       │              │              │
pilot-client-sdk  pilot-server-sdk   pilot-tower-sdk
       │              │              │
       ▼              ▼              ▼
   Aviato Web,    Aviato media   Tower web
   Afterburner,   server,        (ato.software)
   3rd-party      3rd-party
   apps           Aviato-protocol
                  servers
```

- `pilot-core` implements every byte of every cryptographic recipe in `aviato-identity-conn-info.md §9` and every schema in `aviato-identity-v2.md §6` + `aviato-identity-tower-plan.md "New schemas"`.
- `pilot-client-sdk` implements the client-app side of `aviato-identity-v2.md §4.4` (client-pair sign-in) + `§4.8` (cert renewal) + `aviato-identity-conn-info.md §5` (web client conn-info fetch + decrypt).
- `pilot-server-sdk` implements the media-server side of `aviato-identity-server-plan.md` + `aviato-identity-conn-info.md §4` (publish K, pairing-response leg, direct K delivery).
- `pilot-tower-sdk` implements the Tower-web browser side of `aviato-identity-tower-plan.md §5` (vault, passkey-PRF, pairing approval) + `aviato-identity-tower-blueprint.md` (vault structure, PRF login flow).

## Drift policy

When the protocol changes:

1. Update the relevant spec doc here.
2. Update `pilot-core` (schemas + crypto + builders/verifiers).
3. The integration test in `packages/integration-tests/__tests__/full-handshake.test.ts` exercises every cross-package contract — it will fail loudly if a change breaks compatibility.
4. Bump the relevant `v: 1 as const` literals + HKDF/AAD info strings to `v2` for breaking changes; non-breaking additions can keep the same version.
