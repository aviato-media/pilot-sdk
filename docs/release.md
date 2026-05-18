# Releasing Pilot SDK

All five publishable packages ship together at the same version. The git tag is the source of truth.

| Package | npm |
|---|---|
| `packages/core` | `@aviato-media/pilot-core` |
| `packages/client-sdk` | `@aviato-media/pilot-client-sdk` |
| `packages/client-react` | `@aviato-media/pilot-client-react` |
| `packages/server-sdk` | `@aviato-media/pilot-server-sdk` |
| `packages/tower-sdk` | `@aviato-media/pilot-tower-sdk` |

`packages/integration-tests` is private and never published.

## One-time setup

1. Create the `@aviato-media` npm org (if it doesn't exist) and confirm `ben@hutchins.co` has publish rights.
2. Generate an npm **Automation** token (granular access; scope to the `@aviato-media` org; permission "Read and write"). Avoid classic publish tokens — they bypass 2FA enforcement.
3. Add it to GitHub → repo Settings → Secrets and variables → Actions → **New repository secret** named `NPM_TOKEN`.
4. Confirm the repo's Actions permissions allow workflows to write `contents` (Settings → Actions → General → Workflow permissions).

## Cutting a release

```sh
# 1. From a clean main, bump all package versions in lockstep
bun run bump 0.2.0

# 2. Review the diff
git diff

# 3. Commit and tag
git add -A
git commit -m "chore: release v0.2.0"
git tag v0.2.0
git push --follow-tags
```

The push of the `v0.2.0` tag triggers `.github/workflows/ci.yml`:

1. **`verify`** runs (lint, typecheck, test, build) — same job that runs on every PR.
2. **`release`** runs only on the tag push, gated by `verify`:
   - Re-verifies every package.json `version` field matches the tag (catches "forgot to bump" mistakes).
   - Builds.
   - Runs `bun publish --access public` in each publishable package directory. `bun publish` rewrites `workspace:*` deps to the actual semver before packing — no manual rewriting needed.
   - Creates a GitHub Release with auto-generated notes from commits since the last tag.

## Failure recovery

- **First package published, later one failed:** the workflow is not transactional. Once a version is on npm, it cannot be republished (npm forbids overwriting). Bump to the next patch (`0.2.1`), fix the failure cause, and re-tag.
- **Wrong version published:** within 72 hours you can `npm unpublish @aviato-media/<pkg>@<version>`. After 72 hours, deprecate instead: `npm deprecate @aviato-media/<pkg>@<version> "broken — use <next>"`.
- **CI says "version does not match tag":** the bump script wasn't run or wasn't committed before tagging. Delete the tag (`git tag -d v0.2.0 && git push --delete origin v0.2.0`), bump correctly, re-tag.

## Adding a new publishable package

1. Add it under `packages/<name>/` with `publishConfig.access: public`, `license`, `repository.directory`, and `prepack: bun run build`.
2. Add its path to both shell loops in `.github/workflows/ci.yml` — the `Verify tag matches package versions` step **and** the `Publish packages` step. Both lists must stay in sync; only the publish loop actually ships, but a package missing from the verify loop will skip the version sanity check.
3. The bump script auto-discovers all `packages/*/package.json` — no change needed.
