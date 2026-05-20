// Monorepo release config. semantic-release is the single source of truth for
// the synced version across all publishable packages. It computes the next
// version from conventional commits on `main`, then `@semantic-release/exec`
// drives `bump-version.ts` to write that version into every package.json and
// runs the per-package `bun publish` loop.
//
// `bun publish` (not `npm publish`) is required: it rewrites `workspace:*` deps
// to the resolved semver before packing. `--no-scripts` skips `prepack` so we
// ship the dist built and verified by the `prepare` step, not a fresh rebuild.
//
// `bun publish` resolves `workspace:*` against the version recorded in
// `bun.lock`, not the current `package.json` — and `bun install` (without
// removing the lockfile) does not re-sync workspace versions after a bump.
// So the prepare sequence is: bump package.jsons → delete lockfile → reinstall
// → build. `bun.lock` is then committed alongside the package.json changes so
// the published deps point at the actual released version.
//
// `bun publish` on a dependent package verifies that the rewritten workspace
// dep (e.g. `@aviato-media/pilot-core@1.1.0`) is resolvable from the registry
// before allowing the publish to proceed. npm read-replica propagation lags
// the write by several seconds, so the publish loop polls `npm view` between
// packages — without the wait, every release after `packages/core` 404s.

/** @type {import('semantic-release').GlobalConfig} */
module.exports = {
  branches: ['main'],
  plugins: [
    ['@semantic-release/commit-analyzer', { preset: 'conventionalcommits' }],
    ['@semantic-release/release-notes-generator', { preset: 'conventionalcommits' }],
    ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md' }],
    ['@semantic-release/exec', {
      prepareCmd: 'bun scripts/bump-version.ts ${nextRelease.version} && rm -f bun.lock && bun install && bun run build',
      publishCmd: [
        'set -e',
        'VERSION="${nextRelease.version}"',
        'for pkg in packages/core packages/client-sdk packages/client-react packages/server-sdk packages/tower-sdk; do',
        '  echo "::group::Publishing $pkg"',
        '  (cd "$pkg" && bun publish --access public --no-scripts)',
        '  pkgname=$(cd "$pkg" && node -p "require(\'./package.json\').name")',
        '  echo "Waiting for npm to acknowledge $pkgname@$VERSION..."',
        '  for i in $(seq 1 60); do',
        '    if npm view "$pkgname@$VERSION" version --prefer-online >/dev/null 2>&1; then break; fi',
        '    sleep 3',
        '  done',
        '  echo "::endgroup::"',
        'done',
      ].join('\n'),
    }],
    ['@semantic-release/git', {
      assets: ['packages/*/package.json', 'bun.lock', 'CHANGELOG.md'],
      message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
    }],
    ['@semantic-release/github', {}],
  ],
}
