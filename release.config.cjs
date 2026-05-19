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
        'for pkg in packages/core packages/client-sdk packages/client-react packages/server-sdk packages/tower-sdk; do',
        '  echo "::group::Publishing $pkg"',
        '  (cd "$pkg" && bun publish --access public --no-scripts)',
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
