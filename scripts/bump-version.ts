#!/usr/bin/env bun
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const packagesDir = join(root, 'packages')

const version = process.argv[2]
if (!version || !/^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(version)) {
  console.error('Usage: bun scripts/bump-version.ts <semver>')
  console.error('Example: bun scripts/bump-version.ts 0.2.0')
  process.exit(1)
}

const pkgPaths = readdirSync(packagesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => join(packagesDir, d.name, 'package.json'))

let changed = 0
for (const path of pkgPaths) {
  const pkg = JSON.parse(readFileSync(path, 'utf8')) as { name: string,
    version?: string,
    private?: boolean }
  // Skip private packages (e.g. integration-tests). Lockstep versioning is
  // only meaningful for the published packages; bumping a private workspace
  // package would just add noise to the release commit.
  if (pkg.private || pkg.version === undefined || pkg.version === version) {
    continue
  }
  const oldVersion = pkg.version
  pkg.version = version
  writeFileSync(path, `${JSON.stringify(pkg, null, 2) }\n`)
  console.log(`  ${pkg.name}: ${oldVersion} → ${version}`)
  changed++
}

if (changed === 0) {
  console.log(`All packages already at ${version}`)
} else {
  console.log(`\nBumped ${changed} package(s) to ${version}`)
}
