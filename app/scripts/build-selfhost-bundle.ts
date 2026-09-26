// Build the self-host deployment bundle for `npx sigillo self-host`.
//
// Packages two workers, the app and its own login provider, each as its vite
// build output (worker modules + static assets) plus its D1 migrations, into
// a single gzipped JSON file that the CLI can upload to a customer's
// Cloudflare account via raw API calls — no wrangler or node build step
// needed on the customer machine.
//
// Asset hashes are precomputed here with blake3 (same algorithm wrangler
// uses: blake3(base64Contents + extension).hex.slice(0, 32)) so the CLI
// needs no blake3 dependency.
//
// Run after `pnpm build` here and in provider/:  pnpm bundle:selfhost
// Output: dist/sigillo-selfhost-bundle.json.gz

import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from 'node:fs'
import { join, relative, extname } from 'node:path'
import { gzipSync } from 'node:zlib'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { hash: blake3hash } = require('blake3-wasm') as {
  hash: (input: string) => Buffer
}

const appDir = join(import.meta.dirname, '..')
const providerDir = join(appDir, '../provider')
const cliPackageJson = join(appDir, '../cli/package.json')
const outPath = join(appDir, 'dist/sigillo-selfhost-bundle.json.gz')

// Mirrors the shape consumed by cli/src/selfhost/deploy.ts — keep in sync.
interface WorkerBundle {
  compatibilityDate: string
  compatibilityFlags: string[]
  mainModule: string
  /** relative posix path -> base64 module content */
  modules: Record<string, string>
  /** "/path" -> asset entry (hash precomputed with blake3 like wrangler) */
  assets: Record<string, { base64: string; hash: string; size: number; contentType: string }>
  /** migration filename -> sql */
  migrations: Record<string, string>
}

interface SelfhostBundle {
  formatVersion: 2
  version: string
  createdAt: string
  app: WorkerBundle
  provider: WorkerBundle
}

const CONTENT_TYPES: Record<string, string> = {
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.css': 'text/css',
  '.html': 'text/html',
  '.json': 'application/json',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mp3': 'audio/mpeg',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.txt': 'text/plain',
  '.xml': 'application/xml',
  '.pdf': 'application/pdf',
  '.wasm': 'application/wasm',
  '.webmanifest': 'application/manifest+json',
  '.map': 'application/json',
  '.sh': 'application/x-sh',
}

function listFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { recursive: true, encoding: 'utf-8' })) {
    const abs = join(dir, entry)
    const st = statSync(abs)
    if (st.isFile()) out.push(entry.split('\\').join('/'))
  }
  return out
}

// Worker vars (PROVIDER_URL, BETTER_AUTH_URL) are not bundled: self-host
// sets them per deployment once it knows the workers.dev URLs.
function readWorker(label: string, distDir: string, migrationsDir: string): WorkerBundle {
  const rscDir = join(distDir, 'rsc')
  const clientDir = join(distDir, 'client')
  for (const dir of [rscDir, clientDir]) {
    if (!existsSync(dir)) {
      console.error(`missing ${dir} — run 'pnpm build' first`)
      process.exit(1)
    }
  }

  const wranglerConfig = JSON.parse(readFileSync(join(rscDir, 'wrangler.json'), 'utf-8'))

  // ── Worker modules: all .js files under dist/rsc ──────────────────
  const modules: Record<string, string> = {}
  for (const rel of listFiles(rscDir)) {
    if (!rel.endsWith('.js')) continue
    modules[rel] = readFileSync(join(rscDir, rel)).toString('base64')
  }
  console.log(`${label} worker modules: ${Object.keys(modules).length} (main: ${wranglerConfig.main})`)
  if (!modules[wranglerConfig.main]) {
    throw new Error(`main module ${wranglerConfig.main} not found in ${rscDir}`)
  }

  // ── Static assets: dist/client, honoring .assetsignore ────────────
  const ignorePatterns: string[] = []
  const assetsignorePath = join(clientDir, '.assetsignore')
  if (existsSync(assetsignorePath)) {
    for (const line of readFileSync(assetsignorePath, 'utf-8').split('\n')) {
      const trimmed = line.trim()
      if (trimmed && !trimmed.startsWith('#')) ignorePatterns.push(trimmed)
    }
  }
  const isIgnored = (rel: string) => {
    if (rel === '.assetsignore') return true
    // Our .assetsignore entries are simple filenames (wrangler.json, .dev.vars).
    // Match them against the full relative path and the basename.
    const base = rel.split('/').pop()!
    return ignorePatterns.some((p) => rel === p || base === p)
  }

  const assets: WorkerBundle['assets'] = {}
  for (const rel of listFiles(clientDir)) {
    if (isIgnored(rel)) continue
    const content = readFileSync(join(clientDir, rel))
    const base64 = content.toString('base64')
    const extension = extname(rel).substring(1)
    // Same hashing scheme as wrangler (packages/deploy-helpers hash.ts)
    const hash = blake3hash(base64 + extension).toString('hex').slice(0, 32)
    assets['/' + rel] = {
      base64,
      hash,
      size: content.length,
      contentType: CONTENT_TYPES[extname(rel)] ?? 'application/null',
    }
  }
  console.log(`${label} static assets: ${Object.keys(assets).length}`)

  // ── D1 migrations: flat .sql files ────────────────────────────────
  const migrations: Record<string, string> = {}
  for (const name of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
    migrations[name] = readFileSync(join(migrationsDir, name), 'utf-8')
  }
  console.log(`${label} migrations: ${Object.keys(migrations).length}`)

  return {
    compatibilityDate: wranglerConfig.compatibility_date,
    compatibilityFlags: wranglerConfig.compatibility_flags ?? [],
    mainModule: wranglerConfig.main,
    modules,
    assets,
    migrations,
  }
}

function main() {
  const version: string = JSON.parse(readFileSync(cliPackageJson, 'utf-8')).version
  console.log(`bundling self-host release v${version}`)

  const bundle: SelfhostBundle = {
    formatVersion: 2,
    version,
    createdAt: new Date().toISOString(),
    app: readWorker('app', join(appDir, 'dist'), join(appDir, '../db/drizzle-app')),
    provider: readWorker('provider', join(providerDir, 'dist'), join(providerDir, 'drizzle')),
  }

  const gz = gzipSync(Buffer.from(JSON.stringify(bundle)), { level: 9 })
  writeFileSync(outPath, gz)
  console.log(`wrote ${outPath} (${(gz.length / 1024 / 1024).toFixed(1)} MB gzipped)`)
}

main()
