// Idempotent deploy steps for `npx @kldzj/sigillo self-host`.
//
// Downloads a prebuilt release bundle with two workers, the app and its own
// login provider (modules + assets + D1 migrations each, built by
// app/scripts/build-selfhost-bundle.ts), then provisions both on the
// customer's Cloudflare account via raw API calls:
//
//   D1 create → migrations (wrangler-compatible d1_migrations table) →
//   assets upload session → worker PUT (multipart modules + bindings) →
//   workers.dev subdomain → health check
//
// Every step is safe to re-run: re-running the command updates the deployed
// version, applies only new migrations, and never rotates BETTER_AUTH_SECRET
// (existing secrets are inherited via keep_bindings — rotating the secret
// would invalidate the derived AES encryption key and destroy stored secrets).

import { gunzipSync } from 'node:zlib'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { CfClient, type DeploymentState } from './cloudflare.js'

const GITHUB_RELEASES_URL = 'https://api.github.com/repos/kldzj/sigillo/releases?per_page=30'
export const BUNDLE_ASSET_NAME = 'sigillo-selfhost-bundle.json.gz'

// Keep in sync with app/scripts/build-selfhost-bundle.ts
export interface WorkerBundle {
  compatibilityDate: string
  compatibilityFlags: string[]
  mainModule: string
  modules: Record<string, string>
  assets: Record<string, { base64: string; hash: string; size: number; contentType: string }>
  migrations: Record<string, string>
}

export interface SelfhostBundle {
  formatVersion: 2
  version: string
  createdAt: string
  app: WorkerBundle
  provider: WorkerBundle
}

export interface ReleaseInfo {
  version: string
  url: string
}

/**
 * Resolve the latest release bundle straight from the fork's GitHub releases,
 * so a deploy never depends on anyone's hosted service.
 */
export async function fetchReleaseInfo(): Promise<ReleaseInfo> {
  const res = await fetch(GITHUB_RELEASES_URL, {
    headers: { 'User-Agent': 'sigillo-cli', Accept: 'application/vnd.github+json' },
  })
  if (!res.ok) {
    throw new Error(`Could not fetch releases from GitHub: ${res.status}`)
  }
  const releases = (await res.json()) as Array<{
    tag_name: string
    assets: Array<{ name: string; browser_download_url: string }>
  }>
  for (const release of releases) {
    const asset = release.assets.find((a) => a.name === BUNDLE_ASSET_NAME)
    if (asset && release.tag_name.startsWith('sigillo@')) {
      return { version: release.tag_name.slice('sigillo@'.length), url: asset.browser_download_url }
    }
  }
  throw new Error(`No release with a ${BUNDLE_ASSET_NAME} asset found — self-host bundles start at v0.13.0`)
}

export function parseBundle(gzipped: Buffer): SelfhostBundle {
  const bundle = JSON.parse(gunzipSync(gzipped).toString('utf-8')) as SelfhostBundle
  if (bundle.formatVersion !== 2) {
    throw new Error(`Unsupported bundle format ${bundle.formatVersion} — update the sigillo CLI`)
  }
  return bundle
}

export async function loadBundle(args: { bundlePath?: string; url?: string }): Promise<SelfhostBundle> {
  if (args.bundlePath) {
    return parseBundle(readFileSync(args.bundlePath))
  }
  const url = args.url ?? (await fetchReleaseInfo()).url
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`Bundle download failed: ${res.status} ${url}`)
  }
  return parseBundle(Buffer.from(await res.arrayBuffer()))
}

// ── Conflict detection ──────────────────────────────────────────────

/**
 * Fingerprint an existing worker: every Sigillo deployment has a `DB` D1
 * binding and a `PROVIDER_URL` plain_text binding. An unrelated worker that
 * happens to share the name must never be overwritten.
 */
export function isSigilloWorker(settings: { bindings?: Array<{ type: string; name: string }> } | null): boolean {
  const bindings = settings?.bindings ?? []
  return (
    bindings.some((b) => b.type === 'd1' && b.name === 'DB') &&
    bindings.some((b) => b.type === 'plain_text' && b.name === 'PROVIDER_URL')
  )
}

/** Same check for the login provider, which has BETTER_AUTH_URL instead of PROVIDER_URL. */
export function isSigilloProviderWorker(settings: { bindings?: Array<{ type: string; name: string }> } | null): boolean {
  const bindings = settings?.bindings ?? []
  return (
    bindings.some((b) => b.type === 'd1' && b.name === 'DB') &&
    bindings.some((b) => b.type === 'plain_text' && b.name === 'BETTER_AUTH_URL')
  )
}

// ── D1 ──────────────────────────────────────────────────────────────

/**
 * Find-or-create the D1 database. When adopting an existing database by name
 * (nothing in local state), verify it actually belongs to Sigillo before
 * applying migrations into it: an empty database is fine, a database whose
 * `d1_migrations` history starts with our first migration is ours, anything
 * else is an unrelated database that must not be touched. A Sigillo database
 * that already stores secrets is only adopted when the existing worker keeps
 * its secrets: new ones would make every stored secret unreadable.
 */
export async function ensureDatabase({ client, accountId, name, firstMigrationName, dataTable, secretsKept }: {
  client: CfClient
  accountId: string
  name: string
  firstMigrationName?: string
  /** a table whose rows only the old keys can read: secret_event (app) or jwks (provider) */
  dataTable: string
  /** false when this deploy generates new secrets (see secretsForDeploy) */
  secretsKept: boolean
}): Promise<string> {
  const existing = await client.findD1ByName(accountId, name)
  if (!existing) {
    const created = await client.createD1(accountId, name)
    return created.uuid
  }

  const [tablesResult] = await client.d1Query({
    accountId,
    databaseId: existing.uuid,
    sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%';",
  })
  const tables = (tablesResult?.results ?? []).map((row) => String(row.name))
  if (tables.length === 0) return existing.uuid // empty database — safe to adopt

  if (tables.includes('d1_migrations')) {
    const [appliedResult] = await client.d1Query({
      accountId,
      databaseId: existing.uuid,
      sql: 'SELECT name FROM d1_migrations ORDER BY id LIMIT 1;',
    })
    const first = appliedResult?.results?.[0]?.name
    if (first === undefined) return existing.uuid
    if (first === firstMigrationName) {
      if (secretsKept) return existing.uuid
      const [secretsResult] = await client.d1Query({
        accountId,
        databaseId: existing.uuid,
        sql: `SELECT 1 FROM ${dataTable} LIMIT 1;`,
      })
      if (!secretsResult?.results?.length) return existing.uuid
      throw new Error(
        `The D1 database "${name}" already stores secrets from an earlier deployment, but its worker and ` +
          `~/.sigillo/selfhost.json are gone, so new keys would leave them unreadable. Restore selfhost.json ` +
          'from the machine that deployed it, or re-run with --name <other-name> to start a new deployment.',
      )
    }
  }

  throw new Error(
    `A D1 database named "${name}" already exists on this account and does not look like a Sigillo database. ` +
      'Re-run with --name <other-name> to deploy under a different name.',
  )
}

/**
 * Apply pending migrations using the same `d1_migrations` bookkeeping table
 * wrangler uses, so `wrangler d1 migrations` stays interoperable.
 * Returns the names of newly applied migrations.
 */
export async function applyMigrations({ client, accountId, databaseId, migrations }: {
  client: CfClient
  accountId: string
  databaseId: string
  migrations: Record<string, string>
}): Promise<string[]> {
  await client.d1Query({
    accountId,
    databaseId,
    sql: 'CREATE TABLE IF NOT EXISTS d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);',
  })
  const [appliedResult] = await client.d1Query({ accountId, databaseId, sql: 'SELECT name FROM d1_migrations;' })
  const applied = new Set((appliedResult?.results ?? []).map((row) => String(row.name)))

  const appliedNow: string[] = []
  for (const name of Object.keys(migrations).sort()) {
    if (applied.has(name)) continue
    // Migration SQL + bookkeeping insert in ONE request so a transient
    // failure can't apply the schema without recording it (which would make
    // every subsequent run fail on duplicate DDL). Same approach as wrangler.
    const escapedName = name.replaceAll("'", "''")
    await client.d1Query({
      accountId,
      databaseId,
      sql: `${migrations[name]!}\nINSERT INTO d1_migrations (name) VALUES ('${escapedName}');`,
    })
    appliedNow.push(name)
  }
  return appliedNow
}

// ── Assets ──────────────────────────────────────────────────────────

/**
 * Upload static assets through the assets-upload-session flow and return the
 * completion JWT to attach to the worker upload. Unchanged files (matched by
 * hash) are skipped server-side, which is what makes re-runs fast.
 */
export async function syncAssets({ client, accountId, scriptName, worker, onProgress }: {
  client: CfClient
  accountId: string
  scriptName: string
  worker: WorkerBundle
  onProgress?: (uploaded: number, total: number) => void
}): Promise<string> {
  const manifest: Record<string, { hash: string; size: number }> = {}
  for (const [assetPath, asset] of Object.entries(worker.assets)) {
    manifest[assetPath] = { hash: asset.hash, size: asset.size }
  }
  const session = await client.createAssetsUploadSession({ accountId, scriptName, manifest })
  if (!session?.jwt) {
    throw new Error('Cloudflare did not return an assets upload session')
  }
  const buckets = session.buckets ?? []
  const totalFiles = buckets.flat().length
  if (totalFiles === 0) return session.jwt

  const byHash = new Map(Object.values(worker.assets).map((asset) => [asset.hash, asset]))
  let completionJwt = ''
  let uploaded = 0
  for (const bucket of buckets) {
    const formData = new FormData()
    for (const hash of bucket) {
      const asset = byHash.get(hash)
      if (!asset) throw new Error(`Upload session requested unknown asset hash ${hash}`)
      formData.append(hash, new File([asset.base64], hash, { type: asset.contentType }), hash)
    }
    const res = await client.uploadAssetsBucket({ accountId, uploadJwt: session.jwt, formData })
    uploaded += bucket.length
    onProgress?.(uploaded, totalFiles)
    if (res.jwt) completionJwt = res.jwt
  }
  if (!completionJwt) {
    throw new Error('Asset upload finished but Cloudflare returned no completion token')
  }
  return completionJwt
}

// ── Worker upload ───────────────────────────────────────────────────

export function generateBetterAuthSecret(): string {
  return randomBytes(32).toString('base64')
}

// Never rotate either secret. ENCRYPTION_KEY is the AES key for all stored
// secrets, and without it the app derives that key from BETTER_AUTH_SECRET.
// Existing worker → NEVER send secrets, inherit everything via keep_bindings
// (sending would delete user-added secrets and make stored data unreadable).
// New worker → reuse what the state file saved (worker deleted but D1
// survived), else generate both. Only a brand-new deployment gets its own
// ENCRYPTION_KEY: one that stored data before this keeps its derived key.
export function secretsForDeploy({ workerExists, saved }: {
  workerExists: boolean
  saved?: DeploymentState
}): { betterAuthSecret?: string; encryptionKey?: string } {
  if (workerExists) return {}
  if (saved) {
    return { betterAuthSecret: saved.betterAuthSecret ?? generateBetterAuthSecret(), encryptionKey: saved.encryptionKey }
  }
  // 32 random bytes, base64: the format the app's ENCRYPTION_KEY expects
  return { betterAuthSecret: generateBetterAuthSecret(), encryptionKey: randomBytes(32).toString('base64') }
}

// Same rule as secretsForDeploy, for the provider: never rotate its
// BETTER_AUTH_SECRET (it encrypts the JWT signing keys in its D1). An
// existing provider keeps everything via keep_bindings, a recreated one
// reuses what the state file saved, and only a brand-new one needs a Google
// OAuth client from the user.
export function providerSecretsForDeploy({ providerExists, saved, google }: {
  providerExists: boolean
  saved?: DeploymentState
  google?: { clientId: string; clientSecret: string }
}): Record<string, string> | undefined {
  if (providerExists) return undefined
  // A client passed explicitly wins, so a wrong saved one can be replaced
  const clientId = google?.clientId ?? saved?.googleClientId
  const clientSecret = google?.clientSecret ?? saved?.googleClientSecret
  if (!clientId || !clientSecret) {
    throw new Error('A new deployment needs a Google OAuth client ID and secret for its login provider')
  }
  return {
    BETTER_AUTH_SECRET: saved?.providerAuthSecret ?? generateBetterAuthSecret(),
    GOOGLE_CLIENT_ID: clientId,
    GOOGLE_CLIENT_SECRET: clientSecret,
  }
}

// The app fetches its provider, another worker on the same account's
// workers.dev subdomain, which Cloudflare refuses (error 1042) unless the
// fetch goes out over the public internet.
export function appCompatibilityFlags(flags: string[]): string[] {
  return flags.includes('global_fetch_strictly_public') ? flags : [...flags, 'global_fetch_strictly_public']
}

export async function uploadWorker(
  client: CfClient,
  args: {
    accountId: string
    scriptName: string
    worker: WorkerBundle
    databaseId: string
    assetsJwt: string
    /** plain-text bindings, e.g. PROVIDER_URL for the app or BETTER_AUTH_URL for the provider */
    vars: Record<string, string>
    /** set for a new worker only; an existing one keeps its secrets via keep_bindings */
    secrets?: Record<string, string>
    compatibilityFlags?: string[]
  },
): Promise<void> {
  const { worker } = args
  const bindings: Array<Record<string, unknown>> = [
    { type: 'd1', name: 'DB', id: args.databaseId },
    ...Object.entries(args.vars).map(([name, text]) => ({ type: 'plain_text', name, text })),
    ...Object.entries(args.secrets ?? {}).map(([name, text]) => ({ type: 'secret_text', name, text })),
  ]

  const metadata = {
    main_module: worker.mainModule,
    compatibility_date: worker.compatibilityDate,
    compatibility_flags: args.compatibilityFlags ?? worker.compatibilityFlags,
    bindings,
    // Never clobber secrets on update: they hold the keys to data already
    // stored, and rotating them would make it unreadable.
    ...(args.secrets ? {} : { keep_bindings: ['secret_text', 'secret_key'] }),
    placement: { mode: 'smart' },
    observability: { enabled: true },
    assets: { jwt: args.assetsJwt, config: {} },
  }

  const formData = new FormData()
  formData.append(
    'metadata',
    new File([JSON.stringify(metadata)], 'metadata.json', { type: 'application/json' }),
  )
  for (const [modulePath, base64] of Object.entries(worker.modules)) {
    formData.append(
      modulePath,
      new File([Buffer.from(base64, 'base64')], modulePath, { type: 'application/javascript+module' }),
      modulePath,
    )
  }
  await client.putWorker({ accountId: args.accountId, scriptName: args.scriptName, formData })
}

// ── workers.dev + health ────────────────────────────────────────────

export async function waitForHealth(url: string, path = '/health', timeoutMs = 60_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}${path}`)
      if (res.ok) return true
    } catch {
      // DNS for fresh workers.dev subdomains can lag — keep retrying
    }
    await new Promise((resolve) => setTimeout(resolve, 3000))
  }
  return false
}
