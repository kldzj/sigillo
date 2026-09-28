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
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { CfClient, CloudflareApiError, type DeploymentState } from './cloudflare.js'

const GITHUB_RELEASES_URL = 'https://api.github.com/repos/kldzj/sigillo/releases'
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

// The bundle this CLI deploys: its version, and the SHA-256 that CI recorded
// in dist/selfhost-bundle.json when it built the bundle and staged this npm
// package. Absent when the CLI runs from a local build.
export interface ExpectedBundle {
  version: string
  sha256: string
}

// Only a missing file means a local build. One that is there but unreadable
// stops the run: deploying unchecked must never be how a damaged package fails.
export function readExpectedBundle(file: URL = new URL('../selfhost-bundle.json', import.meta.url)): ExpectedBundle | null {
  let text: string
  try {
    text = readFileSync(file, 'utf-8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  let expected: Partial<ExpectedBundle> | null = null
  try {
    expected = JSON.parse(text)
  } catch {
    // Reported below, like a file without the fields
  }
  if (typeof expected?.version !== 'string' || !expected.version || typeof expected.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expected.sha256)) {
    throw new Error(`${fileURLToPath(file)} has no valid bundle version and SHA-256, so the bundle can't be checked: reinstall @kldzj/sigillo`)
  }
  return { version: expected.version, sha256: expected.sha256 }
}

type GithubRelease = { tag_name: string; assets: Array<{ name: string; browser_download_url: string }> }

/**
 * Resolve a release bundle straight from the fork's GitHub releases, so a
 * deploy never depends on anyone's hosted service: the release of this CLI's
 * own version, or with none given, the latest one.
 */
export async function fetchReleaseInfo(version?: string): Promise<ReleaseInfo> {
  const res = await fetch(version ? `${GITHUB_RELEASES_URL}/tags/sigillo@${version}` : `${GITHUB_RELEASES_URL}?per_page=30`, {
    headers: { 'User-Agent': 'sigillo-cli', Accept: 'application/vnd.github+json' },
  })
  if (!res.ok) {
    throw new Error(version && res.status === 404
      ? `No published release sigillo@${version} on GitHub yet`
      : `Could not fetch releases from GitHub: ${res.status}`)
  }
  const releases = version ? [(await res.json()) as GithubRelease] : (await res.json()) as GithubRelease[]
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

// The bundle holds the code that runs with the deployment's secrets, so a
// published CLI deploys only the bundle it was released with: the one whose
// SHA-256 it carries, from wherever it came.
export function checkBundle(gzipped: Buffer, expected: ExpectedBundle | null): SelfhostBundle {
  if (expected) {
    const sha256 = createHash('sha256').update(gzipped).digest('hex')
    if (sha256 !== expected.sha256) {
      throw new Error(`This bundle isn't the one @kldzj/sigillo ${expected.version} was released with (SHA-256 ${sha256}, expected ${expected.sha256}), so nothing was deployed`)
    }
  }
  const bundle = parseBundle(gzipped)
  if (expected && bundle.version !== expected.version) {
    throw new Error(`The bundle is v${bundle.version}, but this CLI deploys v${expected.version}`)
  }
  return bundle
}

export async function loadBundle(args: { bundlePath?: string; url?: string; expected: ExpectedBundle | null }): Promise<SelfhostBundle> {
  if (args.bundlePath) return checkBundle(readFileSync(args.bundlePath), args.expected)
  const url = args.url ?? (await fetchReleaseInfo(args.expected?.version)).url
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`Bundle download failed: ${res.status} ${url}`)
  }
  return checkBundle(Buffer.from(await res.arrayBuffer()), args.expected)
}

// Whether a is an older version than b, both like 0.15.2
export function isOlderVersion(a: string, b: string): boolean {
  const parts = (v: string) => v.split('-')[0]!.split('.').map((n) => Number.parseInt(n, 10) || 0)
  const [pa, pb] = [parts(a), parts(b)]
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0)
  }
  return false
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
 * else is an unrelated database that must not be touched.
 */
export async function ensureDatabase({ client, accountId, name, firstMigrationName }: {
  client: CfClient
  accountId: string
  name: string
  firstMigrationName?: string
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
    if (first === undefined || first === firstMigrationName) return existing.uuid
  }

  throw new Error(
    `A D1 database named "${name}" already exists on this account and does not look like a Sigillo database. ` +
      'Re-run with --name <other-name> to deploy under a different name.',
  )
}

/**
 * Refuse to deploy a freshly generated BETTER_AUTH_SECRET onto a database that
 * already stores secrets: they were encrypted with a key that is gone (worker
 * deleted, and the secret is not in selfhost.json), so every one of them
 * would silently become unreadable. Covers adopted-by-name databases and
 * databases remembered in state whose worker was adopted without its secret.
 */
export async function assertNoStoredSecrets({ client, accountId, databaseId, dataTable = 'secret_event' }: {
  client: CfClient
  accountId: string
  databaseId: string
  /** secret_event for the app, jwks for its login provider */
  dataTable?: string
}): Promise<void> {
  const [tablesResult] = await client.d1Query({
    accountId,
    databaseId,
    sql: `SELECT name FROM sqlite_master WHERE type='table' AND name = '${dataTable}';`,
  })
  if (!tablesResult?.results?.length) return
  const [secretsResult] = await client.d1Query({ accountId, databaseId, sql: `SELECT 1 AS found FROM ${dataTable} LIMIT 1;` })
  if (!secretsResult?.results?.length) return
  throw new Error(
    'This D1 database already stores secrets, but its worker is gone and ~/.sigillo/selfhost.json has no saved ' +
      'BETTER_AUTH_SECRET for it. Deploying would generate a new secret and make every stored secret unreadable. ' +
      'Restore the original ~/.sigillo/selfhost.json and re-run, or deploy under --name <other-name>.',
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

/**
 * Secrets to bind on this deploy. A new deployment gets its own
 * ENCRYPTION_KEY, separate from the BETTER_AUTH_SECRET that signs sessions:
 * SIGILLO_ENCRYPTION_KEY if set, a random key otherwise. Neither is ever
 * rotated, since a new key would make every stored secret unreadable, so a
 * deployment without an ENCRYPTION_KEY keeps deriving it from BETTER_AUTH_SECRET.
 * Returns {} for an existing worker (inherit everything via keep_bindings).
 */
export function resolveDeploySecrets({ workerExists, saved, encryptionKeyEnv }: {
  workerExists: boolean
  saved?: { betterAuthSecret?: string; encryptionKey?: string }
  encryptionKeyEnv?: string
}): { betterAuthSecret?: string; encryptionKey?: string; generated?: boolean } {
  const encryptionKey = encryptionKeyEnv?.trim() || undefined
  if (encryptionKey && Buffer.from(encryptionKey, 'base64').length !== 32) {
    throw new Error('SIGILLO_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)')
  }
  const isNew = !workerExists && !saved?.betterAuthSecret
  if (!isNew && encryptionKey && encryptionKey !== saved?.encryptionKey) {
    throw new Error(
      'SIGILLO_ENCRYPTION_KEY can only be set on the first deploy. Changing the key of an existing ' +
        'deployment would make its stored secrets unreadable. Unset it to update.',
    )
  }
  if (workerExists) return {}
  if (!isNew) return { betterAuthSecret: saved?.betterAuthSecret, encryptionKey: saved?.encryptionKey }
  return {
    betterAuthSecret: generateBetterAuthSecret(),
    encryptionKey: encryptionKey ?? randomBytes(32).toString('base64'),
    generated: true,
  }
}

// ALLOWED_USERS as self-host stores it: lowercase, no spaces or repeats, and
// only entries the app can match, an email address or a domain.
export function normalizeAllowedUsers(input: string): string {
  const entries = [...new Set(input.split(/[\s,]+/).map((entry) => entry.toLowerCase()).filter(Boolean))]
  const domain = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
  const invalid = entries.filter((entry) => {
    const at = entry.lastIndexOf('@')
    return at === -1 ? !domain.test(entry) : at === 0 || !domain.test(entry.slice(at + 1))
  })
  if (invalid.length > 0) throw new Error(`Not an email address or a domain: ${invalid.join(', ')}`)
  return entries.join(',')
}

// A worker that already exists keeps its secrets (keep_bindings), so a
// changed list is set or removed on its own. A new worker gets it with its
// first upload instead.
export async function updateAllowedUsersSecret({ client, accountId, scriptName, list, saved }: {
  client: CfClient
  accountId: string
  scriptName: string
  list: string
  /** what the last run set, unset for deployments older than the list */
  saved?: string
}): Promise<void> {
  if (list === (saved ?? '')) return
  if (list) {
    await client.putWorkerSecret({ accountId, scriptName, name: 'ALLOWED_USERS', text: list })
    return
  }
  await client.deleteWorkerSecret({ accountId, scriptName, name: 'ALLOWED_USERS' }).catch((error) => {
    // Removed by hand already: nothing left to do
    if (!(error instanceof CloudflareApiError && error.status === 404)) throw error
  })
}

// Same rule as resolveDeploySecrets, for the provider: never rotate its
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
