// Unit tests for the self-host command's pure pieces: wrangler TOML
// round-trip, bundle parsing, and the token template deep link.
// The full deploy path is exercised manually/e2e against a real Cloudflare
// account (network + credentials required), not here.

import { gzipSync } from 'node:zlib'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { parseWranglerToml, serializeWranglerToml, TOKEN_TEMPLATE_URL, type CfClient, type DeploymentState } from '../src/selfhost/cloudflare.js'
import {
  appCompatibilityFlags, ensureDatabase, fetchReleaseInfo, isSigilloProviderWorker, parseBundle, providerSecretsForDeploy,
  secretsForDeploy, uploadWorker,
  type SelfhostBundle, type WorkerBundle,
} from '../src/selfhost/deploy.js'

describe('parseWranglerToml', () => {
  const sample = [
    'oauth_token = "tok_abc123"',
    'expiration_time = "2026-01-01T00:00:00.000Z"',
    'refresh_token = "rt_xyz789"',
    'scopes = [ "account:read", "workers:write", "offline_access" ]',
    '',
  ].join('\n')

  test('extracts tokens and scopes', () => {
    expect(parseWranglerToml(sample)).toMatchInlineSnapshot(`
      {
        "expiration_time": "2026-01-01T00:00:00.000Z",
        "oauth_token": "tok_abc123",
        "refresh_token": "rt_xyz789",
        "scopes": [
          "account:read",
          "workers:write",
          "offline_access",
        ],
      }
    `)
  })

  test('round-trips through serialize', () => {
    const parsed = parseWranglerToml(sample)!
    expect(parseWranglerToml(serializeWranglerToml(parsed))).toEqual(parsed)
  })

  test('handles multiline scopes arrays', () => {
    const multiline = sample.replace(
      /scopes = .*/,
      'scopes = [\n  "account:read",\n  "d1:write"\n]',
    )
    expect(parseWranglerToml(multiline)?.scopes).toEqual(['account:read', 'd1:write'])
  })

  test('returns null when tokens are missing', () => {
    expect(parseWranglerToml('api_token = "x"')).toBeNull()
  })
})

describe('parseBundle', () => {
  const worker: WorkerBundle = {
    compatibilityDate: '2026-04-16',
    compatibilityFlags: ['nodejs_compat'],
    mainModule: 'index.js',
    modules: { 'index.js': Buffer.from('export default {}').toString('base64') },
    assets: {
      '/index.html': {
        base64: Buffer.from('<html/>').toString('base64'),
        hash: 'a'.repeat(32),
        size: 7,
        contentType: 'text/html',
      },
    },
    migrations: { '0001_initial.sql': 'CREATE TABLE t(id);' },
  }
  const bundle: SelfhostBundle = {
    formatVersion: 2,
    version: '0.14.0',
    createdAt: '2026-01-01T00:00:00.000Z',
    app: worker,
    provider: { ...worker, migrations: { '0001_initial.sql': 'CREATE TABLE u(id);' } },
  }

  test('round-trips a gzipped bundle', () => {
    const parsed = parseBundle(gzipSync(Buffer.from(JSON.stringify(bundle))))
    expect(parsed).toEqual(bundle)
  })

  test('rejects bundles without a provider worker', () => {
    const v1 = gzipSync(Buffer.from(JSON.stringify({ ...worker, formatVersion: 1, version: '0.13.0' })))
    expect(() => parseBundle(v1)).toThrow('Unsupported bundle format 1')
  })

  test('rejects unknown format versions', () => {
    const bad = gzipSync(Buffer.from(JSON.stringify({ ...bundle, formatVersion: 99 })))
    expect(() => parseBundle(bad)).toThrowErrorMatchingInlineSnapshot(
      `[Error: Unsupported bundle format 99 — update the sigillo CLI]`,
    )
  })
})

describe('TOKEN_TEMPLATE_URL', () => {
  test('encodes the exact permission groups', () => {
    const url = new URL(TOKEN_TEMPLATE_URL)
    expect(url.hostname).toBe('dash.cloudflare.com')
    const keys = JSON.parse(url.searchParams.get('permissionGroupKeys')!)
    expect(keys).toMatchInlineSnapshot(`
      [
        {
          "key": "account_settings",
          "type": "read",
        },
        {
          "key": "user_details",
          "type": "read",
        },
        {
          "key": "memberships",
          "type": "read",
        },
        {
          "key": "workers_scripts",
          "type": "edit",
        },
        {
          "key": "d1",
          "type": "edit",
        },
        {
          "key": "workers_routes",
          "type": "edit",
        },
        {
          "key": "zone",
          "type": "read",
        },
      ]
    `)
  })
})

describe('secretsForDeploy', () => {
  const saved = (fields: Partial<DeploymentState>): DeploymentState => ({
    accountId: 'acc', workerName: 'sigillo', databaseId: 'db', ...fields,
  })

  test('a new deployment gets its own ENCRYPTION_KEY, separate from BETTER_AUTH_SECRET', () => {
    const { betterAuthSecret, encryptionKey } = secretsForDeploy({ workerExists: false })
    expect(Buffer.from(encryptionKey!, 'base64')).toHaveLength(32)
    expect(encryptionKey).not.toBe(betterAuthSecret)
  })

  test('an existing worker keeps the secrets it has, nothing is sent', () => {
    expect(secretsForDeploy({ workerExists: true, saved: saved({ betterAuthSecret: 's', encryptionKey: 'k' }) })).toEqual({})
  })

  test('a recreated worker reuses the saved keys, so stored data stays readable', () => {
    expect(secretsForDeploy({ workerExists: false, saved: saved({ betterAuthSecret: 's', encryptionKey: 'k' }) }))
      .toEqual({ betterAuthSecret: 's', encryptionKey: 'k' })
  })

  test('a deployment from before ENCRYPTION_KEY keeps its derived key', () => {
    expect(secretsForDeploy({ workerExists: false, saved: saved({ betterAuthSecret: 's' }) }))
      .toEqual({ betterAuthSecret: 's', encryptionKey: undefined })
  })
})

describe('uploadWorker', () => {
  const worker = {
    mainModule: 'index.js',
    compatibilityDate: '2026-04-16',
    compatibilityFlags: ['nodejs_compat'],
    modules: { 'index.js': Buffer.from('export default {}').toString('base64') },
  } as unknown as WorkerBundle
  const upload = async (args: { vars: Record<string, string>; secrets?: Record<string, string> }) => {
    let metadata: { bindings: unknown[]; keep_bindings?: string[] } | undefined
    const client = {
      async putWorker({ formData }: { formData: FormData }) {
        metadata = JSON.parse(await (formData.get('metadata') as File).text())
      },
    } as unknown as CfClient
    await uploadWorker(client, { accountId: 'acc', scriptName: 'sigillo', worker, databaseId: 'db', assetsJwt: 'jwt', ...args })
    return metadata!
  }

  test('a new worker gets its vars and secrets', async () => {
    const metadata = await upload({ vars: { PROVIDER_URL: 'https://sigillo-auth.example.workers.dev' }, secrets: { BETTER_AUTH_SECRET: 's', ENCRYPTION_KEY: 'k' } })
    expect(metadata.bindings).toContainEqual({ type: 'plain_text', name: 'PROVIDER_URL', text: 'https://sigillo-auth.example.workers.dev' })
    expect(metadata.bindings).toContainEqual({ type: 'secret_text', name: 'ENCRYPTION_KEY', text: 'k' })
    expect(metadata.keep_bindings).toBeUndefined()
  })

  test('an existing worker keeps the secrets it has', async () => {
    const metadata = await upload({ vars: { BETTER_AUTH_URL: 'https://sigillo-auth.example.workers.dev' } })
    expect(metadata.bindings).not.toContainEqual(expect.objectContaining({ type: 'secret_text' }))
    expect(metadata.keep_bindings).toEqual(['secret_text', 'secret_key'])
  })
})

describe('isSigilloProviderWorker', () => {
  test('recognizes a login provider by its DB and BETTER_AUTH_URL bindings', () => {
    expect(isSigilloProviderWorker({ bindings: [{ type: 'd1', name: 'DB' }, { type: 'plain_text', name: 'BETTER_AUTH_URL' }] })).toBe(true)
    expect(isSigilloProviderWorker({ bindings: [{ type: 'd1', name: 'DB' }, { type: 'plain_text', name: 'PROVIDER_URL' }] })).toBe(false)
    expect(isSigilloProviderWorker(null)).toBe(false)
  })
})

describe('appCompatibilityFlags', () => {
  test('lets the app reach its provider, another worker on the same account', () => {
    expect(appCompatibilityFlags(['nodejs_compat'])).toEqual(['nodejs_compat', 'global_fetch_strictly_public'])
    expect(appCompatibilityFlags(['nodejs_compat', 'global_fetch_strictly_public'])).toEqual(['nodejs_compat', 'global_fetch_strictly_public'])
  })
})

describe('providerSecretsForDeploy', () => {
  const saved = (fields: Partial<DeploymentState>): DeploymentState => ({
    accountId: 'acc', workerName: 'sigillo', databaseId: 'db', ...fields,
  })
  const google = { clientId: 'client-id', clientSecret: 'client-secret' }

  test('an existing provider keeps the secrets it has, nothing is sent', () => {
    expect(providerSecretsForDeploy({ providerExists: true, saved: saved({ providerAuthSecret: 'p' }), google })).toBeUndefined()
  })

  test('a recreated provider reuses its saved secret and Google client', () => {
    expect(providerSecretsForDeploy({
      providerExists: false,
      saved: saved({ providerAuthSecret: 'p', googleClientId: 'saved-id', googleClientSecret: 'saved-secret' }),
    })).toEqual({ BETTER_AUTH_SECRET: 'p', GOOGLE_CLIENT_ID: 'saved-id', GOOGLE_CLIENT_SECRET: 'saved-secret' })
  })

  test('a Google client passed explicitly replaces the saved one', () => {
    expect(providerSecretsForDeploy({
      providerExists: false,
      saved: saved({ providerAuthSecret: 'p', googleClientId: 'saved-id', googleClientSecret: 'saved-secret' }),
      google,
    })).toEqual({ BETTER_AUTH_SECRET: 'p', GOOGLE_CLIENT_ID: 'client-id', GOOGLE_CLIENT_SECRET: 'client-secret' })
  })

  test('a new provider gets its own auth secret and the given Google client', () => {
    const secrets = providerSecretsForDeploy({ providerExists: false, google })!
    expect(Buffer.from(secrets.BETTER_AUTH_SECRET!, 'base64')).toHaveLength(32)
    expect(secrets).toMatchObject({ GOOGLE_CLIENT_ID: 'client-id', GOOGLE_CLIENT_SECRET: 'client-secret' })
  })

  test('a new provider without a Google client is refused', () => {
    expect(() => providerSecretsForDeploy({ providerExists: false })).toThrow(/Google OAuth client/)
  })
})

describe('ensureDatabase', () => {
  // A D1 named like ours that already holds a Sigillo deployment with stored secrets
  const queries: string[] = []
  const fakeClient = ({ secretRows }: { secretRows: number }) => ({
    async findD1ByName() { return { uuid: 'db-1' } },
    async d1Query({ sql }: { sql: string }) {
      queries.push(sql)
      if (sql.includes('sqlite_master')) return [{ results: [{ name: 'd1_migrations' }, { name: 'secret_event' }] }]
      if (sql.includes('d1_migrations')) return [{ results: [{ name: '0001_initial.sql' }] }]
      return [{ results: Array.from({ length: secretRows }, () => ({ 1: 1 })) }]
    },
  }) as unknown as CfClient
  const args = { accountId: 'acc', name: 'sigillo-db', firstMigrationName: '0001_initial.sql', dataTable: 'secret_event' }

  test('refuses to put new secrets in front of stored ones', async () => {
    await expect(ensureDatabase({ client: fakeClient({ secretRows: 1 }), ...args, secretsKept: false }))
      .rejects.toThrow(/unreadable/)
  })

  test('adopts it when the existing worker keeps its secrets', async () => {
    expect(await ensureDatabase({ client: fakeClient({ secretRows: 1 }), ...args, secretsKept: true })).toBe('db-1')
  })

  test('adopts it when no secret was ever stored', async () => {
    expect(await ensureDatabase({ client: fakeClient({ secretRows: 0 }), ...args, secretsKept: false })).toBe('db-1')
  })

  test('guards the provider database by its signing keys', async () => {
    await expect(ensureDatabase({ client: fakeClient({ secretRows: 1 }), ...args, name: 'sigillo-auth-db', dataTable: 'jwks', secretsKept: false }))
      .rejects.toThrow(/unreadable/)
    expect(queries.at(-1)).toBe('SELECT 1 FROM jwks LIMIT 1;')
  })
})

describe('fetchReleaseInfo', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  test('reads the newest release with a bundle straight from kldzj/sigillo on GitHub', async () => {
    const requested: string[] = []
    vi.stubGlobal('fetch', async (url: string) => {
      requested.push(String(url))
      return Response.json([
        { tag_name: 'sigillo@0.15.0', assets: [] },
        { tag_name: 'sigillo@0.14.0', assets: [{ name: 'sigillo-selfhost-bundle.json.gz', browser_download_url: 'https://example.com/0.14.0.json.gz' }] },
      ])
    })
    expect(await fetchReleaseInfo()).toEqual({ version: '0.14.0', url: 'https://example.com/0.14.0.json.gz' })
    expect(requested).toEqual(['https://api.github.com/repos/kldzj/sigillo/releases?per_page=30'])
  })
})
