// Unit tests for the self-host command's pure pieces: wrangler TOML
// round-trip, bundle parsing, and the token template deep link.
// The full deploy path is exercised manually/e2e against a real Cloudflare
// account (network + credentials required), not here.

import { createHash, createHmac, hkdfSync, webcrypto } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { CloudflareApiError, parseWranglerToml, serializeWranglerToml, TOKEN_TEMPLATE_URL, type CfClient, type DeploymentState } from '../src/selfhost/cloudflare.js'
import {
  appCompatibilityFlags, assertNoStoredSecrets, assertSecretsDecryptDatabase, checkBundle, fetchReleaseInfo, isOlderVersion, isSigilloProviderWorker, normalizeAllowedUsers, parseBundle,
  providerSecretsForDeploy, readExpectedBundle, resolveDeploySecrets, updateAllowedUsersSecret, uploadWorker,
  type SelfhostBundle, type WorkerBundle,
} from '../src/selfhost/deploy.js'
import { deriveStateKey, isSealed, openState, sealState, unlockStateFile } from '../src/selfhost/state-file.js'
import { baseKeyOf, countNotUnder, newKeyId, openValue, reencryptAll, sealValue, type KeyRing, type Query } from '../src/selfhost/rotate.js'
import { auditWitnesses, verifyHistory, type Witness } from '../src/selfhost/history.js'
import { LEFT_OUT, backupFileName, dumpDatabase, keyFingerprint, loadDatabase, newBackupIdentity, openBackup, sealBackup, splitStatements, type Backup } from '../src/selfhost/backup.js'
import { DatabaseSync } from 'node:sqlite'

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

describe('checkBundle', () => {
  const worker: WorkerBundle = {
    compatibilityDate: '2026-04-16',
    compatibilityFlags: ['nodejs_compat'],
    mainModule: 'index.js',
    modules: { 'index.js': Buffer.from('export default {}').toString('base64') },
    assets: {},
    migrations: {},
  }
  const gzipped = (version: string) => gzipSync(Buffer.from(JSON.stringify({ formatVersion: 2, version, createdAt: '2026-01-01T00:00:00.000Z', app: worker, provider: worker })))
  const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')

  test('deploys only the bundle this CLI was released with', () => {
    const released = gzipped('0.16.0')
    const expected = { version: '0.16.0', sha256: sha256(released) }
    expect(checkBundle(released, expected).version).toBe('0.16.0')
    // Anything else, even a well-formed bundle of another or the same version
    const other = gzipped('0.16.0 ')
    expect(() => checkBundle(other, expected)).toThrow(`This bundle isn't the one @kldzj/sigillo 0.16.0 was released with (SHA-256 ${sha256(other)}, expected ${expected.sha256}), so nothing was deployed`)
    const older = gzipped('0.15.0')
    expect(() => checkBundle(older, { version: '0.16.0', sha256: sha256(older) })).toThrow('The bundle is v0.15.0, but this CLI deploys v0.16.0')
    // A local build carries no digest
    expect(checkBundle(older, null).version).toBe('0.15.0')
  })

  test('a digest file that is there but unreadable stops the run; only a missing one means a local build', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sigillo-digest-'))
    let files = 0
    const read = (content?: string) => {
      const file = path.join(dir, `${++files}.json`)
      if (content !== undefined) writeFileSync(file, content)
      try {
        return readExpectedBundle(pathToFileURL(file))
      } catch (error) {
        return (error as Error).message.replace(file, '<file>')
      }
    }
    const sha = 'ab'.repeat(32)
    const damaged = "<file> has no valid bundle version and SHA-256, so the bundle can't be checked: reinstall @kldzj/sigillo"
    expect({
      released: read(JSON.stringify({ version: '0.16.0', sha256: sha })),
      missing: read(),
      truncated: read('{"version":"0.16.0","sha'),
      noDigest: read(JSON.stringify({ version: '0.16.0' })),
      badDigest: read(JSON.stringify({ version: '0.16.0', sha256: 'not-a-digest' })),
      noVersion: read(JSON.stringify({ sha256: sha })),
    }).toEqual({
      released: { version: '0.16.0', sha256: sha },
      missing: null,
      truncated: damaged,
      noDigest: damaged,
      badDigest: damaged,
      noVersion: damaged,
    })
  })

  test('isOlderVersion compares numerically', () => {
    expect([isOlderVersion('0.15.0', '0.16.0'), isOlderVersion('0.9.0', '0.10.0'), isOlderVersion('0.16.0', '0.16.0'), isOlderVersion('1.0.0', '0.99.9')])
      .toEqual([true, true, false, false])
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

describe('assertNoStoredSecrets', () => {
  const queries: string[] = []
  const fakeClient = ({ rows }: { rows: number }) => ({
    async d1Query({ sql }: { sql: string }) {
      queries.push(sql)
      if (sql.includes('sqlite_master')) return [{ results: [{ name: 'found' }] }]
      return [{ results: Array.from({ length: rows }, () => ({ found: 1 })) }]
    },
  }) as unknown as CfClient
  const args = { accountId: 'acc', databaseId: 'db-1' }

  test('refuses to put new secrets in front of stored ones', async () => {
    await expect(assertNoStoredSecrets({ client: fakeClient({ rows: 1 }), ...args })).rejects.toThrow(/unreadable/)
    expect(queries.at(-1)).toBe('SELECT 1 AS found FROM secret_event LIMIT 1;')
  })

  test('allows it when no secret was ever stored', async () => {
    await expect(assertNoStoredSecrets({ client: fakeClient({ rows: 0 }), ...args })).resolves.toBeUndefined()
  })

  test('guards the provider database by its signing keys', async () => {
    await expect(assertNoStoredSecrets({ client: fakeClient({ rows: 1 }), ...args, dataTable: 'jwks' })).rejects.toThrow(/unreadable/)
    expect(queries.at(-1)).toBe('SELECT 1 AS found FROM jwks LIMIT 1;')
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

describe('resolveDeploySecrets', () => {
  const key = Buffer.alloc(32, 7).toString('base64')
  const other = Buffer.alloc(32, 9).toString('base64')
  const run = (args: Parameters<typeof resolveDeploySecrets>[0]) => {
    try {
      const r = resolveDeploySecrets(args)
      const label = (value: string | undefined, savedValue: string | undefined) =>
        value === undefined ? undefined : value === savedValue ? 'saved' : value === args.encryptionKeyEnv ? 'env' : 'generated'
      return {
        betterAuthSecret: label(r.betterAuthSecret, args.saved?.betterAuthSecret),
        encryptionKey: label(r.encryptionKey, args.saved?.encryptionKey),
        generated: r.generated,
      }
    } catch (error) {
      return (error as Error).message
    }
  }

  test('a new deployment gets its own key; an existing one never gets a new one', () => {
    expect({
      defaultNew: run({ workerExists: false }),
      newWithKey: run({ workerExists: false, encryptionKeyEnv: key }),
      recreatedFromState: run({ workerExists: false, saved: { betterAuthSecret: 's', encryptionKey: key } }),
      recreatedDerivedKey: run({ workerExists: false, saved: { betterAuthSecret: 's' } }),
      recreatedDerivedKeyNewKey: run({ workerExists: false, saved: { betterAuthSecret: 's' }, encryptionKeyEnv: key }),
      recreatedDifferentKey: run({ workerExists: false, saved: { betterAuthSecret: 's', encryptionKey: key }, encryptionKeyEnv: other }),
      existing: run({ workerExists: true, saved: { betterAuthSecret: 's' } }),
      existingSameKey: run({ workerExists: true, saved: { betterAuthSecret: 's', encryptionKey: key }, encryptionKeyEnv: key }),
      existingNewKey: run({ workerExists: true, saved: { betterAuthSecret: 's' }, encryptionKeyEnv: key }),
      invalidKey: run({ workerExists: false, encryptionKeyEnv: 'short' }),
    }).toMatchInlineSnapshot(`
      {
        "defaultNew": {
          "betterAuthSecret": "generated",
          "encryptionKey": "generated",
          "generated": true,
        },
        "existing": {
          "betterAuthSecret": undefined,
          "encryptionKey": undefined,
          "generated": undefined,
        },
        "existingNewKey": "SIGILLO_ENCRYPTION_KEY can only be set on the first deploy. Changing the key of an existing deployment would make its stored secrets unreadable. Unset it to update.",
        "existingSameKey": {
          "betterAuthSecret": undefined,
          "encryptionKey": undefined,
          "generated": undefined,
        },
        "invalidKey": "SIGILLO_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)",
        "newWithKey": {
          "betterAuthSecret": "generated",
          "encryptionKey": "env",
          "generated": true,
        },
        "recreatedDerivedKey": {
          "betterAuthSecret": "saved",
          "encryptionKey": undefined,
          "generated": undefined,
        },
        "recreatedDerivedKeyNewKey": "SIGILLO_ENCRYPTION_KEY can only be set on the first deploy. Changing the key of an existing deployment would make its stored secrets unreadable. Unset it to update.",
        "recreatedDifferentKey": "SIGILLO_ENCRYPTION_KEY can only be set on the first deploy. Changing the key of an existing deployment would make its stored secrets unreadable. Unset it to update.",
        "recreatedFromState": {
          "betterAuthSecret": "saved",
          "encryptionKey": "saved",
          "generated": undefined,
        },
      }
    `)
  })
})

describe('allowed users', () => {
  test('the list is stored lowercase, without spaces or repeats', () => {
    expect(normalizeAllowedUsers(' Acme.com,ops@Partner.io  acme.com,, ')).toBe('acme.com,ops@partner.io')
    expect(normalizeAllowedUsers('')).toBe('')
  })

  test('anything but an email address or a domain is refused', () => {
    expect(() => normalizeAllowedUsers('acme.com,localhost,@acme.com,ops@,x@y')).toThrow('Not an email address or a domain: localhost, @acme.com, ops@, x@y')
  })

  test('an existing worker only gets a changed list', async () => {
    const calls: string[] = []
    const client = {
      async putWorkerSecret({ scriptName, name, text }: { scriptName: string; name: string; text: string }) { calls.push(`put ${scriptName} ${name}=${text}`) },
      async deleteWorkerSecret({ scriptName, name }: { scriptName: string; name: string }) {
        calls.push(`delete ${scriptName} ${name}`)
        if (scriptName === 'gone') throw new CloudflareApiError({ status: 404, errors: [], context: 'secrets' })
      },
    } as unknown as CfClient
    const run = (list: string, saved: string | undefined, scriptName = 'sigillo') =>
      updateAllowedUsersSecret({ client, accountId: 'acc', scriptName, list, saved })
    await run('acme.com', 'acme.com')
    await run('', undefined)
    await run('acme.com,ops@partner.io', 'acme.com')
    await run('', 'acme.com')
    await run('', 'acme.com', 'gone')
    expect(calls).toEqual([
      'put sigillo ALLOWED_USERS=acme.com,ops@partner.io',
      'delete sigillo ALLOWED_USERS',
      'delete gone ALLOWED_USERS',
    ])
  })
})

describe('encrypted state file', () => {
  const state = JSON.stringify({ deployments: { 'acct/sigillo': { betterAuthSecret: 'bas-very-secret', encryptionKey: 'enc-very-secret' } } })
  const passphrase = 'correct horse battery staple'
  const noPrompt = async (): Promise<never> => { throw new Error('should not prompt') }
  const unlock = (args: Partial<Parameters<typeof unlockStateFile>[0]>) => unlockStateFile({
    text: null, envPassphrase: undefined, interactive: false,
    askPassphrase: noPrompt, askNewPassphrase: noPrompt, confirmEncrypt: noPrompt, ...args,
  })

  test('sealed, the file holds no secret, and opens only with its passphrase', () => {
    const text = sealState(state, deriveStateKey(passphrase))
    const { kdf } = JSON.parse(text)
    const tampered = JSON.parse(text)
    tampered.data = Buffer.from(Buffer.from(tampered.data, 'base64').map((byte, i) => (i === 0 ? byte ^ 1 : byte))).toString('base64')
    expect({
      sealed: isSealed(text),
      leaks: text.includes('very-secret') || text.includes('betterAuthSecret'),
      opened: openState(text, deriveStateKey(passphrase, kdf)),
      wrong: (() => { try { return openState(text, deriveStateKey('not the passphrase', kdf)) } catch (e) { return (e as Error).message } })(),
      tampered: (() => { try { return openState(JSON.stringify(tampered), deriveStateKey(passphrase, kdf)) } catch (e) { return (e as Error).message } })(),
    }).toEqual({
      sealed: true,
      leaks: false,
      opened: state,
      wrong: 'Wrong passphrase for ~/.sigillo/selfhost.json',
      tampered: 'Wrong passphrase for ~/.sigillo/selfhost.json',
    })
  })

  test('a first run needs a passphrase: prompted, or from the variable when it cannot prompt', async () => {
    const prompted = await unlock({ interactive: true, askNewPassphrase: async () => passphrase })
    const fromEnv = await unlock({ envPassphrase: passphrase })
    const none = await unlock({}).catch((e: Error) => e.message)
    const short = await unlock({ envPassphrase: 'short' }).catch((e: Error) => e.message)
    expect({ prompted: prompted.stateKey !== null, fromEnv: fromEnv.stateKey !== null, none, short }).toEqual({
      prompted: true,
      fromEnv: true,
      none: 'Set SIGILLO_SELFHOST_PASSPHRASE to the passphrase that encrypts ~/.sigillo/selfhost.json',
      short: 'SIGILLO_SELFHOST_PASSPHRASE: Use at least 12 characters',
    })
  })

  test('an encrypted file opens with the right passphrase, and three wrong ones stop the run', async () => {
    const text = sealState(state, deriveStateKey(passphrase))
    const answers = ['wrong one here', passphrase]
    const retried = await unlock({ text, interactive: true, askPassphrase: async () => answers.shift()! })
    const wrongEnv = await unlock({ text, envPassphrase: 'wrong one here' }).catch((e: Error) => e.message)
    const noEnv = await unlock({ text }).catch((e: Error) => e.message)
    let tries = 0
    const gaveUp = await unlock({ text, interactive: true, askPassphrase: async () => { tries++; return 'wrong one here' } }).catch((e: Error) => e.message)
    expect({
      retried: openState(text, retried.stateKey!), wrongEnv, noEnv, gaveUp, tries,
    }).toEqual({
      retried: state,
      wrongEnv: 'Wrong passphrase for ~/.sigillo/selfhost.json',
      noEnv: '~/.sigillo/selfhost.json is encrypted: set SIGILLO_SELFHOST_PASSPHRASE to its passphrase',
      gaveUp: 'Wrong passphrase for ~/.sigillo/selfhost.json',
      tries: 3,
    })
  })

  test('an unencrypted file is sealed when the owner agrees, and otherwise left with a warning', async () => {
    const agreed = await unlock({ text: state, interactive: true, confirmEncrypt: async () => true, askNewPassphrase: async () => passphrase })
    const declined = await unlock({ text: state, interactive: true, confirmEncrypt: async () => false })
    const fromEnv = await unlock({ text: state, envPassphrase: passphrase })
    const unattended = await unlock({ text: state })
    expect({
      agreed: agreed.seal && agreed.stateKey !== null,
      declined: { seal: declined.seal, key: declined.stateKey, warned: !!declined.warning },
      fromEnv: fromEnv.seal && fromEnv.stateKey !== null,
      unattended: { seal: unattended.seal, key: unattended.stateKey, warning: unattended.warning },
    }).toEqual({
      agreed: true,
      declined: { seal: false, key: null, warned: true },
      fromEnv: true,
      unattended: {
        seal: false,
        key: null,
        warning: '~/.sigillo/selfhost.json is not encrypted. Run self-host in a terminal, or set SIGILLO_SELFHOST_PASSPHRASE, to encrypt it.',
      },
    })
  })
})

describe('state file on disk', () => {
  const originalHome = process.env.HOME
  afterEach(() => {
    process.env.HOME = originalHome
    vi.resetModules()
  })
  // cloudflare.ts reads the home directory when it loads
  const loadWithHome = async () => {
    const home = mkdtempSync(path.join(tmpdir(), 'sigillo-state-'))
    process.env.HOME = home
    vi.resetModules()
    return { home, file: path.join(home, '.sigillo', 'selfhost.json'), cloudflare: await import('../src/selfhost/cloudflare.js') }
  }
  const prompts = { envPassphrase: 'correct horse battery staple', interactive: false, askPassphrase: async () => '', askNewPassphrase: async () => '', confirmEncrypt: async () => false }
  const deployment = { accountId: 'acct', workerName: 'sigillo', databaseId: 'db', betterAuthSecret: 'bas-very-secret' }

  test('writes are sealed, and reads open them', async () => {
    const { file, cloudflare } = await loadWithHome()
    await cloudflare.unlockState(prompts)
    cloudflare.writeState({ deployments: { 'acct/sigillo': deployment } })
    const text = readFileSync(file, 'utf-8')
    expect({ sealed: isSealed(text), leaks: text.includes('very-secret'), read: cloudflare.readState() })
      .toEqual({ sealed: true, leaks: false, read: { deployments: { 'acct/sigillo': deployment } } })
  })

  test('an unencrypted file is sealed in place, with the same content', async () => {
    const { file, cloudflare } = await loadWithHome()
    mkdirSync(path.dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify({ deployments: { 'acct/sigillo': deployment } }))
    await cloudflare.unlockState(prompts)
    expect({ sealed: isSealed(readFileSync(file, 'utf-8')), read: cloudflare.readState() })
      .toEqual({ sealed: true, read: { deployments: { 'acct/sigillo': deployment } } })
  })

  test('a new passphrase replaces the old one', async () => {
    const { home, cloudflare } = await loadWithHome()
    await cloudflare.unlockState(prompts)
    cloudflare.writeState({ deployments: { 'acct/sigillo': deployment } })
    cloudflare.changeStatePassphrase('a brand new passphrase')
    // A later run with each passphrase
    const later = async (envPassphrase: string) => {
      process.env.HOME = home
      vi.resetModules()
      const next = await import('../src/selfhost/cloudflare.js')
      return next.unlockState({ ...prompts, envPassphrase }).then(() => next.readState()).catch((e: Error) => e.message)
    }
    expect({ old: await later(prompts.envPassphrase), new: await later('a brand new passphrase') })
      .toEqual({ old: 'Wrong passphrase for ~/.sigillo/selfhost.json', new: { deployments: { 'acct/sigillo': deployment } } })
  })

  test('nothing is read or written before the file is unlocked', async () => {
    const { cloudflare } = await loadWithHome()
    expect(() => cloudflare.writeState({})).toThrow('~/.sigillo/selfhost.json was not unlocked')
  })
})

describe('rotating the encryption key', () => {
  // Also in app/src/app.test.ts, whose Worker reads it: both sides write and
  // read the same bytes
  const vector = {
    key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
    iv: 'c2lnaWxsby12Mml2',
    encrypted: 'v2.t1.04HOaWtJFS4lf19AmZ7SSntwRBs93eL6CAmTPylB1fxE2Y6tqkquxR0BRLSg',
    slot: { environmentId: '01TESTENVIRONMENT', name: 'DATABASE_URL' },
    value: 'postgres://app:hunter2@db/app',
    // The same key and IV before v2: key 0, no additional data
    v1: 'z4vafG9CXSt+PAVE/XS9/aX7CtsC6HgJG5MY8Q==',
  }
  const base = Buffer.from(vector.key, 'base64')

  test('writes and reads what the Worker does', async () => {
    const sealed = await sealValue({ keyId: 't1', key: vector.key, slot: vector.slot, plaintext: vector.value, iv: Buffer.from(vector.iv, 'base64') })
    const ring = { current: 't1', keys: { t1: vector.key } }
    const outcome = (run: () => Promise<string>) => run().catch((error: Error) => error.message)
    expect({
      sealed: sealed.encrypted,
      opened: await openValue({ ring, baseKey: base, encrypted: vector.encrypted, iv: vector.iv, slot: vector.slot }),
      v1: await openValue({ ring: undefined, baseKey: base, encrypted: vector.v1, iv: vector.iv, slot: vector.slot }),
      elsewhere: await outcome(() => openValue({ ring, baseKey: base, encrypted: vector.encrypted, iv: vector.iv, slot: { ...vector.slot, name: 'OTHER' } })),
      missingKey: await outcome(() => openValue({ ring: undefined, baseKey: base, encrypted: vector.encrypted, iv: vector.iv, slot: vector.slot })),
    }).toEqual({
      sealed: vector.encrypted,
      opened: vector.value,
      v1: 'legacy-value',
      elsewhere: "OTHER can't be decrypted",
      missingKey: "DATABASE_URL is encrypted with the key t1, which ~/.sigillo/selfhost.json doesn't have",
    })
  })

  test('key 0 is ENCRYPTION_KEY, or else derived from BETTER_AUTH_SECRET, and a new key id is new', () => {
    const ring = { current: 'abc123', keys: { abc123: vector.key } }
    const id = newKeyId(ring)
    expect({
      explicit: baseKeyOf({ encryptionKey: vector.key, betterAuthSecret: 'ignored' }).equals(base),
      derived: baseKeyOf({ betterAuthSecret: 'secret' }).equals(createHash('sha256').update('secret').digest()),
      id: /^[a-z0-9]{6}$/.test(id) && id !== 'abc123',
    }).toEqual({ explicit: true, derived: true, id: true })
    expect(() => baseKeyOf({})).toThrow('neither ENCRYPTION_KEY nor BETTER_AUTH_SECRET')
  })

  // The statements run on SQLite, as D1 runs them
  const database = () => {
    const db = new DatabaseSync(':memory:')
    db.exec('CREATE TABLE secret_event (id text PRIMARY KEY, environment_id text NOT NULL, name text NOT NULL, value_encrypted text, iv text)')
    const query: Query = async (sql, params = []) => {
      const statement = db.prepare(sql)
      if (/^\s*SELECT/i.test(sql)) return statement.all(...params) as Array<Record<string, unknown>>
      statement.run(...params)
      return []
    }
    return { db, query }
  }
  const insert = (db: DatabaseSync, row: { id: string; name: string; value: { encrypted: string; iv: string } | null }) =>
    db.prepare('INSERT INTO secret_event VALUES (?, ?, ?, ?, ?)').run(row.id, vector.slot.environmentId, row.name, row.value?.encrypted ?? null, row.value?.iv ?? null)

  test('re-encrypts every value under the current key, from before v2 too, and leaves a purged one purged', async () => {
    const { db, query } = database()
    const t2 = Buffer.alloc(32, 7).toString('base64')
    const ring: KeyRing = { current: 't2', keys: { t1: vector.key, t2 } }
    const slot = (name: string) => ({ ...vector.slot, name })
    insert(db, { id: 'a', name: 'DATABASE_URL', value: { encrypted: vector.v1, iv: vector.iv } })
    insert(db, { id: 'b', name: 'KEY0', value: await sealValue({ keyId: '0', key: vector.key, slot: slot('KEY0'), plaintext: 'under key 0' }) })
    insert(db, { id: 'c', name: 'DATABASE_URL', value: { encrypted: vector.encrypted, iv: vector.iv } })
    insert(db, { id: 'd', name: 'PURGED', value: null })
    // Rows a..c are more than one batch once there are enough of them
    for (let i = 0; i < 30; i++) insert(db, { id: `m${String(i).padStart(2, '0')}`, name: `MANY_${i}`, value: await sealValue({ keyId: 't1', key: vector.key, slot: slot(`MANY_${i}`), plaintext: `value ${i}` }) })
    // An admin purges row c while the rotation runs
    let purgedMeanwhile = false
    const racing: Query = async (sql, params) => {
      if (sql.startsWith('UPDATE') && !purgedMeanwhile) {
        purgedMeanwhile = true
        db.prepare("UPDATE secret_event SET value_encrypted = NULL, iv = NULL WHERE id = 'c'").run()
      }
      return query(sql, params)
    }
    const progress: number[] = []
    const done = await reencryptAll({ query: racing, ring, baseKey: base, onProgress: (n) => progress.push(n) })
    const rows = db.prepare('SELECT id, name, value_encrypted, iv FROM secret_event ORDER BY id').all() as Array<{ id: string; name: string; value_encrypted: string | null; iv: string | null }>
    const read = async (id: string) => {
      const row = rows.find((r) => r.id === id)!
      return row.value_encrypted ? openValue({ ring: { current: 't2', keys: { t2 } }, baseKey: Buffer.alloc(32), encrypted: row.value_encrypted, iv: row.iv!, slot: slot(row.name) }) : null
    }
    expect({
      done,
      progress,
      prefixes: [...new Set(rows.filter((row) => row.value_encrypted).map((row) => row.value_encrypted!.slice(0, 6)))],
      a: await read('a'),
      b: await read('b'),
      c: await read('c'),
      d: await read('d'),
      m29: await read('m29'),
      left: await countNotUnder(query, 't2'),
    }).toEqual({
      done: 33,
      progress: [25, 33],
      prefixes: ['v2.t2.'],
      a: 'legacy-value',
      b: 'under key 0',
      c: null,
      d: null,
      m29: 'value 29',
      left: 0,
    })
  })

  test('stops at a value it can\'t read, naming its row, and a second run carries on', async () => {
    const { db, query } = database()
    const ring: KeyRing = { current: 't1', keys: { t1: vector.key } }
    insert(db, { id: 'a', name: 'GOOD', value: await sealValue({ keyId: '0', key: vector.key, slot: { ...vector.slot, name: 'GOOD' }, plaintext: 'good' }) })
    insert(db, { id: 'b', name: 'BAD', value: { encrypted: 'v2.0.AAAA', iv: vector.iv } })
    const failed = await reencryptAll({ query, ring, baseKey: base }).catch((error: Error) => error.message)
    db.prepare("DELETE FROM secret_event WHERE id = 'b'").run()
    expect({ failed, left: await countNotUnder(query, 't1'), again: await reencryptAll({ query, ring, baseKey: base }) }).toEqual({
      failed: `BAD can't be decrypted (row b of environment ${vector.slot.environmentId}): the rotation stopped there`,
      left: 1,
      again: 1,
    })
  })
})

describe('checking a restored history', () => {
  // A real chain, written by the Worker in the app's test suite with its
  // BETTER_AUTH_SECRET: a row from before the chain, a purged value, a
  // delete, two purge rows and a read of a protected environment
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/history.json', import.meta.url), 'utf8'))
  const secret = 'test-secret-at-least-32-characters-long!!'
  const load = () => {
    const db = new DatabaseSync(':memory:')
    db.exec(`CREATE TABLE environment (id text PRIMARY KEY, project_id text, slug text);
      CREATE TABLE secret_event (id text PRIMARY KEY, environment_id text, name text, operation text, value_encrypted text, iv text, value_digest text,
        user_id text, api_token_id text, created_at integer, actor text, seq integer, hash text, signature text, adopted integer);
      CREATE TABLE secret_read (id text PRIMARY KEY, environment_id text, actor text, kind text, names text, ip_address text, created_at integer, seq integer, hash text, signature text)`)
    db.prepare("INSERT INTO environment VALUES (?, 'p1', 'prod')").run(fixture.environmentId)
    for (const e of fixture.events) {
      db.prepare('INSERT INTO secret_event VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(e.id, e.environmentId, e.name, e.operation, e.valueEncrypted, e.iv, e.valueDigest,
        e.userId, e.apiTokenId, e.createdAt, e.actor, e.seq, e.hash, e.signature, e.adopted ? 1 : 0)
    }
    for (const r of fixture.reads) {
      db.prepare('INSERT INTO secret_read VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(r.id, r.environmentId, r.actor, r.kind, JSON.stringify(r.names), r.ipAddress, r.createdAt, r.seq, r.hash, r.signature)
    }
    const query: Query = async (sql, params = []) => db.prepare(sql).all(...params) as Array<Record<string, unknown>>
    return { db, check: (witnesses?: Witness[]) => verifyHistory({ query, betterAuthSecret: secret, ring: undefined, baseKey: baseKeyOf({ betterAuthSecret: secret }), witnesses }) }
  }
  const env = fixture.environmentId
  const intact = { environments: 1, rows: 8, outside: 0, unsigned: 0, sinceLastCheck: [], problems: [] }

  test('accepts the Worker\'s own rows', async () => {
    expect(await load().check()).toEqual(intact)
  })

  test('counts environments with changes but no signed history, which nothing checks', async () => {
    const stripped = load()
    stripped.db.exec("UPDATE secret_event SET seq = NULL, hash = NULL, signature = NULL, adopted = 0; DELETE FROM secret_read; UPDATE secret_event SET name = 'RENAMED'")
    stripped.db.exec("INSERT INTO environment VALUES ('empty', 'p1', 'dev')")
    expect(await stripped.check()).toEqual({ ...intact, environments: 2, rows: 0, unsigned: 1 })
  })

  test('compares the heads with what sigillo audit verify saw of this instance', async () => {
    const head = (seq: number) => ({ seq, hash: fixture.events.find((e: { seq: number }) => e.seq === seq).hash })
    const file = path.join(mkdtempSync(path.join(tmpdir(), 'sigillo-witness-')), 'audit.json')
    writeFileSync(file, JSON.stringify({
      // Checked by slug, and by id before witnesses were keyed by project
      'https://secrets.acme.com p1 prod': { public_key: 'k', events: head(7), reads: { seq: 1, hash: fixture.reads[0].hash }, verified_at: 1 },
      [`https://sigillo.acme.workers.dev ${env}`]: { public_key: 'k', events: head(5), reads: null, verified_at: 1 },
      // Another instance
      'https://other.example p1 prod': { public_key: 'k', events: { seq: 99, hash: 'x' }, reads: null, verified_at: 1 },
    }))
    const urls = ['https://sigillo.acme.workers.dev', 'https://secrets.acme.com/']
    const witnesses = auditWitnesses(urls, file)
    const later = [...witnesses, { project: 'p1', environment: env, events: { seq: 9, hash: 'x' }, reads: null }, { project: 'p1', environment: 'staging', events: head(1), reads: null }]
    const rewritten = [{ project: 'p1', environment: 'prod', events: { ...head(3), hash: head(4).hash }, reads: null }]
    expect({
      witnesses: witnesses.map((w) => `${w.project} ${w.environment} ${w.events?.seq} ${w.reads?.seq}`),
      same: (await load().check(witnesses)).sinceLastCheck,
      later: (await load().check(later)).sinceLastCheck,
      rewritten: (await load().check(rewritten)).sinceLastCheck,
      noFile: auditWitnesses(urls, path.join(path.dirname(file), 'missing.json')),
    }).toEqual({
      witnesses: ['p1 prod 7 1', `null ${env} 5 undefined`],
      same: [],
      later: [
        `environment ${env}: its changes have 7 rows, but had 9 when sigillo audit verify last checked them`,
        'environment staging of project p1: not in the backup, but sigillo audit verify checked it',
      ],
      rewritten: [`environment ${env}: changes row 3 differs from the one sigillo audit verify last checked`],
      noFile: [],
    })
  })

  test('finds an edited row, a changed purged digest, a copied signature and an edited read', async () => {
    const renamed = load()
    renamed.db.prepare("UPDATE secret_event SET name = 'Y' WHERE seq = 3").run()
    const digest = load()
    digest.db.prepare("UPDATE secret_event SET value_digest = 'AAAA' WHERE seq = 2").run()
    const signature = load()
    signature.db.prepare('UPDATE secret_event SET signature = (SELECT signature FROM secret_event WHERE seq = 1) WHERE seq = 5').run()
    const read = load()
    read.db.prepare(`UPDATE secret_read SET names = '["X","Z"]'`).run()
    const wrongSecret = load()
    expect({
      renamed: (await renamed.check()).problems,
      digest: (await digest.check()).problems,
      signature: (await signature.check()).problems,
      read: (await read.check()).problems,
      wrongSecret: (await verifyHistory({ query: async (sql, params = []) => wrongSecret.db.prepare(sql).all(...params) as Array<Record<string, unknown>>, betterAuthSecret: 'another-secret-of-another-deployment', ring: undefined, baseKey: baseKeyOf({ betterAuthSecret: secret }) })).problems,
    }).toEqual({
      renamed: [`environment ${env}, changes row 3 does not match its hash`],
      digest: [`environment ${env}, changes row 2 does not match its hash`],
      signature: [`environment ${env}, changes row 5 has an invalid signature`],
      read: [`environment ${env}, reads row 1 does not match its hash`],
      wrongSecret: [`environment ${env}, changes row 1 does not match its hash`, `environment ${env}, reads row 1 has an invalid signature`],
    })
  })

  test('finds a value removed without a purge, even with its digest kept', async () => {
    // X's current value, removed with its digest kept in value_digest, as a purge does
    const current = load()
    const row = fixture.events.find((e: { seq: number }) => e.seq === 3)
    const value = await openValue({ ring: undefined, baseKey: baseKeyOf({ betterAuthSecret: secret }), encrypted: row.valueEncrypted, iv: row.iv, slot: { environmentId: env, name: row.name } })
    const digestKey = Buffer.from(hkdfSync('sha256', secret, new Uint8Array(), 'sigillo audit value digest v1', 32))
    const digest = createHmac('sha256', digestKey).update(JSON.stringify([env, row.name, value])).digest('base64')
    current.db.prepare('UPDATE secret_event SET value_encrypted = NULL, iv = NULL, value_digest = ? WHERE seq = 3').run(digest)
    // Old values set again but never purged: the newest rows, the purges, removed
    const unpurged = load()
    unpurged.db.prepare('DELETE FROM secret_event WHERE seq > 5').run()
    expect({
      current: (await current.check()).problems,
      unpurged: (await unpurged.check()).problems,
    }).toEqual({
      current: [`environment ${env}, changes row 3 lost its value without a purge`],
      unpurged: [`environment ${env}, changes row 2 lost its value without a purge`],
    })
  })

  test('counts a row added around the chain, which the Worker ignores', async () => {
    const planted = load()
    planted.db.prepare(`INSERT INTO secret_event (id, environment_id, name, operation, created_at) VALUES ('planted', '${env}', 'X', 'delete', 1)`).run()
    expect(await planted.check()).toEqual({ ...intact, outside: 1 })
  })
})

describe('backups', () => {
  const backup: Backup = {
    format: 'sigillo-backup',
    version: 1,
    createdAt: '2026-09-29T10:00:00.000Z',
    workerName: 'sigillo',
    sigilloVersion: '0.16.0',
    keys: { '0': '0123456789abcdef' },
    databases: { app: { schema: 'CREATE TABLE t (id text);', data: "INSERT INTO t VALUES ('a');", tables: ['t'], migrations: ['0001_init.sql'] }, provider: null },
  }

  test('open only with their own key, as standard age files', async () => {
    const identity = await newBackupIdentity()
    const sealed = await sealBackup(backup, identity)
    expect({
      age: Buffer.from(sealed.slice(0, 21)).toString('utf8'),
      opened: await openBackup(sealed, identity),
      other: await openBackup(sealed, await newBackupIdentity()).catch((error: Error) => error.message),
      name: backupFileName('sigillo', new Date('2026-09-29T10:04:05.678Z')),
    }).toEqual({
      age: 'age-encryption.org/v1',
      opened: backup,
      other: "This backup doesn't open with the backup key in ~/.sigillo/selfhost.json: it was made for another deployment, or isn't a Sigillo backup",
      name: 'sigillo-2026-09-29T10-04-05Z.backup.age',
    })
  })

  test('name the keys their values need, so a restore after a rotation stops before it starts', () => {
    const before = { ring: undefined, baseKey: baseKeyOf({ encryptionKey: Buffer.alloc(32, 1).toString('base64'), betterAuthSecret: 'secret' }) }
    // The rotation re-encrypted every value and deleted ENCRYPTION_KEY, so key 0 is derived now
    const after = { ring: { current: 'abc123', keys: { abc123: Buffer.alloc(32, 2).toString('base64') } }, baseKey: baseKeyOf({ betterAuthSecret: 'secret' }) }
    expect({
      zeroKept: keyFingerprint('0', before) === keyFingerprint('0', after),
      current: keyFingerprint('abc123', after),
      unknown: keyFingerprint('abc123', before),
    }).toEqual({ zeroKept: false, current: expect.stringMatching(/^[0-9a-f]{16}$/), unknown: undefined })
  })

  test('split SQL at semicolons outside quotes', () => {
    const sql = `PRAGMA defer_foreign_keys=TRUE;\nINSERT INTO "user" VALUES('a;b','it''s\nmultiline');\nINSERT INTO "a""b" VALUES(1);`
    expect(splitStatements(sql)).toEqual([
      'PRAGMA defer_foreign_keys=TRUE;',
      `INSERT INTO "user" VALUES('a;b','it''s\nmultiline');`,
      'INSERT INTO "a""b" VALUES(1);',
    ])
  })

  // What the Cloudflare API answers, step by step, and what the CLI sent
  const fakeCloudflare = () => {
    const calls: string[] = []
    const client = {
      async d1Query({ sql }: { sql: string }) {
        calls.push(`query ${sql.slice(0, 30)}`)
        if (sql.includes('sqlite_master WHERE')) return [{ results: [{ name: 'd1_migrations' }, { name: 'org' }, { name: 'org_member' }, { name: 'session' }] }]
        if (sql.includes("pragma_foreign_key_list('org_member')")) return [{ results: [{ ref: 'org' }] }]
        if (sql.includes('d1_migrations')) return [{ results: [{ name: '0001_init.sql' }] }]
        return [{ results: [] }]
      },
      async d1ExportStep({ dumpOptions, bookmark }: { dumpOptions: object; bookmark?: string }) {
        calls.push(`export ${JSON.stringify(dumpOptions)} ${bookmark ?? 'start'}`)
        return bookmark ? { status: 'complete', result: { signed_url: `https://export.example/${JSON.stringify(dumpOptions)}`, filename: 'x.sql' } } : { status: 'active', at_bookmark: 'b1' }
      },
      async d1ImportStep({ body }: { body: { action: string } }) {
        calls.push(`import ${body.action}`)
        if (body.action === 'init') return { upload_url: 'https://upload.example/x', filename: 'x.sql' }
        if (body.action === 'ingest') return { success: true, status: 'active', at_bookmark: 'b2' }
        return { success: true, status: 'complete' }
      },
    } as unknown as CfClient
    return { calls, client }
  }

  test('export both halves of a database and import them in one step', async () => {
    const { calls, client } = fakeCloudflare()
    let uploaded = ''
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      // As D1 exports them: a member before the organization it points at
      if (url.startsWith('https://export.example/')) return new Response(url.includes('no_data') ? 'CREATE TABLE org (id text);' : 'INSERT INTO "org_member" VALUES(\'m\',\'o\');\nINSERT INTO "org" VALUES(\'o\');')
      uploaded = String(init?.body)
      return new Response('', { status: 200, headers: { etag: `"${createHash('md5').update(uploaded).digest('hex')}"` } })
    })
    const database = { client, accountId: 'acc', databaseId: 'db' }
    const dump = await dumpDatabase(database, ['session'])
    await loadDatabase(database, dump)
    vi.restoreAllMocks()
    expect({ dump, uploaded, calls }).toEqual({
      dump: { schema: 'CREATE TABLE org (id text);', data: 'INSERT INTO "org" VALUES(\'o\');\nINSERT INTO "org_member" VALUES(\'m\',\'o\');', tables: ['d1_migrations', 'org', 'org_member'], migrations: ['0001_init.sql'] },
      uploaded: 'PRAGMA defer_foreign_keys = true;\nCREATE TABLE org (id text);\nINSERT INTO "org" VALUES(\'o\');\nINSERT INTO "org_member" VALUES(\'m\',\'o\');',
      calls: [
        'query SELECT name FROM sqlite_master',
        'query SELECT name FROM d1_migrations',
        'query SELECT "table" AS ref FROM pra',
        'query SELECT "table" AS ref FROM pra',
        'query SELECT "table" AS ref FROM pra',
        'export {"no_data":true} start',
        'export {"no_data":true} b1',
        'export {"no_schema":true,"tables":["d1_migrations","org","org_member"]} start',
        'export {"no_schema":true,"tables":["d1_migrations","org","org_member"]} b1',
        'import init',
        'import ingest',
        'import poll',
      ],
    })
  })
})

describe('sign-in ID tokens', () => {
  // A database migrated like the real one, answering queries and exports as D1 does
  const migrated = (dir: string) => {
    const db = new DatabaseSync(':memory:')
    const folder = new URL(dir, import.meta.url)
    for (const file of readdirSync(folder).filter((name) => name.endsWith('.sql')).sort()) db.exec(readFileSync(new URL(file, `${folder.href}/`), 'utf8'))
    return db
  }
  // D1's export: every value quoted by SQLite
  const exportOf = (db: DatabaseSync, options: { no_data?: boolean; tables?: string[] }) => options.no_data
    ? (db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as Array<{ sql: string }>).map((row) => `${row.sql};`).join('\n')
    : options.tables!.flatMap((table) => {
      const columns = (db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all() as Array<{ name: string }>).map((row) => `quote("${row.name}")`)
      return (db.prepare(`SELECT 'INSERT INTO "${table}" VALUES(' || ${columns.join(" || ',' || ")} || ');' AS statement FROM "${table}"`).all() as Array<{ statement: string }>).map((row) => row.statement)
    }).join('\n')
  const cloudflare = (db: DatabaseSync) => ({
    async d1Query({ sql, params = [] }: { sql: string; params?: string[] }) {
      return [{ results: db.prepare(sql).all(...params) }]
    },
    async d1ExportStep({ dumpOptions }: { dumpOptions: object }) {
      return { status: 'complete', result: { signed_url: `https://export.example/?${encodeURIComponent(JSON.stringify(dumpOptions))}`, filename: 'x.sql' } }
    },
  }) as unknown as CfClient

  test.each([
    { name: 'app', migrations: '../../db/drizzle-app', leftOut: LEFT_OUT.app },
    { name: 'provider', migrations: '../../provider/drizzle', leftOut: LEFT_OUT.provider },
  ])('are left out of the $name database, which restores without them', async ({ migrations, leftOut }) => {
    const live = migrated(migrations)
    live.prepare("INSERT INTO user (id, name, email, email_verified, created_at, updated_at) VALUES ('u1', 'Ada', 'ada@acme.com', 1, 1, 1)").run()
    const account = ['a1', 'u1', 'google-sub', 'google', `enc'd; "access"\ntoken`, null, 1790000000000, null, 'openid email', 'eyJhbGciOiJSUzI1NiJ9.google.id-token', null, 1, 2]
    live.prepare('INSERT INTO account (id, user_id, account_id, provider_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scope, id_token, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(...account)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => new Response(exportOf(live, JSON.parse(decodeURIComponent(new URL(String(input)).search.slice(1))))))
    const dump = await dumpDatabase({ client: cloudflare(live), accountId: 'acc', databaseId: 'db' }, leftOut)
    vi.restoreAllMocks()

    const restored = new DatabaseSync(':memory:')
    restored.exec(`PRAGMA foreign_keys = ON;\n${dump.schema}\n${dump.data}`)
    const columns = 'id, user_id, account_id, provider_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scope, id_token, password, created_at, updated_at'
    expect({
      inDump: JSON.stringify(dump).includes('google.id-token'),
      tables: dump.tables.includes('account') && dump.tables.includes('user'),
      account: Object.values(restored.prepare(`SELECT ${columns} FROM account`).get()!),
      user: restored.prepare('SELECT email FROM user').get(),
    }).toEqual({
      inDump: false,
      tables: true,
      account: account.map((value, i) => (i === 9 ? null : value)),
      user: { email: 'ada@acme.com' },
    })
  })
})

describe('keys for a new worker', () => {
  const slot = { environmentId: '01ENV', name: 'API_KEY' }
  // A database holding these values and a purged one, answering as the D1 API does
  const holding = (values: Array<{ encrypted: string; iv: string }>) => {
    const db = new DatabaseSync(':memory:')
    db.exec('CREATE TABLE secret_event (id text PRIMARY KEY, environment_id text, name text, operation text, value_encrypted text, iv text)')
    db.prepare("INSERT INTO secret_event VALUES ('a-purged', ?, ?, 'set', NULL, NULL)").run(slot.environmentId, slot.name)
    values.forEach((value, i) => db.prepare("INSERT INTO secret_event VALUES (?, ?, ?, 'set', ?, ?)").run(`e${i}`, slot.environmentId, slot.name, value.encrypted, value.iv))
    return {
      async d1Query({ sql }: { sql: string }) {
        return [{ results: db.prepare(sql).all() }]
      },
    } as unknown as CfClient
  }
  const outcome = (client: CfClient, keys: { betterAuthSecret: string; encryptionKey?: string; encryptionKeys?: KeyRing }) =>
    assertSecretsDecryptDatabase({ client, accountId: 'acc', databaseId: 'db', ...keys }).then(() => 'ok', (error: Error) => error.message.split('. ')[0])
  const ring: KeyRing = { current: 'abc123', keys: { abc123: Buffer.alloc(32, 7).toString('base64') } }

  test('must decrypt a stored value, v2 under the ring or from before v2 under key 0', async () => {
    const v2 = await sealValue({ keyId: 'abc123', key: ring.keys.abc123!, slot, plaintext: 'secret' })
    // From before v2: key 0 derived from BETTER_AUTH_SECRET, no additional data
    const iv = Buffer.alloc(12, 1)
    const key0 = await webcrypto.subtle.importKey('raw', new Uint8Array(baseKeyOf({ betterAuthSecret: 'auth-secret' })), { name: 'AES-GCM' }, false, ['encrypt'])
    const v1 = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key0, new TextEncoder().encode('secret'))).toString('base64')
    const v2Row = holding([v2])
    const v1Row = holding([{ encrypted: v1, iv: iv.toString('base64') }])
    expect({
      v2WithRing: await outcome(v2Row, { betterAuthSecret: 'auth-secret', encryptionKeys: ring }),
      v2WithoutRing: await outcome(v2Row, { betterAuthSecret: 'auth-secret' }),
      v1WithSecret: await outcome(v1Row, { betterAuthSecret: 'auth-secret' }),
      v1WithNewSecret: await outcome(v1Row, { betterAuthSecret: 'fresh-secret' }),
      nothingStored: await outcome(holding([]), { betterAuthSecret: 'fresh-secret' }),
    }).toEqual({
      v2WithRing: 'ok',
      v2WithoutRing: 'This D1 database already stores secrets under key abc123, which the keys for this deploy cannot decrypt',
      v1WithSecret: 'ok',
      v1WithNewSecret: 'This D1 database already stores secrets under key 0, which the keys for this deploy cannot decrypt',
      nothingStored: 'ok',
    })
  })

  test('must decrypt a value under every key in use, as an unfinished rotation leaves them', async () => {
    const key0 = baseKeyOf({ betterAuthSecret: 'auth-secret' }).toString('base64')
    // The oldest value under key 0, newer ones under the ring's key
    const mixed = holding([
      await sealValue({ keyId: '0', key: key0, slot, plaintext: 'under key 0' }),
      await sealValue({ keyId: 'abc123', key: ring.keys.abc123!, slot, plaintext: 'under the ring' }),
      await sealValue({ keyId: 'abc123', key: ring.keys.abc123!, slot, plaintext: 'under the ring too' }),
    ])
    expect({
      withoutRing: await outcome(mixed, { betterAuthSecret: 'auth-secret' }),
      withRing: await outcome(mixed, { betterAuthSecret: 'auth-secret', encryptionKeys: ring }),
      withRingOnly: await outcome(mixed, { betterAuthSecret: 'fresh-secret', encryptionKeys: ring }),
    }).toEqual({
      withoutRing: 'This D1 database already stores secrets under key abc123, which the keys for this deploy cannot decrypt',
      withRing: 'ok',
      withRingOnly: 'This D1 database already stores secrets under key 0, which the keys for this deploy cannot decrypt',
    })
  })
})
