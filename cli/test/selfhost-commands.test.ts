// The self-host commands run against a fake Cloudflare account: its D1
// databases are SQLite databases, the state file lives in memory, and there
// is no terminal, so nothing prompts.

import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import type { CfClient, DeploymentState, SelfhostState } from '../src/selfhost/cloudflare.js'
import { baseKeyOf, openValue, sealValue, type KeyRing } from '../src/selfhost/rotate.js'
import { keyFingerprint, newBackupIdentity, sealBackup, type Backup } from '../src/selfhost/backup.js'

const fake = vi.hoisted(() => ({ state: {} as SelfhostState, client: undefined as unknown, logs: [] as string[] }))

vi.mock('../src/selfhost/cloudflare.js', async (importOriginal) => ({
  ...await importOriginal<typeof import('../src/selfhost/cloudflare.js')>(),
  readState: () => structuredClone(fake.state),
  writeState: (state: SelfhostState) => {
    fake.state = structuredClone(state)
  },
  resolveCloudflareAuth: async () => fake.client,
}))

vi.mock('goke', async (importOriginal) => ({ ...await importOriginal<typeof import('goke')>(), isAgent: true }))

vi.mock('@clack/prompts', () => {
  const log = (level: string) => (message: string) => {
    fake.logs.push(`${level}: ${message}`)
  }
  const ask = async () => {
    throw new Error('prompted without a terminal')
  }
  return {
    intro: log('intro'),
    outro: log('outro'),
    note: log('note'),
    log: { info: log('info'), warn: log('warn'), error: log('error'), success: log('success') },
    spinner: () => ({ start: log('start'), stop: log('stop'), message: () => {} }),
    confirm: ask,
    password: ask,
    text: ask,
    select: ask,
    isCancel: () => false,
  }
})

const { restoreDeployment, rotateKey } = await import('../src/selfhost/cli.js')

// A home of its own, for the files the commands read there
const home = process.env.HOME
let dir = ''
beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'sigillo-commands-'))
  process.env.HOME = dir
})
afterEach(() => {
  process.env.HOME = home
  vi.useRealTimers()
  vi.restoreAllMocks()
  fake.logs = []
})

// A D1 database as the query API answers
function d1(db: DatabaseSync) {
  return (sql: string, params: string[] = []): Array<Record<string, unknown>> => {
    if (/^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql)) return db.prepare(sql).all(...params) as Array<Record<string, unknown>>
    if (params.length > 0) db.prepare(sql).run(...params)
    else db.exec(sql)
    return []
  }
}

// Runs a command that waits on timers to the end
async function withTimers<T>(run: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ['setTimeout'] })
  let done = false
  const result = run().finally(() => {
    done = true
  })
  while (!done) await vi.advanceTimersByTimeAsync(10_000)
  return result
}

describe('rotating the key', () => {
  const key0 = Buffer.alloc(32, 1).toString('base64')
  const k1 = Buffer.alloc(32, 2).toString('base64')
  const slot = (name: string) => ({ environmentId: 'env', name })

  test('an unfinished rotation gives the Worker its key ring again before re-encrypting', async () => {
    const db = new DatabaseSync(':memory:')
    db.exec('CREATE TABLE secret_event (id text PRIMARY KEY, environment_id text, name text, operation text, value_encrypted text, iv text)')
    const store = (id: string, name: string, value: { encrypted: string; iv: string }) =>
      db.prepare("INSERT INTO secret_event VALUES (?, 'env', ?, 'set', ?, ?)").run(id, name, value.encrypted, value.iv)
    store('a', 'OLD', await sealValue({ keyId: '0', key: key0, slot: slot('OLD'), plaintext: 'under key 0' }))
    store('b', 'NEW', await sealValue({ keyId: 'k1', key: k1, slot: slot('NEW'), plaintext: 'under k1' }))
    // The first run saved the new ring, then stopped before the Worker had it
    const ring: KeyRing = { current: 'k1', keys: { k1 } }
    fake.state = { deployments: { 'acc/sigillo': { accountId: 'acc', workerName: 'sigillo', databaseId: 'db', betterAuthSecret: 'secret', encryptionKey: key0, encryptionKeys: ring } } }
    const query = d1(db)
    const older = () => Number(query("SELECT count(*) AS n FROM secret_event WHERE substr(value_encrypted, 1, 6) <> 'v2.k1.'")[0]!.n)
    const secrets: string[] = []
    fake.client = {
      async d1Query({ sql, params }: { sql: string; params?: string[] }) {
        return [{ results: query(sql, params) }]
      },
      async putWorkerSecret({ scriptName, name, text }: { scriptName: string; name: string; text: string }) {
        secrets.push(`put ${scriptName} ${name} ${text}, ${older()} values under an older key`)
      },
      async deleteWorkerSecret({ scriptName, name }: { scriptName: string; name: string }) {
        secrets.push(`delete ${scriptName} ${name}`)
      },
    } as unknown as CfClient

    await withTimers(() => rotateKey({}))
    const rows = query('SELECT name, value_encrypted, iv FROM secret_event ORDER BY id')
    expect({
      secrets,
      values: await Promise.all(rows.map((row) => openValue({ ring, baseKey: Buffer.alloc(32), encrypted: String(row.value_encrypted), iv: String(row.iv), slot: slot(String(row.name)) }))),
      saved: fake.state.deployments!['acc/sigillo'],
    }).toEqual({
      secrets: [
        `put sigillo ENCRYPTION_KEYS ${JSON.stringify(ring)}, 1 values under an older key`,
        `put sigillo ENCRYPTION_KEYS ${JSON.stringify(ring)}, 0 values under an older key`,
        'delete sigillo ENCRYPTION_KEY',
      ],
      values: ['under key 0', 'under k1'],
      saved: { accountId: 'acc', workerName: 'sigillo', databaseId: 'db', betterAuthSecret: 'secret', encryptionKeys: ring },
    })
  })
})

// A real history, written by the Worker in the app's test suite with this BETTER_AUTH_SECRET
const fixture = JSON.parse(readFileSync(new URL('./fixtures/history.json', import.meta.url), 'utf8'))
const secret = 'test-secret-at-least-32-characters-long!!'
const APP_SCHEMA = `CREATE TABLE environment (id text PRIMARY KEY, project_id text, slug text);
CREATE TABLE secret_event (id text PRIMARY KEY, environment_id text, name text, operation text, value_encrypted text, iv text, value_digest text,
  user_id text, api_token_id text, created_at integer, actor text, seq integer, hash text, signature text, adopted integer);
CREATE TABLE secret_read (id text PRIMARY KEY, environment_id text, actor text, kind text, names text, ip_address text, created_at integer, seq integer, hash text, signature text);`
const PROVIDER_SCHEMA = 'CREATE TABLE jwks (id text PRIMARY KEY, public_key text, private_key text, created_at integer);'

// Rows as D1's export writes them, every value quoted by SQLite
function exportRows(db: DatabaseSync, table: string): string {
  const columns = (db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all() as Array<{ name: string }>).map((row) => `quote("${row.name}")`)
  return (db.prepare(`SELECT 'INSERT INTO "${table}" VALUES(' || ${columns.join(" || ',' || ")} || ');' AS statement FROM "${table}"`).all() as Array<{ statement: string }>)
    .map((row) => row.statement).join('\n')
}

// The deployment the fixture's history comes from, with its backup key
function deployment(backupIdentity: string): DeploymentState {
  return {
    accountId: 'acc',
    workerName: 'sigillo',
    databaseId: 'app-before',
    betterAuthSecret: secret,
    backupIdentity,
    providerWorkerName: 'sigillo-auth',
    providerDatabaseId: 'auth-before',
    providerAuthSecret: 'provider-secret',
    googleClientId: 'google-id',
    googleClientSecret: 'google-secret',
    allowedUsers: '',
    deployedVersion: '0.16.0',
    url: 'https://sigillo.acme.workers.dev',
  }
}

// A backup of both databases, saved in the test's home, and the state it restores with
async function backupOf(): Promise<{ file: string; saved: DeploymentState }> {
  const app = new DatabaseSync(':memory:')
  app.exec(APP_SCHEMA)
  app.prepare("INSERT INTO environment VALUES (?, 'p1', 'prod')").run(fixture.environmentId)
  for (const e of fixture.events) {
    app.prepare('INSERT INTO secret_event VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(e.id, e.environmentId, e.name, e.operation, e.valueEncrypted, e.iv, e.valueDigest,
      e.userId, e.apiTokenId, e.createdAt, e.actor, e.seq, e.hash, e.signature, e.adopted ? 1 : 0)
  }
  for (const r of fixture.reads) {
    app.prepare('INSERT INTO secret_read VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(r.id, r.environmentId, r.actor, r.kind, JSON.stringify(r.names), r.ipAddress, r.createdAt, r.seq, r.hash, r.signature)
  }
  const identity = await newBackupIdentity()
  const backup: Backup = {
    format: 'sigillo-backup',
    version: 1,
    createdAt: '2026-09-29T10:00:00.000Z',
    workerName: 'sigillo',
    sigilloVersion: '0.16.0',
    keys: { '0': keyFingerprint('0', { ring: undefined, baseKey: baseKeyOf({ betterAuthSecret: secret }) })! },
    databases: {
      app: { schema: APP_SCHEMA, data: ['environment', 'secret_event', 'secret_read'].map((table) => exportRows(app, table)).join('\n'), tables: ['environment', 'secret_event', 'secret_read'], migrations: [] },
      provider: { schema: PROVIDER_SCHEMA, data: `INSERT INTO "jwks" VALUES('j1','public','sealed private',1);`, tables: ['jwks'], migrations: [] },
    },
  }
  const file = path.join(dir, 'sigillo.backup.age')
  writeFileSync(file, await sealBackup(backup, identity))
  return { file, saved: deployment(identity) }
}

describe('restoring a backup', () => {
  test('needs --yes without a terminal, since it discards every change since the backup', async () => {
    const { file, saved } = await backupOf()
    fake.state = { deployments: { 'acc/sigillo': saved } }
    fake.client = {} as CfClient
    await expect(restoreDeployment({ restore: file })).rejects.toThrow(
      'A restore discards every change made to sigillo since the backup of 2026-09-29T10:00:00.000Z. Without a terminal to confirm that, pass --yes.',
    )
    expect(fake.state).toEqual({ deployments: { 'acc/sigillo': saved } })
  })
})
