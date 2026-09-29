// The self-host commands run against a fake Cloudflare account: its D1
// databases are SQLite databases, the state file lives in memory, and there
// is no terminal, so nothing prompts.

import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, test, vi } from 'vitest'
import type { CfClient, SelfhostState } from '../src/selfhost/cloudflare.js'
import { openValue, sealValue, type KeyRing } from '../src/selfhost/rotate.js'

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

const { rotateKey } = await import('../src/selfhost/cli.js')

afterEach(() => {
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
