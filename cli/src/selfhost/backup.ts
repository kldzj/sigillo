/**
 * Backups of a self-hosted instance (`self-host --backup` and `--restore`).
 *
 * A backup holds both D1 databases as Cloudflare's export API dumps them,
 * without the tables that only matter to live logins and without sign-in ID
 * tokens, gzipped and encrypted
 * with age to the deployment's backup key in selfhost.json. It is a standard
 * age file, so `age -d` opens it too. The instance's keys are never in it:
 * a restore takes them from selfhost.json, imports into fresh databases, and
 * checks their history (history.ts) before the Workers switch to them.
 */

import { createHash } from 'node:crypto'
import { gunzipSync, gzipSync } from 'node:zlib'
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption'
import type { CfClient } from './cloudflare.js'
import { KEY_ID_OF_VALUE, type KeyRing, type Query } from './rotate.js'

// Sessions, codes and grants of logins in progress, and rate limit counters:
// a restore signs everyone out rather than bring them back. Only these
// tables point at each other, so the rest imports without them.
export const LEFT_OUT = {
  app: ['session', 'verification', 'rate_limit', 'device_code', 'step_up_request', 'step_up_grant', 'enrollment_approval'],
  provider: ['session', 'verification', 'rate_limit', 'oauth_access_token', 'oauth_refresh_token', 'oauth_client_assertion'],
}

// Columns a backup leaves empty. better-auth keeps Google's ID token, and in
// the app the login provider's, unencrypted, and neither worker reads it
// after the sign-in that stored it.
export const LEFT_EMPTY: Record<string, string[]> = { account: ['id_token'] }

export type DatabaseDump = {
  /** CREATE statements of every table, left out ones too */
  schema: string
  /** The rows of every table but the left out ones */
  data: string
  tables: string[]
  migrations: string[]
}

export type Backup = {
  format: 'sigillo-backup'
  version: 1
  createdAt: string
  workerName: string
  /** The Sigillo version the instance ran */
  sigilloVersion: string | null
  /** The keys its values are encrypted with, by id ('0' for key 0) and fingerprint: a rotation since retires them */
  keys: Record<string, string>
  databases: { app: DatabaseDump; provider: DatabaseDump | null }
}

export function newBackupIdentity(): Promise<string> {
  return generateX25519Identity()
}

export async function sealBackup(backup: Backup, identity: string): Promise<Uint8Array> {
  const encrypter = new Encrypter()
  encrypter.addRecipient(await identityToRecipient(identity))
  return encrypter.encrypt(gzipSync(JSON.stringify(backup)))
}

export async function openBackup(file: Uint8Array, identity: string): Promise<Backup> {
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  let packed: Uint8Array
  try {
    packed = await decrypter.decrypt(file)
  } catch {
    throw new Error("This backup doesn't open with the backup key in ~/.sigillo/selfhost.json: it was made for another deployment, or isn't a Sigillo backup")
  }
  const backup = JSON.parse(gunzipSync(packed).toString('utf8')) as Backup
  if (backup.format !== 'sigillo-backup' || backup.version !== 1) throw new Error('Not a Sigillo backup this version can read')
  return backup
}

export function backupFileName(workerName: string, at: Date): string {
  return `${workerName}-${at.toISOString().replace(/[:.]/g, '-').replace(/-\d+Z$/, 'Z')}.backup.age`
}

type Database = { client: CfClient; accountId: string; databaseId: string }

export function queryOf({ client, accountId, databaseId }: Database): Query {
  return async (sql, params) => (await client.d1Query({ accountId, databaseId, sql, params }))[0]?.results ?? []
}

async function exportSql(database: Database, dumpOptions: { no_data?: boolean; no_schema?: boolean; tables?: string[] }): Promise<string> {
  let step = await database.client.d1ExportStep({ ...database, dumpOptions })
  // The export API answers once it has news, so no pause between polls
  for (let polls = 0; step.status !== 'complete'; polls++) {
    if (step.status === 'error') throw new Error(`Exporting the database failed: ${step.error ?? step.messages?.join(' ') ?? 'no reason given'}`)
    if (polls > 1000 || !step.at_bookmark) throw new Error('Exporting the database did not finish')
    step = await database.client.d1ExportStep({ ...database, dumpOptions, bookmark: step.at_bookmark })
  }
  const res = await fetch(step.result!.signed_url)
  if (!res.ok) throw new Error(`Downloading the database export failed: ${res.status}`)
  return res.text()
}

/** Both halves of one database: every table's schema, and the rows of all but the left out ones */
export async function dumpDatabase(database: Database, leftOut: string[]): Promise<DatabaseDump> {
  const query = queryOf(database)
  const tables = (await query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name"))
    .map((row) => String(row.name))
  const migrations = tables.includes('d1_migrations')
    ? (await query('SELECT name FROM d1_migrations ORDER BY id')).map((row) => String(row.name))
    : []
  const kept = tables.filter((table) => !leftOut.includes(table))
  // D1 refuses pragma_foreign_key_list joined to sqlite_master, so one table at a time
  const references = new Map<string, string[]>()
  for (const table of kept) {
    if (!/^[A-Za-z0-9_]+$/.test(table)) throw new Error(`Unexpected table name: ${table}`)
    references.set(table, (await query(`SELECT "table" AS ref FROM pragma_foreign_key_list('${table}')`)).map((row) => String(row.ref)))
  }
  const schema = await exportSql(database, { no_data: true })
  // Tables with columns left empty are read here instead of exported
  const exported = kept.filter((table) => !LEFT_EMPTY[table])
  const statements = [
    exported.length > 0 ? await exportSql(database, { no_schema: true, tables: exported }) : '',
    ...(await Promise.all(kept.filter((table) => LEFT_EMPTY[table]).map((table) => insertStatements(query, table, LEFT_EMPTY[table]!)))).flat(),
  ].filter(Boolean)
  return {
    schema,
    data: statements.length > 0 ? orderByReferences(statements.join('\n'), references) : '',
    tables: kept,
    migrations,
  }
}

/** A table's rows as INSERT statements, as D1's export writes them (SQLite quotes each value), with these columns NULL */
async function insertStatements(query: Query, table: string, empty: string[]): Promise<string[]> {
  const columns = (await query(`SELECT name FROM pragma_table_info('${table}') ORDER BY cid`)).map((row) => String(row.name))
  for (const column of columns) if (!/^[A-Za-z0-9_]+$/.test(column)) throw new Error(`Unexpected column name: ${table}.${column}`)
  const values = columns.map((column) => (empty.includes(column) ? "'NULL'" : `quote("${column}")`)).join(" || ',' || ")
  const page = (where: string) => query(`SELECT rowid AS r, 'INSERT INTO "${table}" VALUES(' || ${values} || ');' AS statement FROM "${table}" ${where} ORDER BY rowid LIMIT 500`)
  const statements: string[] = []
  // A page at a time, to keep each answer small
  for (let rows = await page(''); rows.length > 0; rows = await page(`WHERE rowid > ${Number(rows.at(-1)!.r)}`)) {
    statements.push(...rows.map((row) => String(row.statement)))
  }
  return statements
}

/** SQL statements, split at each ';' outside quotes */
export function splitStatements(sql: string): string[] {
  const statements: string[] = []
  let start = 0
  let quote: string | null = null
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i]!
    if (quote) {
      // A doubled quote is one quote inside the string
      if (c === quote && sql[i + 1] === quote) i++
      else if (c === quote) quote = null
    } else if (c === "'" || c === '"') {
      quote = c
    } else if (c === ';') {
      statements.push(sql.slice(start, i + 1).trim())
      start = i + 1
    }
  }
  const rest = sql.slice(start).trim()
  if (rest) statements.push(rest)
  return statements.filter(Boolean)
}

/**
 * D1's export writes the tables' rows in an order of its own, often before
 * the rows they point at, and an import checks foreign keys row by row. So
 * the rows are regrouped: every table after the tables it references, each
 * table's rows in their order, anything else first.
 */
export function orderByReferences(sql: string, references: Map<string, string[]>): string {
  const byTable = new Map<string, string[]>()
  const other: string[] = []
  for (const statement of splitStatements(sql)) {
    const table = /^INSERT INTO "?([A-Za-z0-9_]+)"?/i.exec(statement)?.[1]
    if (!table) other.push(statement)
    else byTable.set(table, [...(byTable.get(table) ?? []), statement])
  }
  const ordered: string[] = []
  const seen = new Set<string>()
  const visit = (table: string) => {
    if (seen.has(table)) return
    seen.add(table)
    for (const referenced of references.get(table) ?? []) visit(referenced)
    ordered.push(...(byTable.get(table) ?? []))
  }
  for (const table of byTable.keys()) visit(table)
  return [...other, ...ordered].join('\n')
}

/** The ids of the keys stored values are encrypted with, '0' for key 0 */
export async function keyIdsInUse(database: Database): Promise<string[]> {
  const rows = await queryOf(database)(`SELECT DISTINCT ${KEY_ID_OF_VALUE} AS key_id FROM secret_event WHERE value_encrypted IS NOT NULL ORDER BY key_id`)
  return rows.map((row) => String(row.key_id))
}

/** A short fingerprint of the key with this id in selfhost.json, if it has one */
export function keyFingerprint(id: string, { ring, baseKey }: { ring: KeyRing | undefined; baseKey: Buffer }): string | undefined {
  const raw = id === '0' ? baseKey : ring?.keys[id] ? Buffer.from(ring.keys[id]!, 'base64') : undefined
  return raw && createHash('sha256').update(raw).digest('hex').slice(0, 16)
}

/** Imports a dump into an empty database */
export async function loadDatabase(database: Database, dump: DatabaseDump): Promise<void> {
  // Rows come in table order, before the rows they point at
  const sql = `PRAGMA defer_foreign_keys = true;\n${dump.schema}\n${dump.data}`
  const etag = createHash('md5').update(sql).digest('hex')
  const at = (body: Parameters<CfClient['d1ImportStep']>[0]['body']) => database.client.d1ImportStep({ ...database, body })
  let step = await at({ action: 'init', etag })
  if (step.upload_url) {
    const upload = await fetch(step.upload_url, { method: 'PUT', body: sql, headers: { 'Content-Length': String(Buffer.byteLength(sql)) } })
    if (upload.status !== 200 || upload.headers.get('etag')?.replace(/^"|"$/g, '') !== etag) {
      throw new Error('Uploading the backup to D1 failed: run the restore again')
    }
    step = await at({ action: 'ingest', etag, filename: step.filename! })
  }
  for (let polls = 0; step.status !== 'complete'; polls++) {
    if (step.status === 'error' || step.success === false) {
      throw new Error(`Importing the backup into D1 failed: ${[...(step.errors ?? []), step.error].filter(Boolean).join(' ') || 'no reason given'}`)
    }
    if (polls > 1000 || !step.at_bookmark) throw new Error('Importing the backup into D1 did not finish')
    step = await at({ action: 'poll', current_bookmark: step.at_bookmark })
  }
}
