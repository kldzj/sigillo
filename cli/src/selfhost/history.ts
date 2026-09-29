/**
 * Checks the tamper-evident history of a database before an instance serves
 * it, after a restore. It rebuilds every row's preimage from the database, as
 * the Worker's audit route does (app/src/audit.ts), and checks its hash and
 * the Worker's signature. The signing and digest keys come from
 * BETTER_AUTH_SECRET, and a set event's digest from its decrypted value, so
 * only a restore from the same deployment passes. Nothing else in the
 * database is checked.
 */

import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openValue, type KeyRing, type Query } from './rotate.js'

const subtle = webcrypto.subtle
const encoder = new TextEncoder()
const ZERO_HASH = '0'.repeat(64)
// An Ed25519 private key in PKCS#8 is this fixed prefix and the 32-byte seed
const PKCS8_ED25519_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]

async function deriveBytes(secret: string, label: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: encoder.encode(label) }, base, 256))
}

/** The Worker's history keys: the Ed25519 key it signs with (to verify), and the HMAC key of value digests */
async function historyKeys(betterAuthSecret: string) {
  const seed = await deriveBytes(betterAuthSecret, 'sigillo audit signing key v1')
  const signing = await subtle.importKey('pkcs8', new Uint8Array([...PKCS8_ED25519_PREFIX, ...seed]), { name: 'Ed25519' }, true, ['sign'])
  const { x } = await subtle.exportKey('jwk', signing)
  const verify = await subtle.importKey('raw', new Uint8Array(Buffer.from(x!, 'base64url')), { name: 'Ed25519' }, false, ['verify'])
  const digest = await subtle.importKey('raw', await deriveBytes(betterAuthSecret, 'sigillo audit value digest v1'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return { verify, digest }
}

async function chainHash(prevHash: string, preimage: string): Promise<string> {
  return Buffer.from(await subtle.digest('SHA-256', encoder.encode(prevHash + preimage))).toString('hex')
}

type Row = Record<string, unknown>

// As app/src/audit.ts builds them: any change here breaks every row
function eventPreimage(row: Row, digest: string | null): string {
  return JSON.stringify([row.adopted ? 'adopted' : 'event', row.environment_id, row.seq, row.id, row.name, row.operation, digest, row.actor ?? '', row.created_at])
}

function readPreimage(row: Row): string {
  return JSON.stringify(['read', row.environment_id, row.seq, row.id, row.actor, row.kind, JSON.parse(String(row.names)), row.ip_address ?? null, row.created_at])
}

/**
 * A set event's preimage holds its value's digest, so a row whose value was
 * removed in the database verifies like one that was purged. The only way
 * the Worker removes a value is a purge of an old one: the same name was set
 * again or deleted after it, and purged after that. Returns the seq of the
 * first chained set event that lost its value any other way, as `sigillo
 * audit verify` (cli/zig/src/audit.zig) finds it.
 */
function lostValue(chained: Row[]): number | undefined {
  // Per name, walking from the newest row back: whether a purge comes later,
  // and whether a set or delete that a purge follows comes later
  const later = new Map<string, { purge: boolean; replacedThenPurged: boolean }>()
  let lost: number | undefined
  for (const row of [...chained].reverse()) {
    const seen = later.get(String(row.name)) ?? { purge: false, replacedThenPurged: false }
    later.set(String(row.name), seen)
    // Its digest came from value_digest, as for a purged value
    if (row.operation === 'set' && (!row.value_encrypted || !row.iv) && !seen.replacedThenPurged) lost = Number(row.seq)
    if (row.operation === 'purge') seen.purge = true
    else if (seen.purge && (row.operation === 'set' || row.operation === 'delete')) seen.replacedThenPurged = true
  }
  return lost
}

type Head = { seq: number; hash: string }

/** The heads of one environment's chains as `sigillo audit verify` last saw them */
export type Witness = { project: string | null; environment: string; events: Head | null; reads: Head | null }

/**
 * What `sigillo audit verify` saw of this instance's environments on this
 * machine, from ~/.sigillo/audit.json. It keys the file by '<api url>
 * <project id> <environment id or slug>', and did by '<api url> <environment
 * id>' before that (cli/zig/src/audit.zig).
 */
export function auditWitnesses(urls: string[], file = witnessFile()): Witness[] {
  let witnesses: Record<string, { events?: Head | null; reads?: Head | null }>
  try {
    witnesses = JSON.parse(readFileSync(file, 'utf8')) ?? {}
  } catch {
    return []
  }
  const instance = new Set(urls.map((url) => url.replace(/\/+$/, '')))
  return Object.entries(witnesses).flatMap(([key, seen]) => {
    const [url, ...ids] = key.split(' ')
    if (!instance.has(url!.replace(/\/+$/, '')) || ids.length < 1 || ids.length > 2) return []
    return [{ project: ids.length === 2 ? ids[0]! : null, environment: ids.at(-1)!, events: seen?.events ?? null, reads: seen?.reads ?? null }]
  })
}

// Where the CLI keeps its config (cli/zig/src/config.zig)
function witnessFile(): string {
  return process.platform === 'win32'
    ? path.join(process.env.APPDATA ?? process.env.LOCALAPPDATA ?? os.homedir(), 'sigillo', 'audit.json')
    : path.join(os.homedir(), '.sigillo', 'audit.json')
}

export type HistoryCheck = {
  environments: number
  /** Rows whose hash and signature checked out */
  rows: number
  /** Rows added around a chain, which the Worker ignores */
  outside: number
  /** Environments with changes but no chain, so nothing checked */
  unsigned: number
  /** Where a chain is shorter than, or differs from, what `sigillo audit verify` saw */
  sinceLastCheck: string[]
  problems: string[]
}

/**
 * Checks both chains of every environment: each row's hash and signature,
 * that only purges removed values, and the heads against what `sigillo audit
 * verify` saw. A chain can't show rows removed from its end; only a witness
 * that saw them can.
 */
export async function verifyHistory({ query, betterAuthSecret, ring, baseKey, witnesses = [] }: {
  query: Query
  betterAuthSecret: string
  ring: KeyRing | undefined
  baseKey: Buffer
  witnesses?: Witness[]
}): Promise<HistoryCheck> {
  const keys = await historyKeys(betterAuthSecret)
  const digestOf = async (row: Row): Promise<string> => {
    const slot = { environmentId: String(row.environment_id), name: String(row.name) }
    if (!row.value_encrypted || !row.iv) return row.value_digest ? String(row.value_digest) : 'no value'
    try {
      const value = await openValue({ ring, baseKey, encrypted: String(row.value_encrypted), iv: String(row.iv), slot })
      const mac = await subtle.sign('HMAC', keys.digest, encoder.encode(JSON.stringify([slot.environmentId, slot.name, value])))
      return Buffer.from(mac).toString('base64')
    } catch {
      return 'undecryptable'
    }
  }
  const environments = await query('SELECT id, project_id, slug FROM environment ORDER BY id')
  const events = await query('SELECT * FROM secret_event ORDER BY environment_id, seq')
  const reads = await query('SELECT * FROM secret_read ORDER BY environment_id, seq')
  const check: HistoryCheck = { environments: environments.length, rows: 0, outside: 0, unsigned: 0, sinceLastCheck: [], problems: [] }
  const witnessed = new Set<Witness>()
  for (const { id, project_id: project, slug } of environments) {
    const changes = events.filter((row) => row.environment_id === id)
    const chains = { changes: changes.filter((row) => row.seq !== null), reads: reads.filter((row) => row.environment_id === id) }
    // Rows without seq in an environment with a chain were added around it;
    // without a chain, they join it on the next change
    if (chains.changes.length > 0) check.outside += changes.length - chains.changes.length
    else if (changes.length > 0) check.unsigned++
    for (const witness of witnesses.filter((w) => w.environment === id || (w.project === project && w.environment === slug))) {
      witnessed.add(witness)
      for (const [chain, seen] of [['changes', witness.events], ['reads', witness.reads]] as const) {
        if (!seen) continue
        const row = chains[chain].find((r) => Number(r.seq) === seen.seq)
        if (!row) check.sinceLastCheck.push(`environment ${String(id)}: its ${chain} have ${chains[chain].length} rows, but had ${seen.seq} when sigillo audit verify last checked them`)
        else if (row.hash !== seen.hash) check.sinceLastCheck.push(`environment ${String(id)}: ${chain} row ${seen.seq} differs from the one sigillo audit verify last checked`)
      }
    }
    for (const [chain, rows] of Object.entries(chains)) {
      let head = { seq: 0, hash: ZERO_HASH }
      for (const row of rows) {
        const seq = head.seq + 1
        const where = `environment ${String(id)}, ${chain} row ${seq}`
        if (Number(row.seq) !== seq) {
          check.problems.push(`${where} is missing`)
          break
        }
        const preimage = chain === 'changes' ? eventPreimage(row, row.operation === 'set' ? await digestOf(row) : null) : readPreimage(row)
        if (await chainHash(head.hash, preimage) !== row.hash) {
          check.problems.push(`${where} does not match its hash`)
          break
        }
        if (!await subtle.verify({ name: 'Ed25519' }, keys.verify, new Uint8Array(Buffer.from(String(row.signature), 'base64')), new Uint8Array(Buffer.from(String(row.hash), 'hex')))) {
          check.problems.push(`${where} has an invalid signature`)
          break
        }
        head = { seq, hash: String(row.hash) }
        check.rows++
      }
      const lost = chain === 'changes' && head.seq === rows.length ? lostValue(rows) : undefined
      if (lost !== undefined) check.problems.push(`environment ${String(id)}, changes row ${lost} lost its value without a purge`)
    }
  }
  for (const witness of witnesses.filter((w) => !witnessed.has(w))) {
    check.sinceLastCheck.push(`environment ${witness.environment}${witness.project ? ` of project ${witness.project}` : ''}: not in the backup, but sigillo audit verify checked it`)
  }
  return check
}
