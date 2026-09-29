/**
 * Checks the tamper-evident history of a database before an instance serves
 * it, after a restore. It rebuilds every row's preimage from the database, as
 * the Worker's audit route does (app/src/audit.ts), and checks its hash and
 * the Worker's signature. The signing and digest keys come from
 * BETTER_AUTH_SECRET, and a set event's digest from its decrypted value, so
 * only a restore from the same deployment passes.
 */

import { webcrypto } from 'node:crypto'
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

export type HistoryCheck = { environments: number; rows: number; outside: number; problems: string[] }

/** Checks both chains of every environment: each row's hash and signature, and that only purges removed values */
export async function verifyHistory({ query, betterAuthSecret, ring, baseKey }: {
  query: Query
  betterAuthSecret: string
  ring: KeyRing | undefined
  baseKey: Buffer
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
  const environments = await query('SELECT id FROM environment ORDER BY id')
  const events = await query('SELECT * FROM secret_event ORDER BY environment_id, seq')
  const reads = await query('SELECT * FROM secret_read ORDER BY environment_id, seq')
  const check: HistoryCheck = { environments: environments.length, rows: 0, outside: 0, problems: [] }
  for (const { id } of environments) {
    const changes = events.filter((row) => row.environment_id === id)
    const chains = { changes: changes.filter((row) => row.seq !== null), reads: reads.filter((row) => row.environment_id === id) }
    // Rows without seq in an environment with a chain were added around it;
    // without a chain, they join it on the next change
    if (chains.changes.length > 0) check.outside += changes.length - chains.changes.length
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
  return check
}
