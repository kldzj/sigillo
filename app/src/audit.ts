// Tamper-evident history: the secret_event and secret_read rows of each
// environment form two hash chains, like git. Rows are numbered 1, 2, 3...
// by seq. A row's hash covers the previous row's hash and the row itself
// (its preimage), and the Worker signs the hash with an Ed25519 key only it
// holds. `sigillo audit verify` remembers the last head it saw, so editing,
// removing or reordering a row it has seen shows up there. Rows after that
// head are only as good as the database: someone who can write to D1 can give
// themselves access, have the Worker write rows, and remove the newest ones
// before the next check. Rows from before the chain join it on their
// environment's next write, marked as adopted.
//
// Preimages are built from the rows as they are in D1 now, so the audit API
// can hand them out and a verifier only needs SHA-256 and Ed25519. A set
// event's preimage holds a keyed digest of its plaintext, not the ciphertext:
// swapping in another row's ciphertext changes the digest, while
// re-encrypting a value later does not. A purged value keeps its digest in
// value_digest, so its row still verifies once the value is gone. What says
// it was purged, not removed by hand, is a purge row after a later change of
// its secret (valuesGoneWithoutPurge).

import { env } from 'cloudflare:workers'
import * as orm from 'drizzle-orm'
import type { BatchItem } from 'drizzle-orm/batch'
import { ulid } from 'ulid'
import { getDb, schema } from 'db'
import { actorOf, encrypt, decrypt, deriveSecrets, getUserEnvironmentAccess, InvalidInputError } from './db.ts'
import { getSecretNameError } from './lib/utils.ts'
import { requireStepUp, requireProtectedAccess, requireAdminApproval, StepUpRequiredError, type Reader } from './step-up.ts'
import { securityEvent } from './security-log.ts'

const ZERO_HASH = '0'.repeat(64)
const encoder = new TextEncoder()

// ── Keys ────────────────────────────────────────────────────────────
// Both keys come from BETTER_AUTH_SECRET through HKDF, so the Worker needs no
// extra secret and D1 alone has neither.

async function deriveBytes(label: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey('raw', encoder.encode(env.BETTER_AUTH_SECRET), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: encoder.encode(label) }, base, 256)
  return new Uint8Array(bits)
}

// An Ed25519 private key in PKCS#8 is this fixed prefix and the 32-byte seed
const PKCS8_ED25519_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]

let keys: Promise<{ signing: CryptoKey; publicKey: string; digest: CryptoKey }> | undefined

function getKeys() {
  keys ??= (async () => {
    const seed = await deriveBytes('sigillo audit signing key v1')
    const signing = await crypto.subtle.importKey('pkcs8', new Uint8Array([...PKCS8_ED25519_PREFIX, ...seed]), { name: 'Ed25519' }, true, ['sign'])
    const jwk = await crypto.subtle.exportKey('jwk', signing) as JsonWebKey
    const digest = await crypto.subtle.importKey('raw', await deriveBytes('sigillo audit value digest v1'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    return { signing, publicKey: base64FromBase64Url(jwk.x!), digest }
  })()
  return keys
}

export async function getAuditPublicKey(): Promise<string> {
  return (await getKeys()).publicKey
}

// ── Hashing ─────────────────────────────────────────────────────────

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function base64FromBase64Url(value: string): string {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  return base64 + '='.repeat((4 - (base64.length % 4)) % 4)
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

// hash_n = SHA-256(hash_(n-1) as hex + preimage_n), hash_0 = 64 zeros
export async function chainHash(prevHash: string, preimage: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(prevHash + preimage))))
}

async function signHash(hash: string): Promise<string> {
  const { signing } = await getKeys()
  return toBase64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signing, fromHex(hash))))
}

async function valueDigest(environmentId: string, name: string, value: string): Promise<string> {
  const { digest } = await getKeys()
  const mac = await crypto.subtle.sign('HMAC', digest, encoder.encode(JSON.stringify([environmentId, name, value])))
  return toBase64(new Uint8Array(mac))
}

// The digest of a stored set event, from its ciphertext as it is in D1, or
// the one kept when its value was purged
async function storedValueDigest(row: { environmentId: string; name: string; valueEncrypted: string | null; iv: string | null; valueDigest: string | null }): Promise<string> {
  if (!row.valueEncrypted || !row.iv) return row.valueDigest ?? 'no value'
  try {
    return await valueDigest(row.environmentId, row.name, await decrypt(row.valueEncrypted, row.iv, row))
  } catch {
    return 'undecryptable'
  }
}

// An adopted row is one the Worker found in the database from before the
// chain, not a change it made: its preimage says so, so adopting a chain's
// rows a second time changes every hash
function eventPreimage(row: { environmentId: string; seq: number; id: string; name: string; operation: string; actor: string; createdAt: number; adopted: boolean }, digest: string | null): string {
  return JSON.stringify([row.adopted ? 'adopted' : 'event', row.environmentId, row.seq, row.id, row.name, row.operation, digest, row.actor, row.createdAt])
}

function readPreimage(row: { environmentId: string; seq: number; id: string; actor: string; kind: string; names: string[]; ipAddress: string | null; createdAt: number }): string {
  return JSON.stringify(['read', row.environmentId, row.seq, row.id, row.actor, row.kind, row.names, row.ipAddress, row.createdAt])
}

// ── Appending ───────────────────────────────────────────────────────
// A write reads each chain's head, then inserts the next rows in one batch.
// Two writers that read the same head both try the same seq; the unique
// (environment_id, seq) index refuses the second batch as a whole, which
// then reads the new head and tries again.

function isSeqConflict(error: unknown): boolean {
  for (let current = error; current; current = (current as { cause?: unknown }).cause) {
    if (/UNIQUE constraint failed: secret_(event|read)\.environment_id, secret_(event|read)\.seq/.test(String(current))) return true
  }
  return false
}

async function batchWithRetry(plan: () => Promise<BatchItem<'sqlite'>[]>) {
  const db = getDb()
  for (let attempt = 1; ; attempt++) {
    const [first, ...rest] = await plan()
    if (!first) return
    try {
      await db.batch([first, ...rest])
      return
    } catch (error) {
      if (attempt >= 25 || !isSeqConflict(error)) throw error
      // Spread out writers that keep colliding
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 10 * attempt))
    }
  }
}

type Head = { seq: number; hash: string }

async function eventHead(environmentId: string): Promise<Head | null> {
  const [head] = await getDb().select({ seq: schema.secretEvent.seq, hash: schema.secretEvent.hash })
    .from(schema.secretEvent)
    .where(orm.and(orm.eq(schema.secretEvent.environmentId, environmentId), orm.isNotNull(schema.secretEvent.seq)))
    .orderBy(orm.desc(schema.secretEvent.seq))
    .limit(1)
  return head ? { seq: head.seq!, hash: head.hash! } : null
}

// Rows from before the chain join it in their original order on their
// environment's first chained write. Once a chain exists, a row without seq
// was added around it: it stays out, and the replay ignores it.
async function adoptPriorEvents(environmentId: string): Promise<{ queries: BatchItem<'sqlite'>[]; head: Head | null }> {
  const db = getDb()
  const head = await eventHead(environmentId)
  if (head) return { queries: [], head }
  const prior = await db.select().from(schema.secretEvent)
    .where(orm.and(orm.eq(schema.secretEvent.environmentId, environmentId), orm.isNull(schema.secretEvent.seq)))
    .orderBy(schema.secretEvent.createdAt, schema.secretEvent.id)
  const queries: BatchItem<'sqlite'>[] = []
  let current: Head | null = null
  for (const row of prior) {
    const seq = (current?.seq ?? 0) + 1
    const actor = actorOf(row)
    const digest = row.operation === 'set' ? await storedValueDigest(row) : null
    const hash = await chainHash(current?.hash ?? ZERO_HASH, eventPreimage({ ...row, seq, actor, adopted: true }, digest))
    queries.push(db.update(schema.secretEvent)
      .set({ seq, actor, hash, signature: await signHash(hash), adopted: true })
      .where(orm.and(orm.eq(schema.secretEvent.id, row.id), orm.isNull(schema.secretEvent.seq))))
    current = { seq, hash }
  }
  return { queries, head: current }
}

export type NewSecretEvent = {
  environmentId: string
  name: string
  operation: 'set' | 'delete'
  // Plaintext of a set event
  value?: string
}

// Where a secret may be deleted: a name the set routes would refuse only
// where a secret has it, one made before names had rules, so nothing else
// such a name reaches the signed history
export async function environmentsToDeleteFrom(environmentIds: string[], name: string): Promise<string[]> {
  const nameError = getSecretNameError(name)
  if (!nameError) return environmentIds
  const holding: string[] = []
  for (const environmentId of environmentIds) {
    if ((await deriveSecrets(environmentId)).some((secret) => secret.name === name)) holding.push(environmentId)
  }
  if (holding.length === 0) throw new InvalidInputError(nameError)
  return holding
}

// The only way secret_event rows are written. Changing a protected
// environment takes the same passkey approval or machine token as reading it.
export async function appendSecretEvents({ author, events }: { author: Reader; events: NewSecretEvent[] }): Promise<{ id: string; name: string }[]> {
  // Text with a lone surrogate half doesn't survive encoding unchanged, so
  // its digest would never match again and break the history for good
  for (const event of events) {
    if (!event.name.isWellFormed() || !(event.value ?? '').isWellFormed()) throw new InvalidInputError('Secret names and values must be valid text')
  }
  await requireProtectedAccess({ environmentIds: events.map((event) => event.environmentId), reader: author })
  // Encrypt and digest once, outside the retry loop
  const prepared = await Promise.all(events.map(async (event) => {
    const value = event.operation === 'set' ? event.value ?? '' : null
    return {
      ...newRow({ environmentId: event.environmentId, name: event.name, operation: event.operation, author }),
      encrypted: value === null ? null : await encrypt(value, event),
      digest: value === null ? null : await valueDigest(event.environmentId, event.name, value),
    }
  }))
  await appendPrepared(prepared)
  return prepared.map((event) => ({ id: event.id, name: event.name }))
}

type PreparedEvent = ReturnType<typeof newRow> & { encrypted: { encrypted: string; iv: string } | null; digest: string | null }

function newRow({ environmentId, name, operation, author }: { environmentId: string; name: string; operation: 'set' | 'delete' | 'purge'; author: Reader }) {
  return { id: ulid(), createdAt: Date.now(), environmentId, name, operation, actor: actorOf(author), userId: author.userId, apiTokenId: author.apiTokenId }
}

// Chains and inserts the rows, with any other statements in the same batch
async function appendPrepared(prepared: PreparedEvent[], alongside: BatchItem<'sqlite'>[] = []) {
  const db = getDb()
  await batchWithRetry(async () => {
    const queries: BatchItem<'sqlite'>[] = []
    for (const environmentId of new Set(prepared.map((event) => event.environmentId))) {
      const adopted = await adoptPriorEvents(environmentId)
      queries.push(...adopted.queries)
      let head = adopted.head
      for (const event of prepared.filter((row) => row.environmentId === environmentId)) {
        const seq = (head?.seq ?? 0) + 1
        const hash = await chainHash(head?.hash ?? ZERO_HASH, eventPreimage({ ...event, seq, adopted: false }, event.digest))
        queries.push(db.insert(schema.secretEvent).values({
          id: event.id,
          environmentId,
          name: event.name,
          operation: event.operation,
          valueEncrypted: event.encrypted?.encrypted ?? null,
          iv: event.encrypted?.iv ?? null,
          userId: event.userId,
          apiTokenId: event.apiTokenId,
          createdAt: event.createdAt,
          actor: event.actor,
          seq,
          hash,
          signature: await signHash(hash),
        }))
        head = { seq, hash }
      }
    }
    return [...queries, ...alongside]
  })
}

// The rows holding an old value: every stored value but each secret's
// current one. Once there is a chain, rows outside it don't count, as in the
// replay.
async function findOldValues(environmentId: string) {
  const rows = await getDb().query.secretEvent.findMany({ where: { environmentId }, orderBy: { createdAt: 'asc' } })
  const chained = rows.some((row) => row.seq !== null)
  const current = new Set((await deriveSecrets(environmentId)).map((secret) => secret.id))
  return rows.filter((row) => (!chained || row.seq !== null) && row.operation === 'set' && row.valueEncrypted && row.iv && !current.has(row.id))
}

export async function countOldValues(environmentId: string): Promise<number> {
  return (await findOldValues(environmentId)).length
}

// The old values as they are now, each with the digest its row keeps once
// the value goes
export async function readOldValues(environmentId: string) {
  const old = await findOldValues(environmentId)
  const digests = await Promise.all(old.map((row) => storedValueDigest(row)))
  // Their digest couldn't be kept, and their rows would never verify again
  const unreadable = [...new Set(old.filter((_, i) => digests[i] === 'undecryptable').map((row) => row.name))]
  if (unreadable.length) throw new Error(`Old values of ${unreadable.join(', ')} can't be decrypted, so nothing was purged`)
  return old.map((row, i) => ({ id: row.id, name: row.name, iv: row.iv!, digest: digests[i]! }))
}

export type OldValue = Awaited<ReturnType<typeof readOldValues>>[number]

// A value changed between reading and removing it: a key rotation
// re-encrypted it, or another purge removed it
class OldValuesChangedError extends Error {}

// Removes an environment's old values: every value but each secret's
// current one. Their rows stay, with who and when, and keep the digest their
// history row was signed with, so the chain still verifies. A purge row per
// name records who removed them. The caller checks that it's an org admin's,
// with their passkey (requireOldValuesPurge).
export async function purgeOldValues({ environmentId, author, request = null }: { environmentId: string; author: Reader; request?: Request | null }): Promise<{ purged: number }> {
  for (let attempt = 1; ; attempt++) {
    const old = await readOldValues(environmentId)
    if (old.length === 0) return { purged: 0 }
    try {
      await removeOldValues({ environmentId, old, author, request })
      return { purged: old.length }
    } catch (error) {
      // Read them again
      if (attempt >= 3 || !(error instanceof OldValuesChangedError)) throw error
    }
  }
}

// Removes the values as read, all of them or none. A value changed since
// would stay, and its purge row and the security log would report a removal
// that didn't happen.
export async function removeOldValues({ environmentId, old, author, request = null }: { environmentId: string; old: OldValue[]; author: Reader; request?: Request | null }) {
  const db = getDb()
  const environment = await db.query.environment.findFirst({ where: { id: environmentId }, columns: { id: true, name: true, projectId: true } })
  if (!environment) throw new Error('Environment not found')
  const prepared = [...new Set(old.map((row) => row.name))].map((name) => ({ ...newRow({ environmentId, name, operation: 'purge', author }), encrypted: null, digest: null }))
  // Named only while every value still has the IV read, which re-encrypting
  // it changes and purging it clears. Otherwise the name is null and the
  // whole batch fails, before the updates below could match nothing.
  const asRead = JSON.stringify(old.map((row) => [row.id, row.iv]))
  const name = orm.sql`(select ${schema.environment.name} from ${schema.environment} where ${schema.environment.id} = ${environmentId} and (
    select count(*) from ${schema.secretEvent}, json_each(${asRead}) as seen
    where ${schema.secretEvent.id} = json_extract(seen.value, '$[0]') and ${schema.secretEvent.iv} = json_extract(seen.value, '$[1]')
  ) = ${old.length})`
  try {
    await appendPrepared(prepared, [
      securityEvent({
        request, author, kind: 'values.purged', where: { projectId: environment.projectId },
        subject: { id: environment.id, name }, details: { values: old.length, names: prepared.length },
      }),
      ...old.map((row) => db.update(schema.secretEvent)
        .set({ valueEncrypted: null, iv: null, valueDigest: row.digest })
        .where(orm.and(orm.eq(schema.secretEvent.id, row.id), orm.eq(schema.secretEvent.iv, row.iv)))),
    ])
  } catch (error) {
    const now = await db.select({ id: schema.secretEvent.id, iv: schema.secretEvent.iv }).from(schema.secretEvent).where(orm.eq(schema.secretEvent.environmentId, environmentId))
    const ivs = new Map(now.map((row) => [row.id, row.iv]))
    if (old.some((row) => ivs.get(row.id) !== row.iv)) throw new OldValuesChangedError('Old values changed while purging them, so nothing was purged: try again')
    throw error
  }
}

export type SecretReadKind = (typeof schema.SECRET_READ_KINDS)[number]

async function appendRead(row: Omit<typeof schema.secretRead.$inferInsert, 'seq' | 'hash' | 'signature'> & { id: string; createdAt: number }, alongside: BatchItem<'sqlite'>[] = []) {
  const db = getDb()
  await batchWithRetry(async () => {
    const [head] = await db.select({ seq: schema.secretRead.seq, hash: schema.secretRead.hash })
      .from(schema.secretRead)
      .where(orm.eq(schema.secretRead.environmentId, row.environmentId))
      .orderBy(orm.desc(schema.secretRead.seq))
      .limit(1)
    const seq = (head?.seq ?? 0) + 1
    const hash = await chainHash(head?.hash ?? ZERO_HASH, readPreimage({ ...row, ipAddress: row.ipAddress ?? null, seq }))
    return [...alongside, db.insert(schema.secretRead).values({ ...row, seq, hash, signature: await signHash(hash) })]
  })
}

function readRow({ request, environmentId, author, kind, names }: {
  request: Request
  environmentId: string
  author: { userId: string | null; apiTokenId: string | null }
  kind: SecretReadKind
  names: string[]
}) {
  return {
    id: ulid(),
    environmentId,
    actor: actorOf(author),
    kind,
    names,
    ipAddress: request.headers.get('cf-connecting-ip'),
    createdAt: Date.now(),
  }
}

// Every read of values passes here before any value leaves the server. A
// protected environment needs a passkey approval for the reading session, or
// a machine token (step-up.ts), and the read is recorded: when the row can't
// be written, it throws and the read fails.
export async function recordSecretRead({ request, environment, author, kind, names }: {
  request: Request
  environment: { id: string; protected: boolean }
  author: Reader
  kind: Exclude<SecretReadKind, 'protected' | 'unprotected'>
  names: string[]
}) {
  if (!environment.protected) return
  await requireStepUp({ environmentId: environment.id, reader: author })
  await appendRead(readRow({ request, environmentId: environment.id, author, kind, names }))
}

// Turns protection on or off together with a row in the read log, so a
// stretch of unlogged reads shows up there
// Turning protection off takes an admin approval, or a stolen admin session
// could switch it off and read. It is the same approval the admin action asks
// for, so the browser asks once.
export async function setEnvironmentProtection({ request, environmentId, protect, author }: {
  request: Request
  environmentId: string
  protect: boolean
  author: Reader
}) {
  const db = getDb()
  const env = await db.query.environment.findFirst({ where: { id: environmentId }, columns: { name: true, projectId: true, protected: true } })
  if (!env) throw new Error('Environment not found')
  if (env.protected && !protect) {
    if (!author.userId || !author.sessionId) throw new StepUpRequiredError('admin')
    await requireAdminApproval({ userId: author.userId, sessionId: author.sessionId })
  }
  await appendRead(
    readRow({ request, environmentId, author, kind: protect ? 'protected' : 'unprotected', names: [] }),
    [
      db.update(schema.environment).set({ protected: protect, updatedAt: Date.now() }).where(orm.eq(schema.environment.id, environmentId)),
      securityEvent({
        request, author, kind: protect ? 'environment.protected' : 'environment.unprotected', where: { projectId: env.projectId },
        subject: { id: environmentId, name: env.name },
      }),
    ],
  )
}

// ── Values for the web UI ───────────────────────────────────────────
// Pages send names only. A value reaches the browser when someone reveals,
// downloads or copies it, and that is what the read log records.

export async function readSecretValues({ request, userId, sessionId, environmentId, names, kind }: {
  request: Request
  userId: string
  sessionId: string
  environmentId: string
  // null for all of them
  names: string[] | null
  kind: 'value' | 'download'
}): Promise<Record<string, string>> {
  if (typeof environmentId !== 'string') throw new InvalidInputError('Invalid input')
  const env = await getUserEnvironmentAccess({ userId, environmentRef: environmentId })
  if (!env) throw new Error('Environment not found')
  const secrets = (await deriveSecrets(env.id)).filter((secret) => !names || names.includes(secret.name))
  await recordSecretRead({ request, environment: env, author: { userId, apiTokenId: null, sessionId }, kind, names: secrets.map((secret) => secret.name) })
  return Object.fromEntries(await Promise.all(secrets.map(async (secret) => [secret.name, await decrypt(secret.valueEncrypted, secret.iv, secret)] as const)))
}

// An old value from the event log
export async function readEventValue({ request, userId, sessionId, eventId }: {
  request: Request
  userId: string
  sessionId: string
  eventId: string
}): Promise<string | null> {
  if (typeof eventId !== 'string') throw new InvalidInputError('Invalid input')
  const event = await getDb().query.secretEvent.findFirst({ where: { id: eventId } })
  if (!event) throw new Error('Event not found')
  const env = await getUserEnvironmentAccess({ userId, environmentRef: event.environmentId })
  if (!env) throw new Error('Environment not found')
  if (!event.valueEncrypted || !event.iv) return null
  await recordSecretRead({ request, environment: env, author: { userId, apiTokenId: null, sessionId }, kind: 'event-log', names: [event.name] })
  return decrypt(event.valueEncrypted, event.iv, event)
}

// ── Verifying ───────────────────────────────────────────────────────

// valueGone, on event rows only: a set row without its value, an empty one
// or its IV. It is outside the preimage, like the value itself.
export type ChainRow = { seq: number; hash: string; signature: string; preimage: string; valueGone?: boolean }

// A set row's value may only go in a purge, and a purge removes old values
// only: a value gone is accounted for by a purge row of its name after a later
// set or delete of it. Any other value gone was removed by hand, keeping its
// digest so that its row still verifies. Takes an event chain's rows and
// returns the seqs of those, in order.
function valuesGoneWithoutPurge(rows: { seq: number; name: string; operation: string; valueGone: boolean }[]): number[] {
  // Newest first: the names with a purge after the rows seen so far, and
  // those with a set or delete that such a purge follows
  const purgedLater = new Set<string>()
  const accounted = new Set<string>()
  const gone: number[] = []
  for (const row of [...rows].sort((a, b) => b.seq - a.seq)) {
    if (row.operation === 'purge') purgedLater.add(row.name)
    if (row.operation !== 'set' && row.operation !== 'delete') continue
    if (row.valueGone && !accounted.has(row.name)) gone.push(row.seq)
    if (purgedLater.has(row.name)) accounted.add(row.name)
  }
  return gone.reverse()
}

// As storedValueDigest decides: a set row without both, emptied or not,
// takes its digest from value_digest
function isValueGone(row: { operation: string; valueEncrypted: string | null; iv: string | null }) {
  return row.operation === 'set' && (!row.valueEncrypted || !row.iv)
}

// For the history page, an environment's set rows whose value is gone, by
// id: purged, or removed without a purge. A row outside the chain has no
// purge to account for it.
export function goneValues(rows: { id: string; seq: number | null; name: string; operation: string; valueEncrypted: string | null; iv: string | null }[]): Map<string, 'purged' | 'removed'> {
  const chained = rows.flatMap((row) => row.seq === null ? [] : [{ ...row, seq: row.seq, valueGone: isValueGone(row) }])
  const unaccounted = new Set(valuesGoneWithoutPurge(chained))
  return new Map(rows.filter(isValueGone).map((row) => [row.id, row.seq !== null && !unaccounted.has(row.seq) ? 'purged' : 'removed']))
}

// Both chains of an environment with every preimage rebuilt from D1 as it is
// now, for `sigillo audit verify`. Chains the environment's older events first.
export async function getAuditChains(environmentId: string) {
  const db = getDb()
  await batchWithRetry(async () => (await adoptPriorEvents(environmentId)).queries)
  const [events, reads] = await Promise.all([
    db.select().from(schema.secretEvent).where(orm.eq(schema.secretEvent.environmentId, environmentId)).orderBy(schema.secretEvent.seq),
    db.select().from(schema.secretRead).where(orm.eq(schema.secretRead.environmentId, environmentId)).orderBy(schema.secretRead.seq),
  ])
  const chained = events.filter((row) => row.seq !== null)
  return {
    publicKey: await getAuditPublicKey(),
    events: {
      rows: await Promise.all(chained.map(async (row): Promise<ChainRow & { valueGone: boolean }> => ({
        seq: row.seq!,
        hash: row.hash ?? '',
        signature: row.signature ?? '',
        preimage: eventPreimage({ ...row, seq: row.seq!, actor: row.actor ?? '' }, row.operation === 'set' ? await storedValueDigest(row) : null),
        valueGone: isValueGone(row),
      }))),
      // Added around the chain, so not covered by it
      outside: events.length - chained.length,
      // From before the chain: signed as found in the database
      adopted: chained.filter((row) => row.adopted).length,
    },
    reads: {
      rows: reads.map((row): ChainRow => ({ seq: row.seq, hash: row.hash, signature: row.signature, preimage: readPreimage(row) })),
    },
  }
}

// What `sigillo audit verify` checks, in TypeScript for the tests
export async function verifyChain(publicKey: string, rows: ChainRow[]): Promise<{ ok: true; head: Head | null } | { ok: false; problem: string }> {
  const key = await crypto.subtle.importKey('raw', fromBase64(publicKey), { name: 'Ed25519' }, false, ['verify'])
  let head: Head | null = null
  for (const row of rows) {
    const seq = (head?.seq ?? 0) + 1
    if (row.seq !== seq) return { ok: false, problem: `row ${seq} is missing` }
    if (await chainHash(head?.hash ?? ZERO_HASH, row.preimage) !== row.hash) return { ok: false, problem: `row ${seq} does not match its hash` }
    if (!await crypto.subtle.verify({ name: 'Ed25519' }, key, fromBase64(row.signature), fromHex(row.hash))) {
      return { ok: false, problem: `row ${seq} has an invalid signature` }
    }
    head = { seq, hash: row.hash }
  }
  // An event chain's rows say which values are gone; its preimages hold
  // their names and operations
  if (rows.some((row) => row.valueGone)) {
    const [gone] = valuesGoneWithoutPurge(rows.map((row) => {
      const [, , , , name, operation] = JSON.parse(row.preimage) as unknown[]
      return { seq: row.seq, name: String(name), operation: String(operation), valueGone: row.valueGone === true }
    }))
    if (gone !== undefined) return { ok: false, problem: `row ${gone} lost its value without a purge` }
  }
  return { ok: true, head }
}
