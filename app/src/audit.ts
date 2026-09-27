// Tamper-evident history: the secret_event and secret_read rows of each
// environment form two hash chains, like git. Rows are numbered 1, 2, 3...
// by seq. A row's hash covers the previous row's hash and the row itself
// (its preimage), and the Worker signs the hash with an Ed25519 key only it
// holds. Someone who can write to D1 can't edit, remove or add a row without
// breaking a chain, and `sigillo audit verify` remembers the last head it
// saw, so a shortened chain shows up there.
//
// Preimages are built from the rows as they are in D1 now, so the audit API
// can hand them out and a verifier only needs SHA-256 and Ed25519. A set
// event's preimage holds a keyed digest of its plaintext, not the ciphertext:
// swapping in another row's ciphertext changes the digest, while
// re-encrypting a value later does not.

import { env } from 'cloudflare:workers'
import * as orm from 'drizzle-orm'
import type { BatchItem } from 'drizzle-orm/batch'
import { ulid } from 'ulid'
import { getDb, schema } from 'db'
import { encrypt, decrypt, deriveSecrets, getUserEnvironmentAccess } from './db.ts'

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

// The digest of a stored set event, from its ciphertext as it is in D1
async function storedValueDigest(row: { environmentId: string; name: string; valueEncrypted: string | null; iv: string | null }): Promise<string> {
  if (!row.valueEncrypted || !row.iv) return 'no value'
  try {
    return await valueDigest(row.environmentId, row.name, await decrypt(row.valueEncrypted, row.iv))
  } catch {
    return 'undecryptable'
  }
}

export function actorOf(author: { userId: string | null; apiTokenId: string | null }): string {
  if (author.userId) return `user:${author.userId}`
  if (author.apiTokenId) return `token:${author.apiTokenId}`
  return 'deleted'
}

function eventPreimage(row: { environmentId: string; seq: number; id: string; name: string; operation: string; actor: string; createdAt: number }, digest: string | null): string {
  return JSON.stringify(['event', row.environmentId, row.seq, row.id, row.name, row.operation, digest, row.actor, row.createdAt])
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
    const hash = await chainHash(current?.hash ?? ZERO_HASH, eventPreimage({ ...row, seq, actor }, digest))
    queries.push(db.update(schema.secretEvent)
      .set({ seq, actor, hash, signature: await signHash(hash) })
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
  userId: string | null
  apiTokenId: string | null
}

// The only way secret_event rows are written
export async function appendSecretEvents(events: NewSecretEvent[]): Promise<{ id: string; name: string }[]> {
  // Encrypt and digest once, outside the retry loop
  const prepared = await Promise.all(events.map(async (event) => {
    const value = event.operation === 'set' ? event.value ?? '' : null
    return {
      id: ulid(),
      createdAt: Date.now(),
      environmentId: event.environmentId,
      name: event.name,
      operation: event.operation,
      actor: actorOf(event),
      userId: event.userId,
      apiTokenId: event.apiTokenId,
      encrypted: value === null ? null : await encrypt(value),
      digest: value === null ? null : await valueDigest(event.environmentId, event.name, value),
    }
  }))
  const db = getDb()
  await batchWithRetry(async () => {
    const queries: BatchItem<'sqlite'>[] = []
    for (const environmentId of new Set(prepared.map((event) => event.environmentId))) {
      const adopted = await adoptPriorEvents(environmentId)
      queries.push(...adopted.queries)
      let head = adopted.head
      for (const event of prepared.filter((row) => row.environmentId === environmentId)) {
        const seq = (head?.seq ?? 0) + 1
        const hash = await chainHash(head?.hash ?? ZERO_HASH, eventPreimage({ ...event, seq }, event.digest))
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
    return queries
  })
  return prepared.map((event) => ({ id: event.id, name: event.name }))
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

// Records a read of a protected environment. Call it before any value leaves
// the server: when the row can't be written, it throws and the read fails.
export async function recordSecretRead({ request, environment, author, kind, names }: {
  request: Request
  environment: { id: string; protected: boolean }
  author: { userId: string | null; apiTokenId: string | null }
  kind: Exclude<SecretReadKind, 'protected' | 'unprotected'>
  names: string[]
}) {
  if (!environment.protected) return
  await appendRead(readRow({ request, environmentId: environment.id, author, kind, names }))
}

// Turns protection on or off together with a row in the read log, so a
// stretch of unlogged reads shows up there
export async function setEnvironmentProtection({ request, environmentId, protect, author }: {
  request: Request
  environmentId: string
  protect: boolean
  author: { userId: string | null; apiTokenId: string | null }
}) {
  const db = getDb()
  await appendRead(
    readRow({ request, environmentId, author, kind: protect ? 'protected' : 'unprotected', names: [] }),
    [db.update(schema.environment).set({ protected: protect, updatedAt: Date.now() }).where(orm.eq(schema.environment.id, environmentId))],
  )
}

// ── Values for the web UI ───────────────────────────────────────────
// Pages send names only. A value reaches the browser when someone reveals,
// downloads or copies it, and that is what the read log records.

export async function readSecretValues({ request, userId, environmentId, names, kind }: {
  request: Request
  userId: string
  environmentId: string
  // null for all of them
  names: string[] | null
  kind: 'value' | 'download'
}): Promise<Record<string, string>> {
  const env = await getUserEnvironmentAccess({ userId, environmentRef: environmentId })
  if (!env) throw new Error('Environment not found')
  const secrets = (await deriveSecrets(env.id)).filter((secret) => !names || names.includes(secret.name))
  await recordSecretRead({ request, environment: env, author: { userId, apiTokenId: null }, kind, names: secrets.map((secret) => secret.name) })
  return Object.fromEntries(await Promise.all(secrets.map(async (secret) => [secret.name, await decrypt(secret.valueEncrypted, secret.iv)] as const)))
}

// An old value from the event log
export async function readEventValue({ request, userId, eventId }: {
  request: Request
  userId: string
  eventId: string
}): Promise<string | null> {
  const event = await getDb().query.secretEvent.findFirst({ where: { id: eventId } })
  if (!event) throw new Error('Event not found')
  const env = await getUserEnvironmentAccess({ userId, environmentRef: event.environmentId })
  if (!env) throw new Error('Environment not found')
  if (!event.valueEncrypted || !event.iv) return null
  await recordSecretRead({ request, environment: env, author: { userId, apiTokenId: null }, kind: 'event-log', names: [event.name] })
  return decrypt(event.valueEncrypted, event.iv)
}

// ── Verifying ───────────────────────────────────────────────────────

export type ChainRow = { seq: number; hash: string; signature: string; preimage: string }

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
      rows: await Promise.all(chained.map(async (row): Promise<ChainRow> => ({
        seq: row.seq!,
        hash: row.hash ?? '',
        signature: row.signature ?? '',
        preimage: eventPreimage({ ...row, seq: row.seq!, actor: row.actor ?? '' }, row.operation === 'set' ? await storedValueDigest(row) : null),
      }))),
      // Added around the chain, so not covered by it
      outside: events.length - chained.length,
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
  return { ok: true, head }
}
