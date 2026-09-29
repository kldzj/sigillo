/**
 * Rotating the key stored values are encrypted with (`self-host --rotate-key`).
 *
 * The Worker reads its key ring from the ENCRYPTION_KEYS secret: key ids,
 * their keys, and the current one, which new values use (app/src/db.ts).
 * Key 0 is ENCRYPTION_KEY, or else derived from BETTER_AUTH_SECRET. A
 * rotation adds a new current key, re-encrypts every stored value here, with
 * the keys from selfhost.json, through the D1 API, and then drops the keys
 * no value uses any more. So the Worker has no route that decrypts
 * everything.
 */

import { createHash, randomBytes, webcrypto } from 'node:crypto'

export type KeyRing = { current: string; keys: Record<string, string> }
export type Slot = { environmentId: string; name: string }
/** Runs one SQL statement against the app's D1 database and returns its rows */
export type Query = (sql: string, params?: string[]) => Promise<Array<Record<string, unknown>>>

const subtle = webcrypto.subtle
const KEY_ID = /^[a-z0-9]{1,16}$/
// D1 binds at most 100 parameters to a statement, and an update takes 4 per row
const BATCH = 25

function slotData({ environmentId, name }: Slot): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${environmentId}:${name}`)
}

function aesKey(raw: Buffer, usage: 'encrypt' | 'decrypt'): Promise<webcrypto.CryptoKey> {
  return subtle.importKey('raw', new Uint8Array(raw), { name: 'AES-GCM' }, false, [usage])
}

/** Key 0 of a deployment: its ENCRYPTION_KEY, or the key derived from BETTER_AUTH_SECRET */
export function baseKeyOf({ encryptionKey, betterAuthSecret }: { encryptionKey?: string; betterAuthSecret?: string }): Buffer {
  if (encryptionKey) return Buffer.from(encryptionKey, 'base64')
  if (betterAuthSecret) return createHash('sha256').update(betterAuthSecret).digest()
  throw new Error('~/.sigillo/selfhost.json has neither ENCRYPTION_KEY nor BETTER_AUTH_SECRET for this deployment, so its values can\'t be read')
}

/** A new key id, unused in the ring */
export function newKeyId(ring?: KeyRing): string {
  for (;;) {
    const id = randomBytes(8).toString('base64url').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6)
    if (id.length === 6 && id !== '0' && !ring?.keys[id]) return id
  }
}

/** The same format as the Worker's encrypt(): v2.<key id>.<ciphertext>, with the environment and name as additional data */
export async function sealValue({ keyId, key, slot, plaintext, iv = randomBytes(12) }: {
  keyId: string
  key: string
  slot: Slot
  plaintext: string
  iv?: Buffer
}): Promise<{ encrypted: string; iv: string }> {
  if (!KEY_ID.test(keyId)) throw new Error(`Invalid key id: ${keyId}`)
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: slotData(slot) },
    await aesKey(Buffer.from(key, 'base64'), 'encrypt'),
    new TextEncoder().encode(plaintext),
  )
  return { encrypted: `v2.${keyId}.${Buffer.from(ciphertext).toString('base64')}`, iv: iv.toString('base64') }
}

/** What the Worker's decrypt() reads: a v2 value under any key of the ring, or a value from before v2 under key 0 */
export async function openValue({ ring, baseKey, encrypted, iv, slot }: {
  ring: KeyRing | undefined
  baseKey: Buffer
  encrypted: string
  iv: string
  slot: Slot
}): Promise<string> {
  const v2 = encrypted.startsWith('v2.')
  const [keyId, ciphertext] = v2 ? encrypted.slice(3).split('.') : ['0', encrypted]
  const raw = keyId === '0' ? baseKey : ring?.keys[keyId!] ? Buffer.from(ring.keys[keyId!]!, 'base64') : undefined
  if (!raw) throw new Error(`${slot.name} is encrypted with the key ${keyId}, which ~/.sigillo/selfhost.json doesn't have`)
  let plaintext: ArrayBuffer
  try {
    plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(Buffer.from(iv, 'base64')), ...(v2 ? { additionalData: slotData(slot) } : {}) },
      await aesKey(raw, 'decrypt'),
      new Uint8Array(Buffer.from(ciphertext!, 'base64')),
    )
  } catch {
    throw new Error(`${slot.name} can't be decrypted`)
  }
  // Keeps a leading byte order mark, as the Worker does
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(plaintext)
}

function notUnder(keyId: string) {
  const prefix = `v2.${keyId}.`
  return { sql: `value_encrypted IS NOT NULL AND iv IS NOT NULL AND substr(value_encrypted, 1, ${prefix.length}) <> ?1`, params: [prefix] }
}

/** How many stored values aren't encrypted with this key yet */
export async function countNotUnder(query: Query, keyId: string): Promise<number> {
  const where = notUnder(keyId)
  const [row] = await query(`SELECT count(*) AS n FROM secret_event WHERE ${where.sql}`, where.params)
  return Number(row?.n ?? 0)
}

/**
 * Re-encrypts every value not yet under the ring's current key, in batches.
 * A row is only replaced while it still holds the value read, so a value
 * purged meanwhile stays purged. Safe to stop and run again: every value
 * names its key. Returns how many values it re-encrypted.
 */
export async function reencryptAll({ query, ring, baseKey, onProgress }: {
  query: Query
  ring: KeyRing
  baseKey: Buffer
  onProgress?: (done: number) => void
}): Promise<number> {
  const key = ring.keys[ring.current]
  if (!key) throw new Error(`The key ring has no key ${ring.current}`)
  const where = notUnder(ring.current)
  let done = 0
  for (;;) {
    const rows = await query(`SELECT id, environment_id, name, value_encrypted, iv FROM secret_event WHERE ${where.sql} ORDER BY id LIMIT ${BATCH}`, where.params)
    if (rows.length === 0) return done
    const params: string[] = []
    for (const row of rows) {
      const slot = { environmentId: String(row.environment_id), name: String(row.name) }
      const plaintext = await openValue({ ring, baseKey, encrypted: String(row.value_encrypted), iv: String(row.iv), slot })
        .catch((error: Error) => {
          throw new Error(`${error.message} (row ${String(row.id)} of environment ${slot.environmentId}): the rotation stopped there`)
        })
      const sealed = await sealValue({ keyId: ring.current, key, slot, plaintext })
      params.push(String(row.id), sealed.encrypted, sealed.iv, String(row.value_encrypted))
    }
    const at = (i: number, n: number) => `?${i * 4 + n}`
    await query(
      `UPDATE secret_event SET value_encrypted = CASE id ${rows.map((_, i) => `WHEN ${at(i, 1)} THEN ${at(i, 2)}`).join(' ')} END, ` +
        `iv = CASE id ${rows.map((_, i) => `WHEN ${at(i, 1)} THEN ${at(i, 3)}`).join(' ')} END ` +
        `WHERE ${rows.map((_, i) => `(id = ${at(i, 1)} AND value_encrypted = ${at(i, 4)})`).join(' OR ')}`,
      params,
    )
    done += rows.length
    onProgress?.(done)
  }
}
