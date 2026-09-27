// Encryption for ~/.sigillo/selfhost.json, which holds the keys to every
// deployment: BETTER_AUTH_SECRET, ENCRYPTION_KEY, the login provider's
// secrets, the Google client and the Cloudflare login. scrypt derives a key
// from the owner's passphrase and AES-256-GCM seals the JSON, so the file can
// stay on disk while only the passphrase lives in a password manager.
//
// A run unlocks the file once (unlockStateFile) and keeps the derived key:
// every read opens the file with it, and every write seals it again with a
// new IV.

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'

export const PASSPHRASE_ENV = 'SIGILLO_SELFHOST_PASSPHRASE'
export const MIN_PASSPHRASE_LENGTH = 12

type Kdf = { name: 'scrypt'; N: number; r: number; p: number; salt: string }

type SealedFile = {
  'sigillo-selfhost': 1
  kdf: Kdf
  iv: string
  data: string
}

export type StateKey = { key: Buffer; kdf: Kdf }

// Binds the ciphertext to this format
const AAD = Buffer.from('sigillo-selfhost v1')

export function isSealed(text: string): boolean {
  try {
    return JSON.parse(text)?.['sigillo-selfhost'] === 1
  } catch {
    return false
  }
}

// scrypt with N = 2^17, r = 8: about 128 MiB and a fraction of a second, once per run
export function deriveStateKey(passphrase: string, kdf?: Kdf): StateKey {
  const params = kdf ?? { name: 'scrypt', N: 2 ** 17, r: 8, p: 1, salt: randomBytes(16).toString('base64') }
  const key = scryptSync(passphrase.normalize('NFC'), Buffer.from(params.salt, 'base64'), 32, {
    N: params.N, r: params.r, p: params.p, maxmem: 512 * 1024 * 1024,
  })
  return { key, kdf: params }
}

export function sealState(json: string, stateKey: StateKey): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', stateKey.key, iv)
  cipher.setAAD(AAD)
  const data = Buffer.concat([cipher.update(json, 'utf8'), cipher.final(), cipher.getAuthTag()])
  const sealed: SealedFile = { 'sigillo-selfhost': 1, kdf: stateKey.kdf, iv: iv.toString('base64'), data: data.toString('base64') }
  return JSON.stringify(sealed, null, 2) + '\n'
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('Wrong passphrase for ~/.sigillo/selfhost.json')
    this.name = 'WrongPassphraseError'
  }
}

export function openState(text: string, stateKey: StateKey): string {
  const sealed = JSON.parse(text) as SealedFile
  const data = Buffer.from(sealed.data, 'base64')
  const decipher = createDecipheriv('aes-256-gcm', stateKey.key, Buffer.from(sealed.iv, 'base64'))
  decipher.setAAD(AAD)
  decipher.setAuthTag(data.subarray(data.length - 16))
  try {
    return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString('utf8')
  } catch {
    throw new WrongPassphraseError()
  }
}

export function passphraseProblem(passphrase: string): string | undefined {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) return `Use at least ${MIN_PASSPHRASE_LENGTH} characters`
  return undefined
}

export type Unlocked = {
  // null: the file stays unencrypted
  stateKey: StateKey | null
  // An unencrypted file to seal right away
  seal: boolean
  warning?: string
}

// Decides how this run gets at the state file. `text` is the file as it is on
// disk, null when there is none yet. The passphrase comes from
// SIGILLO_SELFHOST_PASSPHRASE, otherwise from a prompt; runs that can't
// prompt need the variable, except for an old unencrypted file.
export async function unlockStateFile({ text, envPassphrase, interactive, askPassphrase, askNewPassphrase, confirmEncrypt }: {
  text: string | null
  envPassphrase: string | undefined
  interactive: boolean
  askPassphrase: () => Promise<string>
  askNewPassphrase: () => Promise<string>
  confirmEncrypt: () => Promise<boolean>
}): Promise<Unlocked> {
  const newKey = async () => {
    const passphrase = envPassphrase ?? (interactive ? await askNewPassphrase() : undefined)
    if (passphrase === undefined) {
      throw new Error(`Set ${PASSPHRASE_ENV} to the passphrase that encrypts ~/.sigillo/selfhost.json`)
    }
    const problem = passphraseProblem(passphrase)
    if (problem) throw new Error(`${PASSPHRASE_ENV}: ${problem}`)
    return deriveStateKey(passphrase)
  }

  if (text === null) return { stateKey: await newKey(), seal: false }

  if (isSealed(text)) {
    const { kdf } = JSON.parse(text) as SealedFile
    if (envPassphrase !== undefined || !interactive) {
      if (envPassphrase === undefined) {
        throw new Error(`~/.sigillo/selfhost.json is encrypted: set ${PASSPHRASE_ENV} to its passphrase`)
      }
      const stateKey = deriveStateKey(envPassphrase, kdf)
      openState(text, stateKey)
      return { stateKey, seal: false }
    }
    for (let attempt = 1; ; attempt++) {
      const stateKey = deriveStateKey(await askPassphrase(), kdf)
      try {
        openState(text, stateKey)
        return { stateKey, seal: false }
      } catch (error) {
        if (!(error instanceof WrongPassphraseError) || attempt >= 3) throw error
      }
    }
  }

  // Unencrypted, from before this existed
  if (envPassphrase !== undefined || (interactive && await confirmEncrypt())) {
    return { stateKey: await newKey(), seal: true }
  }
  return {
    stateKey: null,
    seal: false,
    warning: `~/.sigillo/selfhost.json is not encrypted. Run self-host in a terminal, or set ${PASSPHRASE_ENV}, to encrypt it.`,
  }
}
