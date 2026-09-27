// A software WebAuthn authenticator for the tests: an ES256 key that answers
// registration and authentication challenges the way a platform authenticator
// does, with "none" attestation. Test-only.

import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server'

const encoder = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4)), (c) => c.charCodeAt(0))
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

// Just enough CBOR for attestation objects and COSE keys
type Cbor = number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>
function cbor(value: Cbor): Uint8Array<ArrayBuffer> {
  const head = (major: number, length: number) => {
    if (length < 24) return Uint8Array.of((major << 5) | length)
    if (length < 256) return Uint8Array.of((major << 5) | 24, length)
    if (length < 65536) return Uint8Array.of((major << 5) | 25, length >> 8, length & 0xff)
    return Uint8Array.of((major << 5) | 26, (length >>> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff)
  }
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') {
    const bytes = encoder.encode(value)
    return concat(head(3, bytes.length), bytes)
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value)
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(cbor))
  return concat(head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]))
}

// WebCrypto signs ECDSA as r || s; WebAuthn wants DER
function derSignature(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const integer = (bytes: Uint8Array) => {
    let i = 0
    while (i < bytes.length - 1 && bytes[i] === 0) i++
    let trimmed = bytes.slice(i)
    if (trimmed[0]! & 0x80) trimmed = concat(Uint8Array.of(0), trimmed)
    return concat(Uint8Array.of(0x02, trimmed.length), trimmed)
  }
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)))
  return concat(Uint8Array.of(0x30, body.length), body)
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

export async function createSoftAuthenticator({ rpID, origin }: { rpID: string; origin: string }) {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey) as JsonWebKey
  const credentialId = crypto.getRandomValues(new Uint8Array(16))
  const cose = cbor(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, fromB64url(jwk.x!)], [-3, fromB64url(jwk.y!)]]))
  const rpIdHash = await sha256(encoder.encode(rpID))
  let signCount = 0
  const counter = () => {
    const bytes = new Uint8Array(4)
    new DataView(bytes.buffer).setUint32(0, signCount)
    return bytes
  }
  // Bit 0 user present, bit 2 user verified, bit 6 attested credential data
  const flags = (userVerified: boolean, attested: boolean) => Uint8Array.of(0x01 | (userVerified ? 0x04 : 0) | (attested ? 0x40 : 0))

  return {
    credentialId: b64url(credentialId),

    async register(options: { challenge: string }, { userVerified = true } = {}): Promise<RegistrationResponseJSON> {
      const clientDataJSON = encoder.encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }))
      const authData = concat(rpIdHash, flags(userVerified, true), counter(), new Uint8Array(16), Uint8Array.of(0, credentialId.length), credentialId, cose)
      const attestationObject = cbor(new Map<Cbor, Cbor>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key',
        response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject), transports: ['internal'] },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform',
      }
    },

    async authenticate(options: { challenge: string }, { userVerified = true, origin: claimedOrigin = origin } = {}): Promise<AuthenticationResponseJSON> {
      signCount++
      const clientDataJSON = encoder.encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: claimedOrigin, crossOrigin: false }))
      const authenticatorData = concat(rpIdHash, flags(userVerified, false), counter())
      const signed = concat(authenticatorData, await sha256(clientDataJSON))
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, signed))
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key',
        response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authenticatorData), signature: b64url(derSignature(raw)) },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform',
      }
    },
  }
}
