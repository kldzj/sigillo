// Unit tests for the self-host command's pure pieces: wrangler TOML
// round-trip, bundle parsing, and the token template deep link.
// The full deploy path is exercised manually/e2e against a real Cloudflare
// account (network + credentials required), not here.

import { gzipSync } from 'node:zlib'
import { describe, expect, test } from 'vitest'
import { parseWranglerToml, serializeWranglerToml, TOKEN_TEMPLATE_URL } from '../src/selfhost/cloudflare.js'
import { canDecryptStoredSecret, parseBundle, resolveDeploySecrets, type SelfhostBundle } from '../src/selfhost/deploy.js'

describe('parseWranglerToml', () => {
  const sample = [
    'oauth_token = "tok_abc123"',
    'expiration_time = "2026-01-01T00:00:00.000Z"',
    'refresh_token = "rt_xyz789"',
    'scopes = [ "account:read", "workers:write", "offline_access" ]',
    '',
  ].join('\n')

  test('extracts tokens and scopes', () => {
    expect(parseWranglerToml(sample)).toMatchInlineSnapshot(`
      {
        "expiration_time": "2026-01-01T00:00:00.000Z",
        "oauth_token": "tok_abc123",
        "refresh_token": "rt_xyz789",
        "scopes": [
          "account:read",
          "workers:write",
          "offline_access",
        ],
      }
    `)
  })

  test('round-trips through serialize', () => {
    const parsed = parseWranglerToml(sample)!
    expect(parseWranglerToml(serializeWranglerToml(parsed))).toEqual(parsed)
  })

  test('handles multiline scopes arrays', () => {
    const multiline = sample.replace(
      /scopes = .*/,
      'scopes = [\n  "account:read",\n  "d1:write"\n]',
    )
    expect(parseWranglerToml(multiline)?.scopes).toEqual(['account:read', 'd1:write'])
  })

  test('returns null when tokens are missing', () => {
    expect(parseWranglerToml('api_token = "x"')).toBeNull()
  })
})

describe('parseBundle', () => {
  const bundle: SelfhostBundle = {
    formatVersion: 1,
    version: '0.13.0',
    createdAt: '2026-01-01T00:00:00.000Z',
    providerUrl: 'https://auth.sigillo.dev',
    compatibilityDate: '2026-04-16',
    compatibilityFlags: ['nodejs_compat'],
    mainModule: 'index.js',
    modules: { 'index.js': Buffer.from('export default {}').toString('base64') },
    assets: {
      '/index.html': {
        base64: Buffer.from('<html/>').toString('base64'),
        hash: 'a'.repeat(32),
        size: 7,
        contentType: 'text/html',
      },
    },
    migrations: { '0001_initial.sql': 'CREATE TABLE t(id);' },
  }

  test('round-trips a gzipped bundle', () => {
    const parsed = parseBundle(gzipSync(Buffer.from(JSON.stringify(bundle))))
    expect(parsed).toEqual(bundle)
  })

  test('rejects unknown format versions', () => {
    const bad = gzipSync(Buffer.from(JSON.stringify({ ...bundle, formatVersion: 99 })))
    expect(() => parseBundle(bad)).toThrowErrorMatchingInlineSnapshot(
      `[Error: Unsupported bundle format 99 — update the sigillo CLI]`,
    )
  })
})

describe('TOKEN_TEMPLATE_URL', () => {
  test('encodes the exact permission groups', () => {
    const url = new URL(TOKEN_TEMPLATE_URL)
    expect(url.hostname).toBe('dash.cloudflare.com')
    const keys = JSON.parse(url.searchParams.get('permissionGroupKeys')!)
    expect(keys).toMatchInlineSnapshot(`
      [
        {
          "key": "account_settings",
          "type": "read",
        },
        {
          "key": "user_details",
          "type": "read",
        },
        {
          "key": "memberships",
          "type": "read",
        },
        {
          "key": "workers_scripts",
          "type": "edit",
        },
        {
          "key": "d1",
          "type": "edit",
        },
        {
          "key": "workers_routes",
          "type": "edit",
        },
        {
          "key": "zone",
          "type": "read",
        },
      ]
    `)
  })
})

describe('resolveDeploySecrets', () => {
  const key = Buffer.alloc(32, 7).toString('base64')
  const other = Buffer.alloc(32, 9).toString('base64')
  const run = (args: Parameters<typeof resolveDeploySecrets>[0]) => {
    try {
      const r = resolveDeploySecrets(args)
      return { betterAuthSecret: r.betterAuthSecret ? (args.saved?.betterAuthSecret ? 'saved' : 'generated') : undefined, encryptionKey: r.encryptionKey }
    } catch (error) {
      return (error as Error).message
    }
  }

  test('existing worker never sends secrets; the key can only be set on first deploy', () => {
    expect({
      defaultNew: run({ workerExists: false }),
      newWithKey: run({ workerExists: false, encryptionKeyEnv: key }),
      recreatedFromState: run({ workerExists: false, saved: { betterAuthSecret: 's', encryptionKey: key } }),
      existing: run({ workerExists: true, saved: { betterAuthSecret: 's' } }),
      existingSameKey: run({ workerExists: true, saved: { encryptionKey: key }, encryptionKeyEnv: key }),
      existingNewKey: run({ workerExists: true, saved: { betterAuthSecret: 's' }, encryptionKeyEnv: key }),
      recreatedDifferentKey: run({ workerExists: false, saved: { encryptionKey: key }, encryptionKeyEnv: other }),
      invalidKey: run({ workerExists: false, encryptionKeyEnv: 'short' }),
    }).toMatchInlineSnapshot(`
      {
        "defaultNew": {
          "betterAuthSecret": "generated",
          "encryptionKey": undefined,
        },
        "existing": {
          "betterAuthSecret": undefined,
          "encryptionKey": undefined,
        },
        "existingNewKey": "SIGILLO_ENCRYPTION_KEY can only be set on the first deploy. Changing the key of an existing deployment would make its stored secrets unreadable. Unset it to update.",
        "existingSameKey": {
          "betterAuthSecret": undefined,
          "encryptionKey": undefined,
        },
        "invalidKey": "SIGILLO_ENCRYPTION_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)",
        "newWithKey": {
          "betterAuthSecret": "generated",
          "encryptionKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        },
        "recreatedDifferentKey": "SIGILLO_ENCRYPTION_KEY differs from the key saved for this deployment. Unset it to reuse the saved key.",
        "recreatedFromState": {
          "betterAuthSecret": "saved",
          "encryptionKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        },
      }
    `)
  })
})

describe('canDecryptStoredSecret', () => {
  // Encrypt exactly like app/src/db.ts encrypt(), so a drift in derivation fails here.
  async function appEncrypt(keyBytes: Uint8Array, plaintext: string) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext))
    return { encrypted: Buffer.from(ct).toString('base64'), iv: Buffer.from(iv).toString('base64') }
  }

  test('accepts only the key that encrypted the stored value', async () => {
    const derived = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('auth-secret')))
    const fromAuth = await appEncrypt(derived, 'v')
    const manualKey = Buffer.alloc(32, 3).toString('base64')
    const fromManual = await appEncrypt(Buffer.from(manualKey, 'base64'), 'v')

    expect({
      derivedOk: await canDecryptStoredSecret({ betterAuthSecret: 'auth-secret', ...fromAuth }),
      newSecret: await canDecryptStoredSecret({ betterAuthSecret: 'fresh', ...fromAuth }),
      manualKeyMissing: await canDecryptStoredSecret({ betterAuthSecret: 'auth-secret', ...fromManual }),
      manualKeyGiven: await canDecryptStoredSecret({ betterAuthSecret: 'fresh', encryptionKey: manualKey, ...fromManual }),
    }).toMatchInlineSnapshot(`
      {
        "derivedOk": true,
        "manualKeyGiven": true,
        "manualKeyMissing": false,
        "newSecret": false,
      }
    `)
  })
})
