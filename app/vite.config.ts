/// <reference types="vitest/config" />
// Read D1 migration SQL files so they can be applied in the workerd setup file
import path from 'node:path'
import { webcrypto } from 'node:crypto'
import { cloudflare } from '@cloudflare/vite-plugin'
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers'
import { holocron } from '@holocron.so/vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { spiceflowPlugin } from 'spiceflow/vite'
import { stradaVitePlugin } from '@strada.sh/sdk/vite'
import { defineConfig } from 'vite'

const port = parseInt(process.env.PORT || '5188', 10)

// Test-only origin for the OAuth provider. Must match PROVIDER_URL in
// wrangler.test.jsonc — outboundService below is the only thing that answers it.
const TEST_PROVIDER_ORIGIN = 'https://provider.invalid'

// Routes every outbound fetch made by the worker under test to this handler.
//
// betterAuth's genericOAuth plugin resolves `discoveryUrl` during plugin init
// and awaits it before any auth endpoint runs. Without this, that fetch went to
// the real network, where workerd hangs forever on an unresolvable host — it
// never resolves and never rejects. Every test calling auth.api.* (i.e. every
// test that creates a user) silently timed out.
//
// Anything unrecognized gets a 501 instead of reaching the internet, so tests
// stay hermetic and a new unmocked dependency fails loudly and instantly
// instead of hanging.
//
// It also plays the OIDC issuers of the workload identity tests: issuer.test
// signs with the keys issuerKeys() makes, which the tests get as the
// TEST_ISSUER_KEYS binding, and the other hosts misbehave in one way each.
function testOutboundService(keys: IssuerKeys, request: Request): Response {
  const url = new URL(request.url)
  const discovery = url.pathname === '/.well-known/openid-configuration'
  if (url.origin === 'https://issuer.test' && discovery) {
    return Response.json({ issuer: 'https://issuer.test', jwks_uri: 'https://issuer.test/jwks' })
  }
  if (url.href === 'https://issuer.test/jwks') {
    keys.fetches++
    return Response.json({ keys: [publicJwk(keys.rsa), publicJwk(keys.ec)] })
  }
  if (url.href === 'https://issuer.test/fetches') return Response.json({ fetches: keys.fetches })
  // Its document names another issuer
  if (url.origin === 'https://liar.test' && discovery) {
    return Response.json({ issuer: 'https://issuer.test', jwks_uri: 'https://issuer.test/jwks' })
  }
  if (url.origin === 'https://redirect.test' && discovery) {
    return new Response(null, { status: 302, headers: { location: 'https://issuer.test/.well-known/openid-configuration' } })
  }
  if (url.origin === 'https://plain.test' && discovery) {
    return Response.json({ issuer: 'https://plain.test', jwks_uri: 'http://plain.test/jwks' })
  }
  if (url.origin === 'https://huge.test' && discovery) {
    return new Response(`{"issuer":"https://huge.test","padding":"${'x'.repeat(1 << 20)}"}`, { headers: { 'content-type': 'application/json' } })
  }

  if (url.origin === TEST_PROVIDER_ORIGIN && url.pathname === '/api/auth/.well-known/openid-configuration') {
    return Response.json({
      issuer: TEST_PROVIDER_ORIGIN,
      authorization_endpoint: `${TEST_PROVIDER_ORIGIN}/api/auth/oauth2/authorize`,
      token_endpoint: `${TEST_PROVIDER_ORIGIN}/api/auth/oauth2/token`,
      userinfo_endpoint: `${TEST_PROVIDER_ORIGIN}/api/auth/oauth2/userinfo`,
      jwks_uri: `${TEST_PROVIDER_ORIGIN}/api/auth/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['EdDSA'],
      scopes_supported: ['openid', 'email', 'profile'],
      code_challenge_methods_supported: ['S256'],
    })
  }

  return Response.json(
    { error: 'unexpected_outbound_request', url: request.url },
    { status: 501 },
  )
}

type IssuerKeys = { rsa: JsonWebKey & { kid: string }; ec: JsonWebKey & { kid: string }; fetches: number }

async function issuerKeys(): Promise<IssuerKeys> {
  const privateJwk = async (algorithm: RsaHashedKeyGenParams | EcKeyGenParams, kid: string, alg: string) => {
    const pair = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']) as CryptoKeyPair
    return { ...await webcrypto.subtle.exportKey('jwk', pair.privateKey), kid, alg }
  }
  return {
    rsa: await privateJwk({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, 'rsa-1', 'RS256'),
    ec: await privateJwk({ name: 'ECDSA', namedCurve: 'P-256' }, 'ec-1', 'ES256'),
    fetches: 0,
  }
}

function publicJwk({ d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, key_ops: _ops, ext: _ext, ...key }: JsonWebKey) {
  return key
}

export default defineConfig(async () => {
  const migrations = process.env.VITEST
    ? await readD1Migrations(path.join(__dirname, '../db/drizzle-app'))
    : []
  const keys = process.env.VITEST ? await issuerKeys() : null

  return {
    server: { port, strictPort: true },
    clearScreen: false,
    plugins: [
      // Tags browser telemetry with git commit/branch (release metadata).
      stradaVitePlugin(),
      // cloudflareTest() runs tests inside workerd via @cloudflare/vitest-pool-workers.
      // cloudflare() handles dev/build/deploy but conflicts with the vitest pool
      // (both manage workerd), so only one is active at a time.
      process.env.VITEST
        ? cloudflareTest({
            wrangler: { configPath: './wrangler.test.jsonc' },
            miniflare: {
              bindings: {
                TEST_MIGRATIONS: migrations,
                TEST_ISSUER_KEYS: { rsa: keys!.rsa, ec: keys!.ec },
                BETTER_AUTH_SECRET: 'test-secret-at-least-32-characters-long!!',
              },
              outboundService: (request: Request) => testOutboundService(keys!, request),
            },
          })
        : null,
      // app.tsx imports `@holocron.so/vite/app`, so holocron must run in BOTH
      // modes to (a) alias that bare id to its `src/app.tsx` and (b) provide the
      // `virtual:holocron-*` modules. Without it in tests, the id resolves to
      // `dist/app.js` which imports virtual modules that don't exist, crashing
      // module load. In test mode we also pass the raw react+spiceflow plugins;
      // holocron detects them and skips adding its own duplicates, avoiding the
      // conflict with cloudflareTest (which manages workerd itself).
      ...(process.env.VITEST
        ? [react(), spiceflowPlugin({ entry: './src/app.tsx' }), holocron({ entry: './src/app.tsx', pagesDir: './src' })]
        : [holocron({ entry: './src/app.tsx', pagesDir: './src' })]),
      // cloudflare() must come AFTER spiceflow/holocron — spiceflow sets ssr outDir to
      // dist/rsc/ssr (nested inside the worker root) so workerd can resolve the
      // cross-environment import. cloudflare's config hook unconditionally sets
      // outDir to dist/ssr (sibling), and Vite's config merge gives the first
      // setter priority. See https://github.com/cloudflare/workers-sdk/issues/13869
      !process.env.VITEST
        ? cloudflare({
            viteEnvironment: {
              name: 'rsc',
              childEnvironments: ['ssr'],
            },
          })
        : null,
    ],
    resolve: {
      dedupe: ['spiceflow', 'spiceflow/react', 'react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime'],
    },
    test: {
      setupFiles: ['./src/test-setup.ts'],
    },
  }
})
