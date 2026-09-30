// Tests for the login provider, inside workerd against a migrated D1 (vitest.config.ts)
import { describe, test, expect } from 'vitest'
import { app } from './app.tsx'

const ORIGIN = 'https://auth.test'
// APP_URL in wrangler.test.jsonc
const APP = 'https://app.test'

// Dynamic client registration is open (allowUnauthenticatedClientRegistration),
// as every self-hosted app registers itself this way on its first request
async function registerClient(redirectUris: string[]) {
  const res = await app.handle(new Request(`${ORIGIN}/api/auth/oauth2/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.9' },
    body: JSON.stringify({
      client_name: 'Another client',
      redirect_uris: redirectUris,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  }))
  const body = await res.json() as { client_id?: string }
  if (res.status !== 201 || !body.client_id) throw new Error(`registration failed: ${res.status} ${JSON.stringify(body)}`)
  return body.client_id
}

async function signOut(params: Record<string, string>) {
  const res = await app.handle(new Request(`${ORIGIN}/sign-out?${new URLSearchParams(params)}`, { redirect: 'manual' }))
  return { status: res.status, location: res.headers.get('location') }
}

describe('/sign-out', () => {
  test('sends the browser only back to the app it signs in for, whatever a registered client names', async () => {
    const other = await registerClient(['https://elsewhere.example/callback'])
    const own = await registerClient([`${APP}/api/auth/callback/sigillo`])
    expect({
      app: await signOut({ client_id: own, post_logout_redirect_uri: `${APP}/login` }),
      elsewhere: await signOut({ client_id: other, post_logout_redirect_uri: 'https://elsewhere.example/page' }),
      none: await signOut({}),
    }).toEqual({
      app: { status: 302, location: `${APP}/login` },
      elsewhere: { status: 302, location: `${APP}/login` },
      none: { status: 302, location: `${APP}/login` },
    })
  })
})
