// Worker-level database client and BetterAuth instance for the provider.
//
// getDb() creates a drizzle-orm/sqlite-proxy client bound to env.DB.
// Uses sqlite-proxy instead of drizzle-orm/d1 to avoid the batch findFirst
// crash (drizzle-team/drizzle-orm#2721). The schema uses epochMs custom
// columns that accept both Date and number inputs, so BetterAuth's Date
// params are converted to epoch ms before reaching D1.
// getAuth() creates a BetterAuth instance backed by the same drizzle client
// with oauthProvider + jwt + Google social.

import { env } from 'cloudflare:workers'
import { drizzle } from 'drizzle-orm/sqlite-proxy'
import * as schema from './schema.ts'
import { betterAuth } from 'better-auth/minimal'
import { jwt } from 'better-auth/plugins'
import { oauthProvider } from '@better-auth/oauth-provider'
import { APIError } from 'better-auth/api'
import { isUserAllowed } from 'sigillo-app/src/lib/utils.ts'
import { drizzleAdapter } from 'better-auth-drizzle-adapter'

// ── Drizzle client via D1 ───────────────────────────────────────────

function d1ToRawRows(results: Record<string, unknown>[]) {
  return results.map((row) => Object.keys(row).map((k) => row[k]))
}

export function getDb() {
  return drizzle(
    async (sql, params, method) => {
      const stmt = env.DB.prepare(sql).bind(...params)
      if (method === 'run') { await stmt.run(); return { rows: [] as any[] } }
      const rows = await stmt.raw()
      if (method === 'get') return { rows: rows[0] as any }
      return { rows: rows as any[] }
    },
    async (queries) => {
      const stmts = queries.map((q) => env.DB.prepare(q.sql).bind(...q.params))
      const results = await env.DB.batch(stmts)
      return results.map((r, i) => {
        const rows = d1ToRawRows(r.results as Record<string, unknown>[])
        if (queries[i]!.method === 'get') return { rows: rows[0] as any }
        return { rows: rows as any[] }
      })
    },
    { schema, relations: schema.relations },
  )
}

// ── BetterAuth ──────────────────────────────────────────────────────

// Optional, so not in the generated Env type: self-host sets it as a secret
const allowedUsers = () => (env as { ALLOWED_USERS?: string }).ALLOWED_USERS

// Same code as the app's, so the /error page can explain a refusal
function notAllowedError(): APIError {
  return new APIError('FORBIDDEN', { message: 'user not allowed', code: 'USER_NOT_ALLOWED' })
}

export function getAuth() {
  const db = getDb()
  return betterAuth({
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    database: drizzleAdapter(db, { provider: 'sqlite' }),
    // The client's IP as Cloudflare saw it: X-Forwarded-For is whatever the
    // client sends, and would let it pick a fresh count per request
    advanced: { ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] } },
    // Per IP, counted in D1 so every isolate sees the same counts. Anyone may
    // register a client, as the app does when it first starts: a few an hour.
    // Discovery is public and unlimited: the app fetches it whenever it
    // builds its auth, from Cloudflare egress IPs other Workers share.
    // Paths are relative to /api/auth, and false turns the limit off.
    rateLimit: {
      enabled: true,
      storage: 'database',
      customRules: {
        '/oauth2/register': { window: 3600, max: 10 },
        '/.well-known/*': false,
      },
    },
    // Google's OAuth tokens are encrypted in D1. Rows written
    // before this stay readable: better-auth passes unencrypted values through.
    account: { encryptOAuthTokens: true },
    // The app's ALLOWED_USERS, applied here too: nobody off the list gets a
    // provider account or session, so they never reach the app at all.
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            if (!isUserAllowed(user, allowedUsers())) throw notAllowedError()
          },
        },
      },
      session: {
        create: {
          before: async (session) => {
            const user = await db.query.user.findFirst({ where: { id: session.userId }, columns: { email: true, emailVerified: true } })
            if (!user || !isUserAllowed(user, allowedUsers())) throw notAllowedError()
          },
        },
      },
    },
    session: {
      cookieCache: {
        enabled: true,
        maxAge: 5 * 60, // 5 minutes — avoids a D1 round-trip on every request
      },
    },
    socialProviders: {
      google: {
        clientId: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        prompt: 'select_account',
        // No sign-in with a raw Google id_token: account.id_token is stored
        // as is, so a D1 reader could replay a recent one. Redirects only.
        disableIdTokenSignIn: true,
      },
    },
    plugins: [
      jwt(),
      oauthProvider({
        loginPage: '/sign-in',
        // Dynamic client registration stays open for self-hosted instances,
        // but clients are no longer treated as trusted by default.
        consentPage: '/consent',
        // Without selectAccount.page, oauthProvider rejects any authorize
        // request carrying prompt=select_account with
        // unsupported_prompt_select_account. /select-account restarts the
        // Google sign-in and then resumes via /oauth2/continue.
        // The page must not carry its own query string: oauthProvider builds
        // the redirect as `${page}?${signedParams}`.
        // shouldRedirect stays false so account selection is never forced on
        // clients that did not ask for it.
        selectAccount: {
          page: '/select-account',
          shouldRedirect: () => false,
        },
        allowDynamicClientRegistration: true,
        allowUnauthenticatedClientRegistration: true,
        scopes: ['openid', 'email', 'profile', 'offline_access'],
        clientRegistrationDefaultScopes: ['openid', 'email', 'profile'],
      }),
    ],
  })
}
