// Worker-level database client, auth, encryption, and authorization guards.
//
// getDb() creates a drizzle-orm/d1 client bound to env.DB. The schema uses
// epochMs custom columns that accept both Date and number inputs, so
// BetterAuth's Date params are converted to epoch ms before reaching D1.
// getAuth(request) creates a BetterAuth instance backed by the same drizzle
// client for the current request host. encrypt()/decrypt() use ENCRYPTION_KEY
// when set, otherwise derive a stable AES-256 key from BETTER_AUTH_SECRET.

import { env } from 'cloudflare:workers'
import * as orm from 'drizzle-orm'
import { DrizzleQueryError } from 'drizzle-orm/errors'
import { ulid } from 'ulid'
import { getDb, schema } from 'db'
import { betterAuth } from 'better-auth/minimal'
import { genericOAuth, deviceAuthorization, bearer } from 'better-auth/plugins'
import { passkey } from '@better-auth/passkey'
import { claimPasskeyAddition, logPasskeyEvent } from './step-up.ts'
import { APIError, createAuthMiddleware } from 'better-auth/api'
import { makeSignature } from 'better-auth/crypto'
import { drizzleAdapter } from 'better-auth-drizzle-adapter'
import { redirect } from 'spiceflow'
import { memoize } from './lib/memoize.ts'
import { COMMON_EMAIL_DOMAINS, getEmailDomain, getNameError, isUserAllowed } from './lib/utils.ts'
export { COMMON_EMAIL_DOMAINS, getEmailDomain }

// ── Drizzle client via D1 ───────────────────────────────────────────
export { getDb }

// ── OAuth client registration ───────────────────────────────────────
// Registers this instance with the provider via RFC 7591 dynamic client
// registration on first request for a hostname, then caches the client_id by
// hostname.

export function getRequestOrigin(request: Request): string {
  const publicOrigin = getPublicOriginOverride(request)
  if (publicOrigin) {
    return publicOrigin
  }

  return new URL(request.url).origin
}

function getRequestHost(request: Request): string {
  const publicOrigin = getPublicOriginOverride(request)
  if (publicOrigin) {
    return new URL(publicOrigin).host.toLowerCase()
  }

  return new URL(request.url).host.toLowerCase()
}

function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1'
}

function originFromHost(host: string, protocol = 'https'): string {
  const hostname = host.split(':')[0] ?? host
  const safeProtocol = protocol === 'http' || protocol === 'https' ? protocol : 'https'
  const scheme = isLocalHost(hostname) ? 'http' : safeProtocol
  return `${scheme}://${host}`
}

// IMPORTANT: This function MUST only run when request.url is localhost.
// The isLocalHost guard below is critical for security. In production,
// Cloudflare Workers set request.url to the real hostname (e.g. sigillo.dev),
// so this function returns null immediately and never reads forwarded headers.
//
// If this guard were removed, an attacker could inject X-Forwarded-Host: evil.com
// to make BetterAuth set baseURL and trustedOrigins to evil.com, redirecting
// the OAuth callback there and stealing the user's auth code/credentials.
//
// This override only exists for local dev behind a tunnel (e.g. traforo),
// where request.url is localhost but the real public URL is the tunnel domain.
function getPublicOriginOverride(request: Request): string | null {
  const requestUrl = new URL(request.url)
  if (!isLocalHost(requestUrl.hostname)) {
    return null
  }

  const forwardedHost = request.headers.get('x-forwarded-host')
  if (forwardedHost) {
    const host = forwardedHost.split(',')[0]!.trim().toLowerCase()
    const protocol = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase()
    return originFromHost(host, protocol)
  }

  const origin = request.headers.get('origin')
  if (origin) {
    const originUrl = new URL(origin)
    if (!isLocalHost(originUrl.hostname)) {
      return originUrl.origin
    }
  }

  const referer = request.headers.get('referer')
  if (referer) {
    const refererUrl = new URL(referer)
    if (!isLocalHost(refererUrl.hostname)) {
      return refererUrl.origin
    }
  }

  const traforoUrl = process.env.TRAFORO_URL
  if (!traforoUrl) {
    return null
  }

  return traforoUrl
}

const listOAuthHosts = memoize({
  namespace: 'oauth-hosts',
  fn: async (): Promise<string[] | null> => {
    const db = getDb()
    const rows = await db.select({ host: schema.oauthDomain.host })
      .from(schema.oauthDomain)
      .orderBy(schema.oauthDomain.createdAt)
    if (rows.length === 0) return null
    return rows.map((row) => row.host)
  },
})

// Better Auth trusts the current request host plus previously registered hosts.
// This is safe in the current Cloudflare Workers setup because the host is tied
// to Cloudflare routing, not an arbitrary forged incoming Host header:
// - Custom Domains require an exact hostname match to invoke the worker:
//   https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
// - Workers/resolveOverride keep Host aligned with the URL for security reasons:
//   https://developers.cloudflare.com/workers/runtime-apis/request/
// - Cloudflare explicitly says forged Host headers are blocked to prevent
//   bypassing other customers' security settings:
//   https://news.ycombinator.com/item?id=25058579
// If ingress ever moves outside that model (extra proxies, wildcard SaaS
// routing, etc.), revisit this and add an explicit app-level allowlist instead
// of trusting DB entries.
async function readOAuthClientId(host: string): Promise<string | null> {
  const db = getDb()
  const [row] = await db.select({ oauthClientId: schema.oauthDomain.oauthClientId })
    .from(schema.oauthDomain)
    .where(orm.eq(schema.oauthDomain.host, host))
    .limit(1)
  return row?.oauthClientId ?? null
}

const lookupOAuthClientId = memoize({
  namespace: 'oauth-client',
  fn: readOAuthClientId,
})

// The RFC 7591 registration the app sends to the provider.
export function oauthClientRegistration({ origin, callbackUrl, isLocal }: {
  origin: string
  callbackUrl: string
  isLocal: boolean
}) {
  return {
    client_name: `Sigillo Self-Hosted (${origin})`,
    redirect_uris: [callbackUrl],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'openid email profile',
    token_endpoint_auth_method: 'none',
    // oauth-provider 1.7.6 only lets web clients use https on a real host.
    // Loopback http is for native clients (OpenID Connect Dynamic Client
    // Registration, application_type), so local dev registers as one.
    ...(isLocal ? { application_type: 'native' } : {}),
  }
}

export async function ensureOAuthClient(request: Request): Promise<string> {
  const pathname = new URL(request.url).pathname
  const host = getRequestHost(request)
  const hostname = host.split(':')[0] ?? host
  const isLocal = isLocalHost(hostname)
  const isOAuthCallback = pathname.startsWith('/api/auth/callback/')
  const cachedClientId = isLocal && isOAuthCallback
    ? await readOAuthClientId(host)
    : await lookupOAuthClientId(host)

  if (cachedClientId && (!isLocal || isOAuthCallback)) {
    return cachedClientId
  }

  // Allow *.workers.dev hosts so self-hosters can use the app immediately
  // after deploying via `npx sigillo self-host`, before adding a custom
  // domain. The Cache API (memoize) won't work on *.workers.dev but auth and
  // the rest of the app function correctly.

  const origin = getRequestOrigin(request)
  // The redirect_uri MUST exactly match what genericOAuth sends to the provider's
  // /authorize endpoint (the provider does a strict string compare; a mismatch
  // yields `invalid_redirect`). Since better-auth 1.7, genericOAuth is registered
  // as a social provider and uses the CORE callback route `/api/auth/callback/:id`,
  // NOT the old `/api/auth/oauth2/callback/:id`. Keep this path in sync with the
  // `isOAuthCallback` check above if better-auth ever changes the callback route.
  const callbackUrl = new URL('/api/auth/callback/sigillo', origin).toString()
  // Localhost callback URLs are cheap disposable registrations. Refresh them on
  // sign-in requests so stale provider-side client ids never break local login,
  // but keep the cached id during the OAuth callback so the code exchange uses
  // the same client that started the flow.
  const res = await fetch(`${env.PROVIDER_URL}/api/auth/oauth2/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(oauthClientRegistration({ origin, callbackUrl, isLocal })),
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`OAuth client registration failed: ${res.status} ${body}`)
  }
  const { client_id }: { client_id: string } = await res.json()

  const db = getDb()
  await db.insert(schema.oauthDomain)
    .values({ host, oauthClientId: client_id })
    .onConflictDoUpdate({
      target: schema.oauthDomain.host,
      set: { oauthClientId: client_id, updatedAt: Date.now() },
    })

  return client_id
}

// ── Sign-in allowlist ───────────────────────────────────────────────
// ALLOWED_USERS limits who may sign up and sign in (see isUserAllowed).

function isAllowed(user: { email: string; emailVerified: boolean }): boolean {
  return isUserAllowed(user, process.env.ALLOWED_USERS)
}

// The OAuth callback turns this into /login?error=: a refused session sends
// the code, a refused new user the message with underscores for spaces.
function notAllowedError(): APIError {
  return new APIError('FORBIDDEN', { message: 'user not allowed', code: 'USER_NOT_ALLOWED' })
}

// ── BetterAuth ──────────────────────────────────────────────────────

export async function getAuth(request: Request) {
  const db = getDb()
  const host = getRequestHost(request)
  const clientId = await ensureOAuthClient(request)
  const trustedOrigins = ((await listOAuthHosts()) ?? []).map((host) => originFromHost(host))
  trustedOrigins.push(originFromHost(host))
  return betterAuth({
    baseURL: getRequestOrigin(request),
    secret: env.BETTER_AUTH_SECRET,
    database: drizzleAdapter(db, { provider: 'sqlite' }),
    trustedOrigins: Array.from(new Set(trustedOrigins)),
    // Enable email/password signup in tests so tests can create users via
    // auth.api.signUpEmail() and get bearer tokens without needing the
    // OAuth provider. No-op in production since the UI only shows genericOAuth.
    // VITEST var is set in wrangler.test.jsonc, propagated to process.env by nodejs_compat.
    emailAndPassword: { enabled: !!process.env.VITEST },
    // No cookie cache: a session ended on the Sessions page must stop working
    // on its next request, not up to 5 minutes later. It costs one D1 read.
    // Sessions record the client IP Cloudflare puts in cf-connecting-ip.
    advanced: { ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] } },
    // Per IP, counted in D1 so every isolate sees the same counts. The device
    // plugin allows 5 code lookups per 30 minutes, which a team behind one
    // office IP would run out of: 30 per 10 minutes still can't guess a code.
    // Off in tests, whose requests have no IP and would share one count.
    rateLimit: {
      enabled: !process.env.VITEST,
      storage: 'database',
      customRules: { '/device': { window: 600, max: 30 } },
    },
    // The provider's OAuth tokens are encrypted in D1. Rows written before
    // this stay readable: better-auth passes unencrypted values through.
    account: { encryptOAuthTokens: true },
    // A session token read out of D1 must not work on its own.
    // bearer() below only accepts the signed form, which needs
    // BETTER_AUTH_SECRET, so the device flow hands the CLI that form.
    hooks: {
      // /sign-in/social also signs in with a raw id_token, and
      // account.id_token is stored as is, so a D1 reader could replay a recent
      // one. Signing in only ever goes through the redirect flow.
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path === '/sign-in/social' && ctx.body?.idToken) {
          throw new APIError('BAD_REQUEST', { message: 'id_token sign-in is disabled', code: 'ID_TOKEN_SIGN_IN_DISABLED' })
        }
        // Adding a passkey could also start a new session; passkeys sign nobody in
        if (ctx.path === '/passkey/verify-registration' && ctx.body?.createSession) {
          throw new APIError('BAD_REQUEST', { message: 'passkeys do not sign in', code: 'PASSKEY_SIGN_IN_DISABLED' })
        }
        // A CLI login's device code is stored as its hash (see the after hook),
        // so the CLI's code is looked up by its hash too
        if (ctx.path === '/device/token' && typeof ctx.body?.device_code === 'string') {
          return { context: { body: { ...ctx.body, device_code: await hashTokenKey(ctx.body.device_code) } } }
        }
      }),
      after: createAuthMiddleware(async (ctx) => {
        if (ctx.path === '/passkey/verify-registration') {
          const added = ctx.context.returned as { userId?: unknown; name?: unknown } | undefined
          if (typeof added?.userId === 'string') {
            await logPasskeyEvent({
              request: ctx.request ?? null, userId: added.userId, actor: `user:${added.userId}`, action: 'added',
              passkeyName: typeof added.name === 'string' ? added.name : null,
            })
          }
          return
        }
        // The device code turns into a session once approved: only its hash is
        // kept, so a device code read out of D1 during a login can't be
        // exchanged for one
        if (ctx.path === '/device/code') {
          const started = ctx.context.returned as { device_code?: unknown } | undefined
          if (typeof started?.device_code === 'string') {
            await getDb().update(schema.deviceCode).set({ deviceCode: await hashTokenKey(started.device_code) })
              .where(orm.eq(schema.deviceCode.deviceCode, started.device_code))
          }
          return
        }
        if (ctx.path !== '/device/token') return
        const issued = ctx.context.returned as { access_token?: unknown } | undefined
        if (typeof issued?.access_token !== 'string') return
        const signature = await makeSignature(issued.access_token, ctx.context.secret)
        return ctx.json({ ...issued, access_token: `${issued.access_token}.${signature}` })
      }),
    },
    session: {
      additionalFields: { signedIn: { type: 'boolean', defaultValue: false, input: false } },
    },
    // Nobody off the allowlist gets a user or a session, whichever way they sign in
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            if (!isAllowed(user)) throw notAllowedError()
          },
        },
      },
      session: {
        create: {
          before: async (session, ctx) => {
            const user = await db.query.user.findFirst({ where: { id: session.userId }, columns: { email: true, emailVerified: true } })
            if (!user || !isAllowed(user)) throw notAllowedError()
            // A sign-in through Google (the OAuth callback), or by email in
            // tests. Approving a CLI login on /device also makes a session, and
            // any session can approve one, so that one is never signed in.
            const path = ctx?.path ?? ''
            return { data: { ...session, signedIn: path.startsWith('/callback/') || path === '/sign-in/email' || path === '/sign-up/email' } }
          },
        },
      },
    },
    plugins: [
      genericOAuth({
        config: [
          {
            providerId: 'sigillo',
            clientId,
            clientSecret: '',
            // Auto-discover all endpoints from the provider's OIDC metadata
            discoveryUrl: `${env.PROVIDER_URL}/api/auth/.well-known/openid-configuration`,
            scopes: ['openid', 'email', 'profile'],
            pkce: true,
            // Always let the user pick which Google account to use. Without
            // this the provider silently reuses its own session (and the
            // consent step is auto-accepted for first-party clients), so
            // pressing "Sign in with Google" never showed a choice — you got
            // whichever account the provider last saw. The provider maps
            // prompt=select_account onto its /select-account route, which
            // restarts the Google sign-in and then resumes the authorize flow
            // via /oauth2/continue.
            prompt: 'select_account',
          },
        ],
      }),
      deviceAuthorization({ verificationUri: '/device', schema: {} }),
      bearer({ requireSignature: true }),
      // Passkeys approve reads of protected environments. A passkey is bound
      // to this hostname, and user verification (Touch ID, a PIN) is required.
      passkey({
        rpID: host.split(':')[0] ?? host,
        rpName: 'Sigillo',
        origin: getRequestOrigin(request),
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        // Adding a passkey needs a Google sign-in from the last 5 minutes, or an
        // approval with an existing passkey. Checked here, inside the endpoint,
        // where the session is known, and before the passkey is stored.
        registration: {
          afterVerification: async ({ ctx }) => {
            const current = ctx.context.session
            if (!current || !await claimPasskeyAddition({
              userId: current.user.id, sessionId: current.session.id, signedIn: !!current.session.signedIn,
              sessionCreatedAt: new Date(current.session.createdAt).getTime(),
            })) {
              throw new APIError('FORBIDDEN', { message: 'approve with an existing passkey, or sign in again for your first one', code: 'PASSKEY_APPROVAL_REQUIRED' })
            }
          },
        },
      }),
    ],
    // Signing in always goes through Google: the plugin's passkey sign-in is
    // off. Listing, renaming and removing go through our own actions, which
    // log every removal for org admins.
    disabledPaths: [
      '/passkey/generate-authenticate-options', '/passkey/verify-authentication',
      '/passkey/list-user-passkeys', '/passkey/update-passkey', '/passkey/delete-passkey',
      // Names and pictures come from Google through the provider: a member
      // renaming themselves would show up under an admin's name in the logs.
      // The pages call the session endpoints server-side, never these.
      '/update-user', '/change-email', '/delete-user', '/set-password', '/change-password',
      '/list-sessions', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions', '/update-session',
      '/link-social', '/unlink-account', '/list-accounts', '/account-info', '/refresh-token', '/get-access-token',
    ],
  })
}

// ── Data center location ────────────────────────────────────────────

export function getDataCenter(request: Request & { cf?: { colo?: string } }): string {
  return request.cf?.colo ?? 'unknown'
}

// ── Session helpers ─────────────────────────────────────────────────

type Session = { userId: string; sessionId: string; sessionCreatedAt: number; signedIn: boolean; user: { id: string; name: string; email: string; emailVerified: boolean } }

// Spiceflow passes the SAME request instance to every matched loader/layout in
// a single navigation (verified against the framework source). Several loaders
// call getSession concurrently for one navigation, so without deduping each
// would rebuild a BetterAuth instance and re-validate the session — and on a
// cold cookie cache, each would hit D1 for the same session. Memoizing the
// resolution per request collapses those into one. The WeakMap lets entries be
// GC'd once the request is gone, so it never leaks across requests.
const sessionByRequest = new WeakMap<Request, Promise<Session | null>>()

export function getSession(request: Request): Promise<Session | null> {
  const cached = sessionByRequest.get(request)
  if (cached) return cached
  const promise = resolveSession(request)
  sessionByRequest.set(request, promise)
  return promise
}

const MAX_SESSION_AGE_MS = 30 * 24 * 60 * 60 * 1000

async function resolveSession(request: Request): Promise<Session | null> {
  const hasCookie = request.headers.has('cookie')
  const hasAuthorization = request.headers.has('authorization')
  if (!hasCookie && !hasAuthorization) {
    return null
  }

  const auth = await getAuth(request)
  const session = await auth.api.getSession({ headers: request.headers })
  // A session made before its user left the allowlist ends with it
  if (!session || !isAllowed(session.user)) return null
  // A login renews itself while in use, so a stolen cookie or CLI login in
  // daily use would never end: each ends 30 days after its sign-in
  const sessionCreatedAt = new Date(session.session.createdAt).getTime()
  if (Date.now() - sessionCreatedAt > MAX_SESSION_AGE_MS) {
    await getDb().delete(schema.session).where(orm.eq(schema.session.id, session.session.id))
    return null
  }
  return {
    userId: session.user.id,
    sessionId: session.session.id,
    sessionCreatedAt,
    signedIn: !!session.session.signedIn,
    user: { id: session.user.id, name: session.user.name, email: session.user.email, emailVerified: session.user.emailVerified },
  }
}

// ── Your sessions ───────────────────────────────────────────────────
// Through better-auth, which only ever touches the signed-in user's own
// sessions. Its session list carries each session's token, so tokens stay
// on the server: the page gets ids, and ending one looks its token up again.

// null when this login is too old to list sessions: better-auth wants one
// from the last day (freshAge), and the page then asks to sign in again
export async function listUserSessions(request: Request) {
  const auth = await getAuth(request)
  const current = await auth.api.getSession({ headers: request.headers })
  let sessions
  try {
    sessions = await auth.api.listSessions({ headers: request.headers })
  } catch (error) {
    if (isNotFresh(error)) return null
    throw error
  }
  return sessions.map((session) => ({
    id: session.id,
    createdAt: new Date(session.createdAt).getTime(),
    // better-auth stores '' when a request has no IP or user agent
    ipAddress: session.ipAddress || null,
    userAgent: session.userAgent || null,
    isCurrent: session.id === current?.session.id,
  }))
}

// better-auth's APIError when a login is too old for the endpoint
function isNotFresh(error: unknown) {
  return (error as { body?: { code?: string } } | null)?.body?.code === 'SESSION_NOT_FRESH'
}

// Whether better-auth still counts this login as recent enough for its
// sensitive endpoints, such as adding a passkey (freshAge, a day by default)
export async function isSessionFresh(request: Request, sessionCreatedAt: number) {
  const { sessionConfig } = await (await getAuth(request)).$context
  return sessionConfig.freshAge === 0 || Date.now() - sessionCreatedAt < sessionConfig.freshAge * 1000
}

export async function endUserSession(request: Request, sessionId: string) {
  const auth = await getAuth(request)
  const sessions = await auth.api.listSessions({ headers: request.headers })
  const token = sessions.find((session) => session.id === sessionId)?.token
  if (token) await auth.api.revokeSession({ body: { token }, headers: request.headers })
}

export async function endOtherUserSessions(request: Request) {
  const auth = await getAuth(request)
  await auth.api.revokeOtherSessions({ headers: request.headers })
}

export async function requireApiSession(request: Request): Promise<Session> {
  const session = await getSession(request)
  if (!session) throw unauthorizedResponse()
  return session
}

export async function requirePageSession(request: Request): Promise<Session> {
  const session = await getSession(request)
  if (!session) throw redirect('/login')
  return session
}

// ── Domain auto-join ────────────────────────────────────────────────
// Automatically adds a user as a member to any org whose autoJoinDomain
// matches the user's verified email domain. Runs on every /dash/* page
// load. Uses onConflictDoNothing so it's idempotent; no need to pre-check
// existing memberships (the unique index on org_id+user_id handles it).

// The email domain a user may turn auto-join on for, or why not. One org per
// domain: the first org to claim it keeps it (org_auto_join_domain_unique is
// unique). Otherwise any verified colleague could create a second org for
// the same domain and silently enroll everyone who signs in next.
export async function getClaimableAutoJoinDomain({ session, orgId }: {
  session: Pick<Session, 'userId' | 'user'>
  /** the org being updated, which may keep its own claim */
  orgId?: string
}): Promise<string | Error> {
  if (!session.user.emailVerified) return new Error('Email must be verified to enable auto-join')
  const domain = getEmailDomain(session.user.email)
  if (!domain || COMMON_EMAIL_DOMAINS.has(domain)) return new Error('Cannot enable auto-join for public email domains')
  const claimed = await getDb().query.org.findFirst({ where: { autoJoinDomain: domain }, columns: { id: true } })
  if (claimed && claimed.id !== orgId) return new Error(`Another organization already auto-joins @${domain} accounts`)
  return domain
}

export async function autoJoinOrgsByDomain(session: Pick<Session, 'userId' | 'user'>): Promise<void> {
  if (!session.user.emailVerified) return
  const domain = getEmailDomain(session.user.email)
  if (!domain || COMMON_EMAIL_DOMAINS.has(domain)) return

  const db = getDb()

  // Find orgs with matching auto-join domain
  const matchingOrgs = await db.query.org.findMany({
    where: { autoJoinDomain: domain },
    columns: { id: true },
  })
  // Not an org that removed them: it takes an invite to come back
  const removed = new Set((await db.select({ orgId: schema.orgRemoval.orgId }).from(schema.orgRemoval)
    .where(orm.eq(schema.orgRemoval.userId, session.userId))).map((row) => row.orgId))
  const joinable = matchingOrgs.filter((o) => !removed.has(o.id))
  if (joinable.length === 0) return

  // Insert memberships with onConflictDoNothing — the unique index on
  // (org_id, user_id) prevents duplicates, so we skip already-joined orgs
  // without needing a separate membership read.
  const [firstQuery, ...restQueries] = joinable.map((o) =>
    db.insert(schema.orgMember)
      .values({ orgId: o.id, userId: session.userId, role: 'member' })
      .onConflictDoNothing({ target: [schema.orgMember.orgId, schema.orgMember.userId] }),
  )
  await db.batch([firstQuery!, ...restQueries])
}

// ── Granular project access ─────────────────────────────────────────
// orgMember.projectAccess 'all' → every project; 'selected' → only projects
// in memberAccess (none if zero rows). Admins always bypass restrictions.

// Membership + granular access in ONE round-trip. db.query with `with` emits
// a single SQL statement (accessRules joined via the orgMember relation), so
// this replaces the previous two sequential queries. Because it looks up the
// orgMember row, it doubles as the org-membership check: callers that are
// happy with a plain forbidden outcome for non-members can skip a separate
// requireOrgMember round-trip entirely.
export async function getMemberAccess({ userId, orgId }: {
  userId: string
  orgId: string
}): Promise<{
  role: (typeof schema.orgMember.$inferSelect)['role']
  /** null = unrestricted (admin, or projectAccess 'all'); string[] = only these projects */
  accessibleProjectIds: string[] | null
} | null> {
  const db = getDb()
  const member = await db.query.orgMember.findFirst({
    where: { userId, orgId },
    with: { accessRules: true },
  })
  if (!member) return null
  if (member.role === 'admin' || member.projectAccess === 'all') {
    return { role: member.role, accessibleProjectIds: null }
  }
  return { role: member.role, accessibleProjectIds: member.accessRules.map((r) => r.projectId) }
}

// Check if a specific member has access to a specific project.
// Also verifies org membership (false for non-members) — no separate
// requireOrgMember call needed when a 403 is the desired failure mode.
export async function getMemberProjectAccess({ userId, orgId, projectId }: {
  userId: string
  orgId: string
  projectId: string
}): Promise<boolean> {
  const access = await getMemberAccess({ userId, orgId })
  if (!access) return false
  return access.accessibleProjectIds === null || access.accessibleProjectIds.includes(projectId)
}

// Get list of project IDs a member can access, or null if unrestricted.
// null = all projects (admin, or projectAccess 'all').
// string[] = only these project IDs ([] for non-members).
export async function getAccessibleProjectIds(
  userId: string,
  orgId: string,
): Promise<string[] | null> {
  const access = await getMemberAccess({ userId, orgId })
  if (!access) return []
  return access.accessibleProjectIds
}

// The newest project of an organization this person can open, with its
// environments for picking one
export async function firstAccessibleProject(userId: string, orgId: string) {
  const accessibleIds = await getAccessibleProjectIds(userId, orgId)
  if (accessibleIds !== null && accessibleIds.length === 0) return null
  return await getDb().query.project.findFirst({
    where: { orgId, ...(accessibleIds !== null ? { id: { in: accessibleIds } } : {}) },
    columns: { id: true },
    with: { environments: { columns: { slug: true, createdAt: true } } },
    orderBy: { createdAt: 'desc' },
  }) ?? null
}

// ── Org authorization ───────────────────────────────────────────────

// Membership and environment lookups are deliberately NOT memoized: they
// carry authorization data (role, accessRole), and a Cache API entry cannot
// be invalidated everywhere (it is per data center), so a removed member or
// a newly admin-only environment kept working for up to 15 minutes.
async function lookupOrgMember(userId: string, orgId: string): Promise<{ role: string } | null> {
  const db = getDb()
  const member = await db.query.orgMember.findFirst({ where: { userId, orgId } })
  if (!member) return null
  return { role: member.role }
}

// Removes a member together with what let them keep acting in the org on
// their own: the API tokens they created for its projects, and the invite
// links they created. Tokens and invites used to outlive their creator, so a
// departed member's CI token kept reading secrets. The secrets those tokens
// wrote stay (secret_event.api_token_id is SET NULL).
export async function deleteOrgMember(member: { id: string; orgId: string; userId: string }) {
  const db = getDb()
  const orgProjectIds = db.select({ id: schema.project.id }).from(schema.project).where(orm.eq(schema.project.orgId, member.orgId))
  await db.batch([
    db.delete(schema.apiToken).where(orm.and(
      orm.eq(schema.apiToken.createdBy, member.userId),
      orm.inArray(schema.apiToken.projectId, orgProjectIds),
    )),
    db.delete(schema.orgInvitation).where(orm.and(
      orm.eq(schema.orgInvitation.orgId, member.orgId),
      orm.eq(schema.orgInvitation.createdBy, member.userId),
    )),
    db.delete(schema.orgMember).where(orm.eq(schema.orgMember.id, member.id)),
    db.insert(schema.orgRemoval).values({ orgId: member.orgId, userId: member.userId }).onConflictDoNothing(),
  ])
}

// People who left an organization or were removed from it
export async function listFormerMembers(orgId: string) {
  return getDb().select({ id: schema.user.id, name: schema.user.name }).from(schema.orgRemoval)
    .innerJoin(schema.user, orm.eq(schema.user.id, schema.orgRemoval.userId))
    .where(orm.eq(schema.orgRemoval.orgId, orgId))
}

// Joins an organization with an invite link. The link stays valid until it
// expires, for everyone it was shared with. An invitation made before someone
// left or was removed doesn't bring them back: that takes a new one.
export async function joinOrgByInvite({ invitationId, userId }: { invitationId: string; userId: string }) {
  const db = getDb()
  const invite = await db.query.orgInvitation.findFirst({ where: { id: invitationId } })
  if (!invite || invite.expiresAt < Date.now()) throw new Error('Invitation not found or expired')
  const existing = await db.query.orgMember.findFirst({ where: { orgId: invite.orgId, userId }, columns: { id: true } })
  if (existing) return invite.orgId
  const [removal] = await db.select({ createdAt: schema.orgRemoval.createdAt }).from(schema.orgRemoval)
    .where(orm.and(orm.eq(schema.orgRemoval.orgId, invite.orgId), orm.eq(schema.orgRemoval.userId, userId)))
  if (removal && removal.createdAt >= invite.createdAt) {
    throw new Error('You left or were removed from this organization after this invitation was made: ask an admin for a new one.')
  }
  // A scoped invite whose projects were all deleted is refused: joining
  // with access to nothing would only confuse the invitee.
  const invitedProjectIds: string[] = invite.projectIds ? JSON.parse(invite.projectIds) : []
  const projects = invitedProjectIds.length > 0
    ? await db.query.project.findMany({ where: { orgId: invite.orgId, id: { in: invitedProjectIds } }, columns: { id: true } })
    : []
  if (invitedProjectIds.length > 0 && projects.length === 0) {
    throw new Error('The projects in this invitation no longer exist. Ask for a new invitation.')
  }
  // Membership and scope in one batch, so a failure never leaves a
  // half-scoped member behind. onConflictDoNothing keeps a double-submitted
  // accept a no-op (unique index on org_id + user_id).
  const memberId = ulid()
  await db.batch([
    db.insert(schema.orgMember)
      .values({
        id: memberId, orgId: invite.orgId, userId, role: invite.role,
        projectAccess: invitedProjectIds.length > 0 ? 'selected' : 'all',
      })
      .onConflictDoNothing({ target: [schema.orgMember.orgId, schema.orgMember.userId] }),
    ...projects.map((p) => db.insert(schema.memberAccess).values({ orgMemberId: memberId, projectId: p.id })),
    // Invited back after a removal: auto-join may add them again
    db.delete(schema.orgRemoval).where(orm.and(orm.eq(schema.orgRemoval.orgId, invite.orgId), orm.eq(schema.orgRemoval.userId, userId))),
  ])
  return invite.orgId
}

// Inviting is up to admins: a demoted admin's invite links stop working, as
// a removed member's do
export async function setOrgMemberRole({ member, role }: { member: { id: string; orgId: string; userId: string }; role: 'admin' | 'member' }) {
  const db = getDb()
  await db.batch([
    db.update(schema.orgMember).set({ role }).where(orm.eq(schema.orgMember.id, member.id)),
    ...(role === 'admin' ? [] : [db.delete(schema.orgInvitation).where(orm.and(
      orm.eq(schema.orgInvitation.orgId, member.orgId),
      orm.eq(schema.orgInvitation.createdBy, member.userId),
    ))]),
  ])
}

// What people see of an error the server didn't mean to show them, or null
// when its message is meant for people. A failed query's message holds its
// SQL and parameters, and a programming error's helps nobody.
export function internalErrorMessage(error: unknown): string | null {
  const text = `${(error as Error | undefined)?.message ?? ''} ${String((error as { cause?: unknown } | undefined)?.cause ?? '')}`
  if (error instanceof DrizzleQueryError || /\bD1_|SQLITE_/.test(text)) {
    return /UNIQUE constraint failed/.test(text) ? 'That already exists' : 'Something went wrong on the server. Try again.'
  }
  if (error instanceof TypeError || error instanceof ReferenceError || error instanceof RangeError || error instanceof SyntaxError) {
    return 'Something went wrong on the server. Try again.'
  }
  return null
}

// Input the API answers with 400 and its message
export class InvalidInputError extends Error {
  readonly status = 400
  constructor(message: string) {
    super(message)
    this.name = 'InvalidInputError'
  }
}

export function requireValidName(name: string) {
  const error = getNameError(name)
  if (error) throw new InvalidInputError(error)
}

// Distinct class instead of `new Error('FORBIDDEN')` so the API/page wrappers
// below can tell an authorization denial apart from an infrastructure failure.
// A bare `catch {}` there used to turn D1 outages into a bogus 403/redirect,
// hiding real errors from Strada and from the user.
export class ForbiddenError extends Error {
  constructor(message = 'FORBIDDEN') {
    super(message)
    this.name = 'ForbiddenError'
  }
}

export async function requireOrgMember(userId: string, orgId: string) {
  const member = await lookupOrgMember(userId, orgId)
  if (!member) throw new ForbiddenError()
  return member
}

export async function requireApiOrgMember(userId: string, orgId: string) {
  try {
    return await requireOrgMember(userId, orgId)
  } catch (error) {
    if (!(error instanceof ForbiddenError)) throw error
    throw new Response(JSON.stringify({ error: 'forbidden' }), { status: 403, headers: { 'content-type': 'application/json' } })
  }
}

export async function requirePageOrgMember(userId: string, orgId: string) {
  try {
    return await requireOrgMember(userId, orgId)
  } catch (error) {
    if (!(error instanceof ForbiddenError)) throw error
    throw redirect('/')
  }
}

// A project page's own check, on top of its layout's: someone who can't open
// the project goes to the dashboard. Returns their access in its organization.
export async function requirePageProjectAccess(userId: string, projectId: string) {
  const access = await getProjectMemberAccess(userId, projectId)
  if (!access || (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(projectId))) throw redirect('/dash')
  return access
}

// ── Org ownership chain lookups ─────────────────────────────────────

export const getOrgIdForProject = memoize({
  namespace: 'project-org',
  fn: async (projectId: string): Promise<string | null> => {
    const db = getDb()
    const row = await db.query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } })
    return row?.orgId ?? null
  },
})

// Resolve an environment identifier (ULID or slug) to { id, projectId, slug, orgId }.
// Tries ID first, falls back to slug within the project scope.
type ResolvedEnvironment = {
  id: string
  projectId: string
  name: string
  slug: string
  accessRole: string
  protected: boolean
  createdAt: number
  updatedAt: number
  orgId: string | null
}

// Not memoized: carries accessRole (see lookupOrgMember).
export async function resolveEnvironment(identifier: string, projectId?: string | null): Promise<ResolvedEnvironment | null> {
  const db = getDb()
  const byId = await db.query.environment.findFirst({
    where: { id: identifier },
    with: { project: { columns: { orgId: true } } },
  })
  if (byId) return { ...byId, orgId: byId.project?.orgId ?? null }
  if (projectId) {
    const bySlug = await db.query.environment.findFirst({
      where: { projectId, slug: identifier },
      with: { project: { columns: { orgId: true } } },
    })
    if (bySlug) return { ...bySlug, orgId: bySlug.project?.orgId ?? null }
  }
  return null
}

// ── Environment authorization ───────────────────────────────────────
// One rule for every secret read/write path (REST API, pages, actions):
// org member + project access + admin role for admin-only envs.

type MemberAccess = NonNullable<Awaited<ReturnType<typeof getMemberAccess>>>

export function getEnvironmentAccessError(
  access: MemberAccess | null,
  env: { projectId: string; accessRole: string },
): string | null {
  if (!access) return 'forbidden'
  if (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(env.projectId)) {
    return 'you do not have access to this project'
  }
  if (env.accessRole === 'admin' && access.role !== 'admin') return 'admin access required for this environment'
  return null
}

export async function getProjectMemberAccess(userId: string, projectId: string) {
  const orgId = await getOrgIdForProject(projectId)
  return orgId ? getMemberAccess({ userId, orgId }) : null
}

// Returns null when the environment does not exist; throws ForbiddenError
// when the user may not access it.
export async function getUserEnvironmentAccess({ userId, environmentRef, projectId }: {
  userId: string
  environmentRef: string
  projectId?: string | null
}) {
  const env = await resolveEnvironment(environmentRef, projectId)
  if (!env?.orgId) return null
  const access = await getMemberAccess({ userId, orgId: env.orgId })
  const error = getEnvironmentAccessError(access, env)
  if (error || !access) throw new ForbiddenError(error ?? 'forbidden')
  return { id: env.id, projectId: env.projectId, orgId: env.orgId, role: access.role, protected: env.protected }
}

export async function getOrgIdForEnvironment(environmentId: string, projectId?: string | null) {
  const env = await resolveEnvironment(environmentId, projectId)
  return env?.orgId ?? null
}

export async function getProjectIdForEnvironment(environmentId: string, projectId?: string | null) {
  const env = await resolveEnvironment(environmentId, projectId)
  return env?.projectId ?? null
}

// ── Derive current secrets from event log ───────────────────────────
// Replays the append-only secretEvent log for an environment and returns
// the current state: last "set" event per name wins, "delete" removes it.

export type DerivedSecret = {
  id: string
  name: string
  valueEncrypted: string
  iv: string
  createdAt: number
  updatedAt: number
  // Who set it, as the history chain records it: 'user:<id>' or 'token:<id>'
  actor: string
}

// The author of a change or a read as the history chain records it
export function actorOf(author: { userId: string | null; apiTokenId: string | null }): string {
  if (author.userId) return `user:${author.userId}`
  if (author.apiTokenId) return `token:${author.apiTokenId}`
  return 'deleted'
}

// Minimal shape of a secret event row needed to replay current state.
type SecretEventRow = {
  id: string
  name: string
  operation: string
  valueEncrypted: string | null
  iv: string | null
  userId: string | null
  apiTokenId: string | null
  actor: string | null
  createdAt: number
  seq: number | null
}

// Replay an append-only event log (ordered by createdAt asc) into the current
// set of secrets. Last "set" per name wins; "delete" removes it. Rows missing
// a value/iv are dropped. Pure — no DB access, so it can run on rows fetched
// from any query or batch.
// Once an environment's events are chained (see audit.ts), the chain's order
// counts, and a row without seq was added around the chain: it is ignored.
function replaySecretEvents(allEvents: SecretEventRow[]): DerivedSecret[] {
  const chained = allEvents.filter((evt) => evt.seq !== null)
  const events = chained.length ? chained.sort((a, b) => a.seq! - b.seq!) : allEvents
  const state = new Map<string, {
    id: string
    name: string
    valueEncrypted: string | null
    iv: string | null
    actor: string
    createdAt: number
    firstCreatedAt: number
  }>()

  for (const evt of events) {
    const existing = state.get(evt.name)
    if (evt.operation === 'delete') {
      state.delete(evt.name)
    } else {
      state.set(evt.name, {
        id: evt.id,
        name: evt.name,
        valueEncrypted: evt.valueEncrypted,
        iv: evt.iv,
        // Rows from before the chain have no actor yet
        actor: evt.actor ?? actorOf(evt),
        createdAt: evt.createdAt,
        firstCreatedAt: existing?.firstCreatedAt ?? evt.createdAt,
      })
    }
  }

  return Array.from(state.values())
    .filter((s) => s.valueEncrypted && s.iv)
    .map((s) => ({
      id: s.id,
      name: s.name,
      valueEncrypted: s.valueEncrypted!,
      iv: s.iv!,
      createdAt: s.firstCreatedAt,
      updatedAt: s.createdAt,
      actor: s.actor,
    }))
}

export async function deriveSecrets(environmentId: string): Promise<DerivedSecret[]> {
  const db = getDb()
  const events = await db.query.secretEvent.findMany({
    where: { environmentId },
    orderBy: { createdAt: 'asc' },
  })
  return replaySecretEvents(events)
}

// ── Derive secrets for one env + all names across envs in ONE batch ─
// The project secrets page needs two things: the decryptable secrets for the
// selected environment, and the union of secret names across every environment
// (to render the "missing in this env" hints). Previously this was two separate
// round-trips (deriveSecrets + deriveAllSecretNames). This folds every
// secret_event read into a single db.batch so the whole page costs one D1
// round-trip for secret data instead of N+1.
export async function deriveEnvironmentSecretsAndNames(
  { environmentIds, selectedEnvId }: { environmentIds: string[]; selectedEnvId: string | null },
): Promise<{ secrets: DerivedSecret[]; allNames: string[] }> {
  if (environmentIds.length === 0) return { secrets: [], allNames: [] }
  const db = getDb()

  const [firstEnvId, ...restEnvIds] = environmentIds
  const results = await db.batch([
    db.query.secretEvent.findMany({
      where: { environmentId: firstEnvId },
      orderBy: { createdAt: 'asc' },
    }),
    ...restEnvIds.map((envId) =>
      db.query.secretEvent.findMany({
        where: { environmentId: envId },
        orderBy: { createdAt: 'asc' },
      }),
    ),
  ])

  const allNames = new Set<string>()
  let selectedEvents: SecretEventRow[] = []
  for (let i = 0; i < environmentIds.length; i++) {
    const events = results[i]!
    if (environmentIds[i] === selectedEnvId) selectedEvents = events
    for (const secret of replaySecretEvents(events)) allNames.add(secret.name)
  }

  return {
    secrets: selectedEnvId ? replaySecretEvents(selectedEvents) : [],
    allNames: [...allNames].sort(),
  }
}

// How many secrets each environment has now, in one batch
export async function countSecrets(environmentIds: string[]): Promise<Record<string, number>> {
  if (environmentIds.length === 0) return {}
  const db = getDb()
  const [first, ...rest] = environmentIds.map((environmentId) => db.query.secretEvent.findMany({ where: { environmentId }, orderBy: { createdAt: 'asc' } }))
  const results = await db.batch([first!, ...rest])
  return Object.fromEntries(environmentIds.map((id, i) => [id, replaySecretEvents(results[i]!).length]))
}

// Deleting can't be undone: an organization only when its name is typed, an
// environment with secrets only when its slug is
export async function requireOrgDeletionTyped({ orgId, typed }: { orgId: string; typed: string | undefined }) {
  const org = await getDb().query.org.findFirst({ where: { id: orgId }, columns: { name: true } })
  if (!org || typed !== org.name) throw new Error("Type the organization's name to delete it")
}

export async function requireProjectDeletionTyped({ projectId, typed }: { projectId: string; typed: string | undefined }) {
  const project = await getDb().query.project.findFirst({ where: { id: projectId }, columns: { name: true } })
  if (!project || typed !== project.name) throw new Error("Type the project's name to delete it")
}

export async function requireEnvironmentDeletionTyped({ environmentId, typed }: { environmentId: string; typed: string | undefined }) {
  const environment = await getDb().query.environment.findFirst({ where: { id: environmentId }, columns: { slug: true } })
  if (!environment) return
  const count = (await countSecrets([environmentId]))[environmentId] ?? 0
  if (count > 0 && typed !== environment.slug) throw new Error(`Type the environment's slug to delete it and its ${count} ${count === 1 ? 'secret' : 'secrets'}`)
}

// ── Secrets API auth (session OR bearer token) ─────────────────────
// Unified auth for secrets API routes. Accepts either:
// 1. Session cookie → verifies org membership, returns { userId }
// 2. Authorization: Bearer sig_... → verifies token scope, returns { apiTokenId }
//
// Exactly one of userId/apiTokenId is set in the return value. This maps
// directly to secretEvent columns — the event log shows either the user
// name or the API token name depending on which performed the action.

function unauthorizedResponse(error = 'not signed in, or the session expired: run `sigillo login`'): Response {
  return new Response(JSON.stringify({ error }), {
    status: 401, headers: { 'content-type': 'application/json' },
  })
}

function forbiddenResponse(msg = 'forbidden'): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status: 403, headers: { 'content-type': 'application/json' },
  })
}

export type SecretsAuth = (
  | { userId: string; apiTokenId: null; sessionId: string }
  | { userId: null; apiTokenId: string; sessionId: null }
)

// Environments of a project the caller may read, with the same rules as
// requireSecretsApiAuth. Used where one request touches several envs (e.g.
// the allNames list), so names from admin-only or out-of-scope envs never leak.
export async function getReadableEnvironmentIds(auth: SecretsAuth, projectId: string): Promise<string[]> {
  const db = getDb()
  const [environments, orgId] = await Promise.all([
    db.query.environment.findMany({ where: { projectId }, columns: { id: true, projectId: true, accessRole: true } }),
    getOrgIdForProject(projectId),
  ])
  if (!orgId) return []
  if (auth.userId) {
    const access = await getMemberAccess({ userId: auth.userId, orgId })
    return environments.filter((env) => !getEnvironmentAccessError(access, env)).map((env) => env.id)
  }
  if (!auth.apiTokenId) return []
  const token = await db.query.apiToken.findFirst({
    where: { id: auth.apiTokenId },
    columns: { projectId: true, createdBy: true },
    with: { environments: { columns: { environmentId: true } } },
  })
  if (!token || token.projectId !== projectId) return []
  const allowlist = token.environments.length > 0 ? new Set(token.environments.map((row) => row.environmentId)) : null
  const creator = await getMemberAccess({ userId: token.createdBy, orgId })
  return environments
    .filter((env) => !allowlist || allowlist.has(env.id))
    .filter((env) => env.accessRole !== 'admin' || creator?.role === 'admin')
    .map((env) => env.id)
}

// The environmentRef can be either a ULID or a slug. For token auth the
// token's project scope is used to resolve slugs. For session auth we
// need the caller to pass projectId when using a slug.
// Returns { auth, environmentId } where environmentId is the resolved ULID.
export async function requireSecretsApiAuth(
  {
    request,
    environmentRef,
    projectId,
  }: {
    request: Request
    environmentRef: string
    projectId?: string | null
  },
): Promise<SecretsAuth & { environmentId: string; protected: boolean }> {
  const apiToken = await getRequestApiToken(request)
  if (apiToken) {
    const env = await resolveEnvironment(environmentRef, apiToken.projectId)
    if (!env || env.projectId !== apiToken.projectId) throw forbiddenResponse('token does not have access to this environment')
    if (apiToken.environmentIds && !apiToken.environmentIds.includes(env.id)) {
      throw forbiddenResponse('token is scoped to a different environment')
    }
    // Admin-only envs: the token acts for its creator, who must still be an
    // org admin. Covers tokens made by members, and admins later demoted.
    if (env.accessRole === 'admin') {
      const creator = env.orgId ? await getMemberAccess({ userId: apiToken.createdBy, orgId: env.orgId }) : null
      if (creator?.role !== 'admin') throw forbiddenResponse('admin access required for this environment')
    }
    return { userId: null, apiTokenId: apiToken.tokenId, sessionId: null, environmentId: env.id, protected: env.protected }
  }

  // Session auth path — works with both cookies and BetterAuth bearer tokens
  const session = await getSession(request)
  if (!session) throw unauthorizedResponse()

  try {
    const env = await getUserEnvironmentAccess({ userId: session.userId, environmentRef, projectId })
    if (!env) throw new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'content-type': 'application/json' } })
    return { userId: session.userId, apiTokenId: null, sessionId: session.sessionId, environmentId: env.id, protected: env.protected }
  } catch (error) {
    if (error instanceof ForbiddenError) throw forbiddenResponse(error.message)
    throw error
  }
}

// ── API token helpers ───────────────────────────────────────────────
// Tokens use SHA-256 hashing — the full key is never stored, only shown
// once at creation. generateApiToken() creates the raw key + hash + prefix.
// verifyApiToken() looks up a key by its hash for API authentication,
// refuses it once expired, and records its last use at most once an hour.

export async function hashTokenKey(key: string): Promise<string> {
  const encoded = new TextEncoder().encode(key)
  const digest = await crypto.subtle.digest('SHA-256', encoded)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function generateApiToken(): Promise<{ key: string; hashedKey: string; prefix: string }> {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const raw = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  const key = `sig_${raw}`
  const hashedKey = await hashTokenKey(key)
  const prefix = raw.slice(0, 12)
  return { key, hashedKey, prefix }
}

export async function verifyApiToken(key: string, ipAddress: string | null = null): Promise<{
  tokenId: string
  projectId: string
  createdBy: string
  environmentIds: string[] | null
} | null> {
  const hashedKey = await hashTokenKey(key)
  const db = getDb()
  const token = await db.query.apiToken.findFirst({
    where: { hashedKey },
    columns: { id: true, projectId: true, createdBy: true, expiresAt: true, lastUsedAt: true },
    with: { environments: { columns: { environmentId: true } } },
  })
  if (!token) return null
  const now = Date.now()
  if (token.expiresAt !== null && token.expiresAt <= now) {
    throw new Response(JSON.stringify({ error: 'API token expired' }), {
      status: 401, headers: { 'content-type': 'application/json' },
    })
  }
  if (token.lastUsedAt === null || now - token.lastUsedAt > 3_600_000) {
    await db.update(schema.apiToken).set({ lastUsedAt: now, lastUsedIp: ipAddress }).where(orm.eq(schema.apiToken.id, token.id))
  }
  return {
    tokenId: token.id,
    projectId: token.projectId,
    createdBy: token.createdBy,
    environmentIds: token.environments.length === 0
      ? null
      : token.environments.map((row) => row.environmentId),
  }
}

// Reads a sig_ bearer token from the request. Returns null when the request
// is not token auth (cookie session or BetterAuth bearer). Invalid sig_
// tokens throw 401 so they never fall through to session auth.
export async function getRequestApiToken(request: Request): Promise<{
  tokenId: string
  projectId: string
  createdBy: string
  environmentIds: string[] | null
} | null> {
  const authHeader = request.headers.get('authorization')
  const bearer = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null
  if (!bearer?.startsWith('sig_')) return null
  const token = await verifyApiToken(bearer, request.headers.get('cf-connecting-ip'))
  if (!token) throw unauthorizedResponse('invalid or revoked API token')
  // A token acts for its creator: it stops working with their sign-in (the
  // allowlist) and with their access to its project
  const creator = await getDb().query.user.findFirst({ where: { id: token.createdBy }, columns: { email: true, emailVerified: true } })
  if (!creator || !isAllowed(creator)) throw unauthorizedResponse('the creator of this API token may no longer sign in')
  const access = await getProjectMemberAccess(token.createdBy, token.projectId)
  if (!access || (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(token.projectId))) {
    throw forbiddenResponse('the creator of this API token can no longer open its project')
  }
  return token
}

// ── Encryption (AES-256-GCM) ────────────────────────────────────────

async function getEncryptionKey(): Promise<CryptoKey> {
  const configuredKey = process.env.ENCRYPTION_KEY?.trim()
  if (configuredKey) {
    const raw = Uint8Array.from(atob(configuredKey), (c) => c.charCodeAt(0))
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  }

  // AES-256 needs exactly 32 bytes. Hashing the Better Auth secret gives a
  // stable 32-byte fallback key. Plain base64-encoding the secret text would
  // produce variable-length bytes and break encryption.
  const derived = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.BETTER_AUTH_SECRET))
  return crypto.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

export async function encrypt(plaintext: string): Promise<{ encrypted: string; iv: string }> {
  const key = await getEncryptionKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encoded = new TextEncoder().encode(plaintext)
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)
  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  }
}

export async function decrypt(encrypted: string, iv: string): Promise<string> {
  const key = await getEncryptionKey()
  const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0))
  const ciphertext = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0))
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, ciphertext)
  // Keeps a leading byte order mark: the history's digest covers it
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(plaintext)
}
