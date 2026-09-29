// Integration tests for the Sigillo app running inside workerd via
// @cloudflare/vitest-pool-workers. Tests run against real D1, real Cache API,
// real AES-256-GCM encryption. No mocks. Test users are created via
// auth.api.signUpEmail (emailAndPassword enabled by VITEST wrangler var).
//
// Uses createSpiceflowFetch(app) for type-safe API testing. Paths and params
// are fully typed — invalid paths or missing params are compile errors.
// Non-2xx responses come back as Error instances; success returns parsed JSON.
//
// createSpiceflowFetch(app) sends requests with host "e.ly" (not localhost),
// so ensureOAuthClient finds the pre-seeded oauth_domain row and returns
// early without calling the provider.

import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth-drizzle-adapter'
import { describe, test, expect, beforeAll } from 'vitest'
import { env as workerEnv } from 'cloudflare:workers'
import { createSpiceflowFetch } from 'spiceflow/client'
import * as orm from 'drizzle-orm'
import worker, { app } from './app.js'
import { getAuth, encrypt, decrypt, hashTokenKey, deriveSecrets, deriveEnvironmentSecretsAndNames, generateApiToken, getDb, autoJoinOrgsByDomain, getMemberProjectAccess, getAccessibleProjectIds, getClaimableAutoJoinDomain, deleteOrgMember, joinOrgByInvite, listFormerMembers, setOrgMemberRole, getSession, countSecrets, requireOrgDeletionTyped, requireEnvironmentDeletionTyped, requireProjectDeletionTyped, oauthClientRegistration, listUserSessions, endUserSession, endOtherUserSessions, internalErrorMessage } from './db.js'
import { schema } from 'db'
import { makeSignature } from 'better-auth/crypto'
import { appendSecretEvents, recordSecretRead, setEnvironmentProtection, getAuditChains, verifyChain, getAuditPublicKey, readSecretValues, readEventValue, purgeOldValues, readOldValues, removeOldValues, goneValues } from './audit.js'
import { createSoftAuthenticator } from './soft-authenticator.js'
import { passkeyChallenge, verifyPasskey, StepUpRequiredError, findStepUpRequest, approvalOptions, approveStepUpRequest, createStepUpRequest, requireMachineTokenApproval, requireMachineTokenDeletion, requireOldValuesPurge, requireOrgAdmin, requireAdminApproval, resetMemberPasskeys, requestEnrollment, approveEnrollment, passkeyApproverOrgs, requirePasskeyOnceEnrolled, canAddPasskey, claimPasskeyAddition, pendingEnrollments, requireTokenDeletion } from './step-up.js'
import type { AuthenticationResponseJSON } from '@simplewebauthn/server'
import { createTrustRule, deleteTrustRule, renewTrustRule, replaceTrustRuleKeys, trustRuleEvidence, type TrustRuleInput } from './workload.js'
import { createToken, deleteToken, expiringCredentials, expiryBanner, regenerateToken, stopPreviousValue } from './tokens.js'
import * as jose from 'jose'
import { formatAbsoluteDate, formatTime, isUserAllowed, loginErrorMessage, describeUserAgent, formatIp, formatUserCode, describeExpiry, GITHUB_ISSUER } from './lib/utils.js'

// ── Test helpers ────────────────────────────────────────────────────

let cachedAuth: Awaited<ReturnType<typeof getAuth>> | null = null

async function getTestAuth() {
  if (!cachedAuth) {
    cachedAuth = await getAuth(new Request('http://e.ly'))
  }
  return cachedAuth
}

async function insertApiToken({
  name,
  projectId,
  createdBy,
  environmentIds,
  expiresAt,
  protectedAccess,
}: {
  name: string
  projectId: string
  createdBy: string
  environmentIds?: string[]
  expiresAt?: number
  // A machine token, which may read protected environments
  protectedAccess?: boolean
}) {
  const { key, hashedKey, prefix } = await generateApiToken()
  const db = getDb()
  // Its creator is a member of the org, as the Machines tab requires: a token
  // acts with its creator's access
  const project = await db.query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } })
  if (project) await db.insert(schema.orgMember).values({ orgId: project.orgId, userId: createdBy, role: 'member' }).onConflictDoNothing()
  const [token] = await db.insert(schema.apiToken).values({
    name,
    projectId,
    prefix,
    hashedKey,
    createdBy,
    expiresAt,
    protectedAccess,
  }).returning({ id: schema.apiToken.id })
  if (environmentIds?.length) {
    await db.insert(schema.apiTokenEnvironment).values(
      environmentIds.map((environmentId) => ({ tokenId: token!.id, environmentId })),
    )
  }
  return { key, tokenId: token!.id }
}

async function createTestUser(overrides?: { email?: string; name?: string }) {
  const email = overrides?.email ?? `test-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`
  const name = overrides?.name ?? 'Test User'
  const auth = await getTestAuth()
  const res = await auth.api.signUpEmail({
    body: { email, name, password: 'test-password-123' },
  })
  // Signed like the session cookie and the CLI's token; bearer() refuses raw tokens
  const { secret } = await auth.$context
  return { user: res.user, token: `${res.token!}.${await makeSignature(res.token!, secret)}` }
}

// The session behind a test token (signed: <token>.<signature>)
async function sessionIdOf(token: string) {
  return (await getDb().query.session.findFirst({ where: { token: token.split('.')[0]! }, columns: { id: true } }))!.id
}

// A passkey approval to read and change environments, without the ceremony
async function grantRead(token: string, environmentIds: string[], expiresAt = Date.now() + 60_000) {
  const session = (await getDb().query.session.findFirst({ where: { token: token.split('.')[0]! }, columns: { id: true, userId: true } }))!
  await getDb().insert(schema.stepUpGrant).values({ userId: session.userId, sessionId: session.id, purpose: 'access', environmentIds, expiresAt })
}

// A passkey approval for admin actions, without the ceremony
async function grantAdmin(token: string, expiresAt = Date.now() + 60_000) {
  const session = (await getDb().query.session.findFirst({ where: { token: token.split('.')[0]! }, columns: { id: true, userId: true } }))!
  await getDb().insert(schema.stepUpGrant).values({ userId: session.userId, sessionId: session.id, purpose: 'admin', environmentIds: [], expiresAt })
}

/** Throw if Error, return the success result */
// TS cannot narrow `T | Error` to `Exclude<T, Error>` on a type parameter,
// so the cast is unavoidable here (canonical errore-style helper).
function assertOk<T>(result: T | Error): Exclude<T, Error> {
  if (result instanceof Error) throw result
  return result as Exclude<T, Error>
}

/** Assert result is an Error with a specific HTTP status code */
function assertErrorStatus<T>(result: T | Error, status: number) {
  expect(result).toBeInstanceOf(Error)
  if (!(result instanceof Error)) throw new Error('unreachable')
  // spiceflow wraps non-2xx responses as Error with a status property
  expect(Reflect.get(result, 'status')).toBe(status)
}

/** Create a typed fetch client with Bearer auth for a given token */
function authedFetch(token: string) {
  return createSpiceflowFetch(app, {
    headers: { authorization: `Bearer ${token}` },
  })
}

const f = createSpiceflowFetch(app)

// ── Health & Info ───────────────────────────────────────────────────

describe('health & info', () => {
  test('GET /health returns ok', async () => {
    const result = await f('/health');

    expect(result).toMatchInlineSnapshot(`
      {
        "ok": true,
        "service": "sigillo-app",
      }
    `)
  })

  test('GET /api/info returns colo', async () => {
    const result = await f('/api/info')
    expect(result).toMatchInlineSnapshot(`
      {
        "colo": "unknown",
      }
    `)
  })
})

// ── Auth — unauthenticated access ───────────────────────────────────

describe('auth — unauthenticated access', () => {
  test('GET /api/v0/me returns 401', async () => {
    assertErrorStatus(await f('/api/v0/me'), 401)
  })

  test('GET /api/v0/orgs returns 401', async () => {
    assertErrorStatus(await f('/api/v0/orgs'), 401)
  })

  test('POST /api/v0/orgs returns 401', async () => {
    assertErrorStatus(await f('/api/v0/orgs', { method: 'POST', body: { name: 'test' } }), 401)
  })

  test('POST /api/v0/projects returns 401', async () => {
    assertErrorStatus(await f('/api/v0/projects', { method: 'POST', body: { name: 'test', orgId: 'fake' } }), 401)
  })
})

// ── Orgs CRUD ───────────────────────────────────────────────────────

describe('orgs CRUD', () => {
  let af: ReturnType<typeof authedFetch>

  beforeAll(async () => {
    const user = await createTestUser({ name: 'OrgUser' })
    af = authedFetch(user.token)
  })

  test('POST /api/v0/orgs creates an org', async () => {
    const result = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Acme Corp' } }))
    expect(result.ok).toBe(true)
    expect(result.name).toBe('Acme Corp')
    expect(result.id).toBeTruthy()
  })

  test('GET /api/v0/orgs lists user orgs', async () => {
    const result = assertOk(await af('/api/v0/orgs'))
    expect(result.orgs.length).toBeGreaterThanOrEqual(1)
    const org = result.orgs.find((o) => o.name === 'Acme Corp')
    expect(org).toBeTruthy()
    expect(org!.role).toBe('admin')
  })

  test('GET /api/v0/me returns user info with orgs', async () => {
    const result = assertOk(await af('/api/v0/me'))
    expect(result.user.name).toBe('OrgUser')
    expect(result.user.email).toBeTruthy()
    expect(result.orgs.length).toBeGreaterThanOrEqual(1)
  })
})

// ── Projects CRUD ───────────────────────────────────────────────────

describe('projects CRUD', () => {
  let af: ReturnType<typeof authedFetch>
  let orgId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'ProjectUser' })
    af = authedFetch(user.token)
    const result = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Project Org' } }))
    orgId = result.id
  })

  test('POST /api/v0/projects creates project with default environments', async () => {
    const result = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'My App', orgId } }))
    expect(result.ok).toBe(true)
    expect(result.name).toBe('My App')

    // GET the project and verify default environments
    const project = assertOk(await af('/api/v0/projects/:id', { params: { id: result.id } }))
    expect(project.name).toBe('My App')
    expect(project.environments.map((e) => e.slug).sort()).toMatchInlineSnapshot(`
      [
        "dev",
        "preview",
        "prod",
      ]
    `)
  })

  test('GET /api/v0/projects lists projects', async () => {
    const result = assertOk(await af('/api/v0/projects'))
    expect(result.projects.length).toBeGreaterThanOrEqual(1)
    const project = result.projects.find((p) => p.name === 'My App')
    expect(project).toBeTruthy()
    expect(project!.environments.length).toBe(3)
  })

  test('PATCH /api/v0/projects/:id renames project', async () => {
    const created = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'To Rename', orgId } }))
    const patched = assertOk(await af('/api/v0/projects/:id', {
      method: 'PATCH',
      params: { id: created.id },
      body: { name: 'Renamed' },
    }))
    expect(patched.name).toBe('Renamed')
  })

  test('DELETE /api/v0/projects/:id deletes project', async () => {
    const created = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'To Delete', orgId } }))
    assertOk(await af('/api/v0/projects/:id', { method: 'DELETE', params: { id: created.id } }))

    // Verify 404
    const gone = await af('/api/v0/projects/:id', { params: { id: created.id } })
    expect(gone).toBeInstanceOf(Error)
  })
})

// ── Environments CRUD ───────────────────────────────────────────────

describe('names', () => {
  test('of organizations, projects and environments can\'t carry terminal control characters', async () => {
    const user = await createTestUser({ name: 'Naming User' })
    const af = authedFetch(user.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Café Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Café', orgId } })).id
    const clipboard = 'api\u001b]52;c;ZWNobyBoaQ==\u0007'
    const status = (result: unknown) => result instanceof Error ? (result as { status?: number }).status : 200
    expect({
      org: status(await af('/api/v0/orgs', { method: 'POST', body: { name: clipboard } })),
      project: status(await af('/api/v0/projects', { method: 'POST', body: { name: clipboard, orgId } })),
      rename: status(await af('/api/v0/projects/:id', { method: 'PATCH', params: { id: projectId }, body: { name: 'C1\u009b2J' } })),
      environment: status(await af('/api/v0/projects/:projectId/environments', { method: 'POST', params: { projectId }, body: { name: clipboard, slug: 'staging' } })),
      environmentRename: status(await af('/api/v0/projects/:projectId/environments/:id', { method: 'PATCH', params: { projectId, id: 'dev' }, body: { name: '\r' } })),
    }).toEqual({ org: 400, project: 400, rename: 400, environment: 400, environmentRename: 400 })
  })
})

describe('errors the server doesn\'t mean to show', () => {
  test('reach people without their query, while messages meant for them stay', async () => {
    const user = await createTestUser({ name: 'Error User' })
    const orgId = assertOk(await authedFetch(user.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Error Org' } })).id
    const projectId = assertOk(await authedFetch(user.token)('/api/v0/projects', { method: 'POST', body: { name: 'Error Project', orgId } })).id
    // Real failures from D1: a slug taken twice, and a project in no organization
    const duplicate = await getDb().insert(schema.environment).values({ projectId, name: 'Again', slug: 'dev' }).catch((error: unknown) => error)
    const orphan = await getDb().insert(schema.project).values({ name: 'Orphan', orgId: 'no-such-org' }).catch((error: unknown) => error)
    expect({
      duplicate: [String((duplicate as Error).message).startsWith('Failed query'), internalErrorMessage(duplicate)],
      orphan: internalErrorMessage(orphan),
      bug: internalErrorMessage(new TypeError("Cannot read properties of undefined (reading 'id')")),
      meant: internalErrorMessage(new Error('Name is required')),
    }).toEqual({
      duplicate: [true, 'That already exists'],
      orphan: 'Something went wrong on the server. Try again.',
      bug: 'Something went wrong on the server. Try again.',
      meant: null,
    })
  })
})

describe('environments CRUD', () => {
  test('a slug is lowercase letters, digits and dashes', async () => {
    const user = await createTestUser({ name: 'Slug User' })
    const uf = authedFetch(user.token)
    const orgId = assertOk(await uf('/api/v0/orgs', { method: 'POST', body: { name: 'Slug Org' } })).id
    const projectId = assertOk(await uf('/api/v0/projects', { method: 'POST', body: { name: 'Slug Project', orgId } })).id
    const create = (slug: string) => app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments`, {
      method: 'POST', headers: { authorization: `Bearer ${user.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ name: slug, slug }),
    })).then((res) => res.status)
    const created = assertOk(await uf('/api/v0/projects/:projectId/environments', { method: 'POST', params: { projectId }, body: { name: 'Staging', slug: 'staging-2' } })).id
    const rename = await app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${created}`, {
      method: 'PATCH', headers: { authorization: `Bearer ${user.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ slug: 'Prod Old' }),
    }))
    expect({
      refused: await Promise.all(['Prod', 'prod env', 'prod;x=1', '-prod', 'x'.repeat(64)].map(create)),
      rename: [rename.status, await rename.json()],
    }).toEqual({
      refused: [400, 400, 400, 400, 400],
      rename: [400, { error: 'Invalid slug "Prod Old". Use lowercase letters, digits and dashes, starting with a letter or digit, at most 63.' }],
    })
  })

  let af: ReturnType<typeof authedFetch>
  let projectId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'EnvUser' })
    af = authedFetch(user.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Env Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Env Project', orgId: org.id } }))
    projectId = proj.id
  })

  test('GET lists default environments', async () => {
    const result = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    expect(result.environments.map((e) => ({ name: e.name, slug: e.slug }))).toMatchInlineSnapshot(`
      [
        {
          "name": "Dev",
          "slug": "dev",
        },
        {
          "name": "Preview",
          "slug": "preview",
        },
        {
          "name": "Prod",
          "slug": "prod",
        },
      ]
    `)
  })

  test('POST creates a custom environment', async () => {
    const result = assertOk(await af('/api/v0/projects/:pid/environments', {
      method: 'POST',
      params: { pid: projectId },
      body: { name: 'Staging', slug: 'staging' },
    }))
    expect(result.ok).toBe(true)
    expect(result.name).toBe('Staging')
    expect(result.slug).toBe('staging')
  })

  test('DELETE removes an environment', async () => {
    const created = assertOk(await af('/api/v0/projects/:pid/environments', {
      method: 'POST',
      params: { pid: projectId },
      body: { name: 'Temp', slug: 'temp' },
    }))
    assertOk(await af('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE',
      params: { pid: projectId, id: created.id },
    }))
  })

  test('GET by slug resolves environment', async () => {
    const result = assertOk(await af('/api/v0/projects/:pid/environments/:id', {
      params: { pid: projectId, id: 'dev' },
    }))
    expect(result.slug).toBe('dev')
    expect(result.name).toBe('Dev')
  })
})

// ── Secrets — core flow ─────────────────────────────────────────────

describe('secrets — core flow', () => {
  let af: ReturnType<typeof authedFetch>
  let projectId: string
  let envId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'SecretUser' })
    af = authedFetch(user.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Secret Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Secret Project', orgId: org.id } }))
    projectId = proj.id
    const env = assertOk(await af('/api/v0/projects/:pid/environments/:id', { params: { pid: projectId, id: 'dev' } }))
    envId = env.id
  })

  test('set and get a secret value', async () => {
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: envId },
      body: { name: 'DATABASE_URL', value: 'postgres://localhost:5432/mydb' },
    }))

    const got = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: envId, name: 'DATABASE_URL' },
    }))
    expect(got.name).toBe('DATABASE_URL')
    expect(got.value).toBe('postgres://localhost:5432/mydb')
  })

  test('list secrets does not include values', async () => {
    const result = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: envId },
    }))
    expect(result.secrets.length).toBeGreaterThanOrEqual(1)
    const dbSecret = result.secrets.find((s) => s.name === 'DATABASE_URL')
    expect(dbSecret).toBeTruthy()
    expect(dbSecret!.name).toBe('DATABASE_URL')
    // list endpoint correctly does NOT return the value field
    expect(dbSecret).not.toHaveProperty('value')
  })

  test('delete secret makes it gone', async () => {
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: envId },
      body: { name: 'TO_DELETE', value: 'gone' },
    }))

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      method: 'DELETE',
      params: { pid: projectId, eid: envId, name: 'TO_DELETE' },
    }))

    const gone = await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: envId, name: 'TO_DELETE' },
    })
    expect(gone).toBeInstanceOf(Error)
  })

  test('event sourcing: set → update → delete → set yields final value', async () => {
    const p = { pid: projectId, eid: envId }
    const post = async (name: string, value: string) =>
      assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'POST', params: p, body: { name, value } }))
    const del = async (name: string) =>
      assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', { method: 'DELETE', params: { ...p, name } }))
    const get = (name: string) =>
      af('/api/v0/projects/:pid/environments/:eid/secrets/:name', { params: { ...p, name } })

    await post('EVOLVING', 'v1')
    await post('EVOLVING', 'v2')
    await del('EVOLVING')
    await post('EVOLVING', 'v3')

    const result = assertOk(await get('EVOLVING'))
    expect(result.value).toBe('v3')
  })

  test('bulk set secrets', async () => {
    const result = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT',
      params: { pid: projectId, eid: envId },
      body: { secrets: { BULK_A: 'alpha', BULK_B: 'beta', BULK_C: 'gamma' } },
    }))
    expect(result.ok).toBe(true)
    expect(result.secrets.sort()).toMatchInlineSnapshot(`
      [
        "BULK_A",
        "BULK_B",
        "BULK_C",
      ]
    `)

    for (const [name, value] of [['BULK_A', 'alpha'], ['BULK_B', 'beta'], ['BULK_C', 'gamma']] as const) {
      const s = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
        params: { pid: projectId, eid: envId, name },
      }))
      expect(s.value).toBe(value)
    }
  })
})

// ── Secrets — download formats ──────────────────────────────────────

describe('secrets — download formats', () => {
  let token: string
  let projectId: string
  let envId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'DownloadUser' })
    token = user.token
    const af = authedFetch(token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Download Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Download Project', orgId: org.id } }))
    projectId = proj.id
    const env = assertOk(await af('/api/v0/projects/:pid/environments/:id', { params: { pid: projectId, id: 'dev' } }))
    envId = env.id

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT',
      params: { pid: projectId, eid: envId },
      body: { secrets: { DB_HOST: 'localhost', DB_PORT: '5432' } },
    }))
  })

  // Download routes return raw text/json, so use app.handle() for these
  function downloadUrl(format: string) {
    return `http://e.ly/api/v0/projects/${projectId}/environments/${envId}/secrets/download?format=${format}`
  }
  function downloadReq(format: string) {
    return app.handle(new Request(downloadUrl(format), {
      headers: { authorization: `Bearer ${token}` },
    }))
  }

  test('json format', async () => {
    const res = await downloadReq('json')
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchInlineSnapshot(`
      {
        "DB_HOST": "localhost",
        "DB_PORT": "5432",
      }
    `)
  })

  test('env format', async () => {
    const res = await downloadReq('env')
    const text = await res.text()
    expect(text).toContain(`DB_HOST='localhost'`)
    expect(text).toContain(`DB_PORT='5432'`)
  })

  // Regression: values were JSON.stringify'd into double quotes, so
  // `source .env` ran $(...) and backticks. Names were unvalidated, so a
  // newline in a name injected extra lines into env/docker/yaml.
  test('env/yaml/docker downloads cannot inject shell commands or lines', async () => {
    const af = authedFetch(token)
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    const previewEnvId = envs.environments.find((e) => e.slug === 'preview')!.id

    const badName = await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: previewEnvId },
      body: { name: 'A\nEVIL', value: 'x' },
    })
    expect(badName).toBeInstanceOf(Error)
    const badBulk = await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT',
      params: { pid: projectId, eid: previewEnvId },
      body: { secrets: { 'X=1 Y': 'x' } },
    })
    expect(badBulk).toBeInstanceOf(Error)

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT',
      params: { pid: projectId, eid: previewEnvId },
      body: {
        secrets: {
          SUBSHELL: '$(touch /tmp/pwned)',
          BACKTICK: '`id`',
          VAR: '$HOME',
          QUOTE_ONLY: `it's`,
          QUOTE_AND_DOLLAR: `it's $(id)`,
          MULTILINE: 'line1\nline2',
        },
      },
    }))
    // Legacy rows written before validation must still be sanitized on output.
    await appendSecretEvents({
      author: { userId: null, apiTokenId: null },
      events: [
        { environmentId: previewEnvId, name: 'legacy-name', operation: 'set', value: 'ok' },
        { environmentId: previewEnvId, name: 'A\nEVIL', operation: 'set', value: 'x' },
      ],
    })

    const download = async (format: string) => {
      const res = await app.handle(new Request(
        `http://e.ly/api/v0/projects/${projectId}/environments/${previewEnvId}/secrets/download?format=${format}`,
        { headers: { authorization: `Bearer ${token}` } },
      ))
      return (await res.text()).split('\n').sort().join('\n')
    }

    expect(await download('env')).toMatchInlineSnapshot(`
      "
      BACKTICK='\`id\`'
      MULTILINE='line1
      QUOTE_AND_DOLLAR='it'\\''s $(id)'
      QUOTE_ONLY="it's"
      SUBSHELL='$(touch /tmp/pwned)'
      VAR='$HOME'
      legacy-name='ok'
      line2'"
    `)
    expect(await download('yaml')).toMatchInlineSnapshot(`
      "
      BACKTICK: "\`id\`"
      MULTILINE: "line1\\nline2"
      QUOTE_AND_DOLLAR: "it's $(id)"
      QUOTE_ONLY: "it's"
      SUBSHELL: "$(touch /tmp/pwned)"
      VAR: "$HOME"
      legacy-name: "ok""
    `)
    expect(await download('docker')).toMatchInlineSnapshot(`
      "
      BACKTICK=\`id\`
      MULTILINE=line1\\nline2
      QUOTE_AND_DOLLAR=it's $(id)
      QUOTE_ONLY=it's
      SUBSHELL=$(touch /tmp/pwned)
      VAR=$HOME
      legacy-name=ok"
    `)

    // Output stays readable by our dotenv parser for dotenv-representable values.
    const { parseEnv } = await import('./lib/parse-env.ts')
    const { renderEnvFile } = await import('./lib/utils.ts')
    const roundTrip = parseEnv(renderEnvFile([
      ['SUBSHELL', '$(touch /tmp/pwned)'],
      ['QUOTE_ONLY', `it's`],
      ['MULTILINE', 'line1\nline2'],
    ]))
    expect(roundTrip).toMatchInlineSnapshot(`
      {
        "MULTILINE": "line1
      line2",
        "QUOTE_ONLY": "it's",
        "SUBSHELL": "$(touch /tmp/pwned)",
      }
    `)
  })

  test('env-no-quotes format', async () => {
    const res = await downloadReq('env-no-quotes')
    const text = await res.text()
    expect(text).toContain('DB_HOST=localhost')
    expect(text).toContain('DB_PORT=5432')
    expect(text).not.toContain('"')
  })

  test('yaml format', async () => {
    const res = await downloadReq('yaml')
    const text = await res.text()
    expect(text).toContain('DB_HOST: "localhost"')
    expect(text).toContain('DB_PORT: "5432"')
  })

  test('dotnet-json format nests keys with __', async () => {
    const af = authedFetch(token)
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: envId },
      body: { name: 'CONNECTION__HOST', value: 'Server=localhost' },
    }))
    const res = await downloadReq('dotnet-json')
    const body: Record<string, Record<string, string>> = await res.json()
    // toDotnetJsonKey lowercases then PascalCases each segment
    expect(body.Connection).toBeTruthy()
    expect(body.Connection!.Host).toBe('Server=localhost')
  })
})

// ── API tokens ──────────────────────────────────────────────────────

describe('api tokens', () => {
  test('only its creator or an org admin deletes a token', async () => {
    const admin = await createTestUser({ name: 'Token Admin' })
    const owner = await createTestUser({ name: 'Token Owner' })
    const colleague = await createTestUser({ name: 'Token Colleague' })
    const orgId = assertOk(await authedFetch(admin.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Token Org' } })).id
    const tokenProject = assertOk(await authedFetch(admin.token)('/api/v0/projects', { method: 'POST', body: { name: 'Token Project', orgId } })).id
    for (const user of [owner, colleague]) await getDb().insert(schema.orgMember).values({ orgId, userId: user.user.id, role: 'member' })
    const token = { createdBy: owner.user.id, projectId: tokenProject }
    const deletes = async (who: typeof admin) => {
      try {
        await requireTokenDeletion({ userId: who.user.id, sessionId: await sessionIdOf(who.token), token })
        return 'ok'
      } catch (error) {
        return (error as Error).message
      }
    }
    expect({ owner: await deletes(owner), colleague: await deletes(colleague), admin: await deletes(admin) })
      .toEqual({ owner: 'ok', colleague: 'Only its creator or an org admin deletes or regenerates a token', admin: 'ok' })
  })

  test('a token acts with its creator\'s current access to its project', async () => {
    const admin = await createTestUser({ name: 'Scope Admin' })
    const member = await createTestUser({ name: 'Scope Member' })
    const af = authedFetch(admin.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Scope Org' } })).id
    const payments = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Payments', orgId } })).id
    const website = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Website', orgId } })).id
    const dev = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId: payments, id: 'dev' } })).id
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const { key } = await insertApiToken({ name: 'Payments CI', projectId: payments, createdBy: member.user.id })
    const read = async () => (await app.handle(new Request(`http://e.ly/api/v0/projects/${payments}/environments/${dev}/secrets`, { headers: { authorization: `Bearer ${key}` } }))).status
    const before = await read()
    // An admin limits the member to the website
    const [row] = await getDb().update(schema.orgMember).set({ projectAccess: 'selected' })
      .where(orm.and(orm.eq(schema.orgMember.orgId, orgId), orm.eq(schema.orgMember.userId, member.user.id))).returning({ id: schema.orgMember.id })
    await getDb().insert(schema.memberAccess).values({ orgMemberId: row!.id, projectId: website })
    expect({ before, after: await read() }).toEqual({ before: 200, after: 403 })
  })

  let userToken: string
  let projectId: string
  let devEnvId: string
  let previewEnvId: string
  let prodEnvId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'TokenUser' })
    userToken = user.token
    const af = authedFetch(userToken)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Token Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Token Project', orgId: org.id } }))
    projectId = proj.id
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    devEnvId = envs.environments.find((e) => e.slug === 'dev')!.id
    previewEnvId = envs.environments.find((e) => e.slug === 'preview')!.id
    prodEnvId = envs.environments.find((e) => e.slug === 'prod')!.id

    // Seed a secret in dev
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: devEnvId },
      body: { name: 'TOKEN_TEST', value: 'secret-value' },
    }))
  })

  test('project-scoped token can access secrets', async () => {
    const user = await createTestUser({ name: 'TokenCreator' })
    const { key } = await insertApiToken({
      name: 'ci-token',
      projectId,
      createdBy: user.user.id,
    })

    // Use the API token to access secrets
    const tokenFetch = authedFetch(key)
    const result = assertOk(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: devEnvId, name: 'TOKEN_TEST' },
    }))
    expect(result.value).toBe('secret-value')
  })

  test('an expired token gets 401 API token expired, one still valid keeps working', async () => {
    const user = await createTestUser({ name: 'ExpiryUser' })
    const expired = await insertApiToken({ name: 'expired', projectId, createdBy: user.user.id, expiresAt: Date.now() - 1000 })
    const valid = await insertApiToken({ name: 'valid', projectId, createdBy: user.user.id, expiresAt: Date.now() + 86_400_000 })
    const read = (key: string) => app.handle(new Request(
      `http://e.ly/api/v0/projects/${projectId}/environments/${devEnvId}/secrets/TOKEN_TEST`,
      { headers: { authorization: `Bearer ${key}` } },
    ))
    const expiredRes = await read(expired.key)
    expect({ expired: { status: expiredRes.status, body: await expiredRes.json() }, valid: (await read(valid.key)).status })
      .toEqual({ expired: { status: 401, body: { error: 'API token expired' } }, valid: 200 })
  })

  test('last use and its IP are recorded, at most once an hour', async () => {
    const user = await createTestUser({ name: 'LastUsedUser' })
    const { key, tokenId } = await insertApiToken({ name: 'last-used', projectId, createdBy: user.user.id })
    const read = async (ip: string) => assertOk(await createSpiceflowFetch(app, {
      headers: { authorization: `Bearer ${key}`, 'cf-connecting-ip': ip },
    })('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: devEnvId, name: 'TOKEN_TEST' },
    }))
    const lastUse = async () => (await getDb().query.apiToken.findFirst({ where: { id: tokenId }, columns: { lastUsedAt: true, lastUsedIp: true } }))!
    await read('203.0.113.1')
    const first = await lastUse()
    await read('203.0.113.2')
    const second = await lastUse()
    // Two hours later, the next use writes again
    await getDb().update(schema.apiToken).set({ lastUsedAt: Date.now() - 2 * 3_600_000 }).where(orm.eq(schema.apiToken.id, tokenId))
    await read('203.0.113.3')
    const third = await lastUse()
    expect({
      recorded: first.lastUsedAt !== null,
      firstIp: first.lastUsedIp,
      unchangedWithinHour: second.lastUsedAt === first.lastUsedAt && second.lastUsedIp === first.lastUsedIp,
      rewrittenLater: third.lastUsedAt !== null && third.lastUsedAt > Date.now() - 60_000,
      laterIp: third.lastUsedIp,
    }).toEqual({ recorded: true, firstIp: '203.0.113.1', unchangedWithinHour: true, rewrittenLater: true, laterIp: '203.0.113.3' })
  })

  // Regression: secret_event.api_token_id was ON DELETE CASCADE, so deleting
  // a token deleted the secrets it wrote and reverted overwritten values.
  test('deleting a token or user keeps the secrets it wrote', async () => {
    const user = await createTestUser({ name: 'TokenDeleteUser' })
    const { key, tokenId } = await insertApiToken({ name: 'writer', projectId, createdBy: user.user.id })
    assertOk(await authedFetch(userToken)('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: devEnvId },
      body: { name: 'TOKEN_OVERWRITE', value: 'written-by-user' },
    }))
    assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT',
      params: { pid: projectId, eid: devEnvId },
      body: { secrets: { TOKEN_OVERWRITE: 'overwritten-by-token', TOKEN_ONLY: 'written-by-token' } },
    }))

    // Same for a deleted user (user_id was also ON DELETE CASCADE).
    const author = await createTestUser({ name: 'DeletedAuthor' })
    await appendSecretEvents({
      author: { userId: author.user.id, apiTokenId: null },
      events: [{ environmentId: devEnvId, name: 'USER_ONLY', operation: 'set', value: 'written-by-deleted-user' }],
    })

    await getDb().delete(schema.apiToken).where(orm.eq(schema.apiToken.id, tokenId))
    await getDb().delete(schema.user).where(orm.eq(schema.user.id, author.user.id))

    const derived = await deriveSecrets(devEnvId)
    const values = Object.fromEntries(await Promise.all(
      derived
        .filter((d) => ['TOKEN_OVERWRITE', 'TOKEN_ONLY', 'USER_ONLY'].includes(d.name))
        .map(async (d) => [d.name, await decrypt(d.valueEncrypted!, d.iv!, d)] as const),
    ))
    expect(values).toMatchInlineSnapshot(`
      {
        "TOKEN_ONLY": "written-by-token",
        "TOKEN_OVERWRITE": "overwritten-by-token",
        "USER_ONLY": "written-by-deleted-user",
      }
    `)
  })

  test('env-scoped token cannot access other environments', async () => {
    const user = await createTestUser({ name: 'ScopedTokenUser' })
    const { key } = await insertApiToken({
      name: 'dev-only',
      projectId,
      createdBy: user.user.id,
      environmentIds: [devEnvId],
    })

    const tokenFetch = authedFetch(key)

    // Access dev env — should work
    const devResult = assertOk(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))
    expect(devResult.secrets).toBeTruthy()

    // Access prod env — should be forbidden
    const prodResult = await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: prodEnvId },
    })
    assertErrorStatus(prodResult, 403)
  })

  test('invalid token returns 401', async () => {
    const badFetch = authedFetch('sig_invalid_token_that_does_not_exist')
    const result = await badFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    })
    assertErrorStatus(result, 401)
  })

  test('project-scoped token can get its project (setup path)', async () => {
    const user = await createTestUser({ name: 'SetupTokenUser' })
    const { key } = await insertApiToken({
      name: 'setup-token',
      projectId,
      createdBy: user.user.id,
    })

    const result = assertOk(await authedFetch(key)('/api/v0/projects/:id', {
      params: { id: projectId },
    }))
    expect(result.id).toBe(projectId)
    expect(result.environments.map((e) => e.slug).sort()).toEqual(['dev', 'preview', 'prod'])
  })

  test('project-scoped token can list only its project', async () => {
    const user = await createTestUser({ name: 'ListTokenUser' })
    const { key } = await insertApiToken({
      name: 'list-token',
      projectId,
      createdBy: user.user.id,
    })

    const result = assertOk(await authedFetch(key)('/api/v0/projects'))
    expect(result.projects.map((p) => p.id)).toEqual([projectId])
  })

  test('project-scoped token can list its environments', async () => {
    const user = await createTestUser({ name: 'EnvListTokenUser' })
    const { key } = await insertApiToken({
      name: 'env-list-token',
      projectId,
      createdBy: user.user.id,
    })

    const result = assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments', {
      params: { pid: projectId },
    }))
    expect(result.environments.map((e) => e.slug).sort()).toEqual(['dev', 'preview', 'prod'])
  })

  test('token cannot get a different project', async () => {
    const db = getDb()
    const user = await createTestUser({ name: 'CrossProjectTokenUser' })
    const af = authedFetch(user.token)
    const otherOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Other Org' } }))
    const otherProj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Other Project', orgId: otherOrg.id } }))

    const { key } = await insertApiToken({
      name: 'scoped-token',
      projectId,
      createdBy: user.user.id,
    })

    const result = await authedFetch(key)('/api/v0/projects/:id', {
      params: { id: otherProj.id },
    })
    assertErrorStatus(result, 403)
  })

  test('env-scoped token only sees that environment on the project', async () => {
    const user = await createTestUser({ name: 'EnvScopedSetupUser' })
    const { key } = await insertApiToken({
      name: 'dev-setup',
      projectId,
      createdBy: user.user.id,
      environmentIds: [devEnvId],
    })

    const project = assertOk(await authedFetch(key)('/api/v0/projects/:id', {
      params: { id: projectId },
    }))
    expect(project.environments.map((e) => e.slug)).toEqual(['dev'])

    const envs = assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments', {
      params: { pid: projectId },
    }))
    expect(envs.environments.map((e) => e.slug)).toEqual(['dev'])
  })

  test('token cannot mutate a project', async () => {
    const user = await createTestUser({ name: 'MutateTokenUser' })
    const { key } = await insertApiToken({
      name: 'read-only',
      projectId,
      createdBy: user.user.id,
    })

    const patched = await authedFetch(key)('/api/v0/projects/:id', {
      method: 'PATCH',
      params: { id: projectId },
      body: { name: 'Hacked' },
    })
    assertErrorStatus(patched, 401)
  })

  test('invalid token on project get returns 401', async () => {
    const result = await authedFetch('sig_invalid_token_that_does_not_exist')('/api/v0/projects/:id', {
      params: { id: projectId },
    })
    assertErrorStatus(result, 401)
  })

  test('deleting a scoped environment revokes the token', async () => {
    const user = await createTestUser({ name: 'CascadeTokenUser' })
    const af = authedFetch(user.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Cascade Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Cascade Project', orgId: org.id } }))
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: proj.id } }))
    const dev = envs.environments.find((e) => e.slug === 'dev')!
    const prod = envs.environments.find((e) => e.slug === 'prod')!

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: proj.id, eid: prod.id },
      body: { name: 'PROD_SECRET', value: 'prod-value' },
    }))

    const { key } = await insertApiToken({
      name: 'dev-only',
      projectId: proj.id,
      createdBy: user.user.id,
      environmentIds: [dev.id],
    })

    assertOk(await af('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE',
      params: { pid: proj.id, id: dev.id },
    }))

    const result = await authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: proj.id, eid: prod.id, name: 'PROD_SECRET' },
    })
    assertErrorStatus(result, 401)
  })

  test('project-scoped token can call me and list its org', async () => {
    const user = await createTestUser({ name: 'MeTokenUser' })
    const { key } = await insertApiToken({
      name: 'me-token',
      projectId,
      createdBy: user.user.id,
    })

    const tf = authedFetch(key)
    const me = assertOk(await tf('/api/v0/me'))
    expect(me.user.id).toBe(user.user.id)
    expect(me.user.name).toBe('MeTokenUser')
    expect(me.orgs).toHaveLength(1)

    const orgs = assertOk(await tf('/api/v0/orgs'))
    expect(orgs.orgs.map((org) => org.id)).toEqual([me.orgs[0]!.id])
  })

  test('project-scoped token can get an environment', async () => {
    const user = await createTestUser({ name: 'EnvGetTokenUser' })
    const { key } = await insertApiToken({
      name: 'env-get-token',
      projectId,
      createdBy: user.user.id,
    })

    const result = assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments/:id', {
      params: { pid: projectId, id: devEnvId },
    }))
    expect(result.id).toBe(devEnvId)
    expect(result.slug).toBe('dev')
  })

  test('env-scoped token cannot get a different environment', async () => {
    const user = await createTestUser({ name: 'EnvGetScopedUser' })
    const { key } = await insertApiToken({
      name: 'dev-get',
      projectId,
      createdBy: user.user.id,
      environmentIds: [devEnvId],
    })

    const result = await authedFetch(key)('/api/v0/projects/:pid/environments/:id', {
      params: { pid: projectId, id: prodEnvId },
    })
    assertErrorStatus(result, 403)
  })

  test('token scoped to multiple envs can access those envs but not others', async () => {
    const user = await createTestUser({ name: 'MultiEnvTokenUser' })
    const { key } = await insertApiToken({
      name: 'dev-preview',
      projectId,
      createdBy: user.user.id,
      environmentIds: [devEnvId, previewEnvId],
    })

    const tokenFetch = authedFetch(key)
    assertOk(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))
    assertOk(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: previewEnvId },
    }))
    assertErrorStatus(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: prodEnvId },
    }), 403)

    const project = assertOk(await tokenFetch('/api/v0/projects/:id', {
      params: { id: projectId },
    }))
    expect(project.environments.map((e) => e.slug).sort()).toEqual(['dev', 'preview'])

    const envs = assertOk(await tokenFetch('/api/v0/projects/:pid/environments', {
      params: { pid: projectId },
    }))
    expect(envs.environments.map((e) => e.slug).sort()).toEqual(['dev', 'preview'])
  })

  test('deleting one env from a multi-env token keeps the others', async () => {
    const user = await createTestUser({ name: 'PartialCascadeUser' })
    const af = authedFetch(user.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Partial Cascade Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Partial Cascade Project', orgId: org.id } }))
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: proj.id } }))
    const dev = envs.environments.find((e) => e.slug === 'dev')!
    const preview = envs.environments.find((e) => e.slug === 'preview')!
    const prod = envs.environments.find((e) => e.slug === 'prod')!

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: proj.id, eid: preview.id },
      body: { name: 'PREVIEW_SECRET', value: 'preview-value' },
    }))
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: proj.id, eid: prod.id },
      body: { name: 'PROD_SECRET', value: 'prod-value' },
    }))

    const { key } = await insertApiToken({
      name: 'dev-preview',
      projectId: proj.id,
      createdBy: user.user.id,
      environmentIds: [dev.id, preview.id],
    })

    assertOk(await af('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE',
      params: { pid: proj.id, id: dev.id },
    }))

    const tokenFetch = authedFetch(key)
    const previewSecret = assertOk(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: proj.id, eid: preview.id, name: 'PREVIEW_SECRET' },
    }))
    expect(previewSecret.value).toBe('preview-value')
    assertErrorStatus(await tokenFetch('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: proj.id, eid: prod.id, name: 'PROD_SECRET' },
    }), 403)
  })
})

// ── Security — cross-user isolation ─────────────────────────────────
// Uses app.handle() directly here to check specific HTTP status codes (403 vs 401)

describe('security — cross-user isolation', () => {
  let userAToken: string
  let userAProjectId: string
  let userAEnvId: string
  let userAOrgId: string
  let userBToken: string

  beforeAll(async () => {
    const userA = await createTestUser({ name: 'Alice', email: 'alice-sec@test.com' })
    userAToken = userA.token
    const userB = await createTestUser({ name: 'Bob', email: 'bob-sec@test.com' })
    userBToken = userB.token

    const af = authedFetch(userAToken)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Alice Org' } }))
    userAOrgId = org.id
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Alice Project', orgId: userAOrgId } }))
    userAProjectId = proj.id
    const env = assertOk(await af('/api/v0/projects/:pid/environments/:id', { params: { pid: userAProjectId, id: 'dev' } }))
    userAEnvId = env.id

    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: userAProjectId, eid: userAEnvId },
      body: { name: 'ALICE_SECRET', value: 'only-for-alice' },
    }))
  })

  function req({ path, token, method = 'GET', body }: { path: string; token: string; method?: string; body?: object }) {
    const headers: Record<string, string> = { authorization: `Bearer ${token}` }
    if (body) headers['content-type'] = 'application/json'
    return app.handle(new Request(`http://e.ly${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    }))
  }

  test('user B cannot access user A project (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}`, token: userBToken })
    expect(res.status).toBe(403)
  })

  test('user B cannot list user A secrets (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}/secrets`, token: userBToken })
    expect(res.status).toBe(403)
  })

  test('user B cannot create project in user A org (403)', async () => {
    const res = await req({ path: '/api/v0/projects', token: userBToken, method: 'POST', body: { name: 'Sneaky', orgId: userAOrgId } })
    expect(res.status).toBe(403)
  })

  test('user B cannot delete user A project (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}`, token: userBToken, method: 'DELETE' })
    expect(res.status).toBe(403)
  })

  test('user B cannot get user A secret value (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}/secrets/ALICE_SECRET`, token: userBToken })
    expect(res.status).toBe(403)
  })

  // Write-path isolation — these are the scary paths
  test('user B cannot set secrets in user A env (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}/secrets`, token: userBToken, method: 'POST', body: {
      name: 'INJECTED', value: 'evil',
    } })
    expect(res.status).toBe(403)
  })

  test('user B cannot bulk-set secrets in user A env (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}/secrets`, token: userBToken, method: 'PUT', body: {
      secrets: { INJECTED: 'evil' },
    } })
    expect(res.status).toBe(403)
  })

  test('user B cannot delete user A secret (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}/secrets/ALICE_SECRET`, token: userBToken, method: 'DELETE' })
    expect(res.status).toBe(403)
  })

  test('user B cannot create environment in user A project (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments`, token: userBToken, method: 'POST', body: {
      name: 'Injected', slug: 'injected',
    } })
    expect(res.status).toBe(403)
  })

  test('user B cannot delete user A environment (403)', async () => {
    const res = await req({ path: `/api/v0/projects/${userAProjectId}/environments/${userAEnvId}`, token: userBToken, method: 'DELETE' })
    expect(res.status).toBe(403)
  })
})

// ── Secrets derivation — batching & multi-author ────────────────────
// deriveEnvironmentSecretsAndNames powers the project secrets page loader.
// It must (1) derive the selected env's secrets, (2) return the union of
// names across ALL envs, and (3) do it in a SINGLE db.batch round-trip
// regardless of env count — this guards against the old N+1 author lookup
// and the separate names/values round-trips.

describe('secrets derivation — batching & multi-author', () => {
  let af: ReturnType<typeof authedFetch>
  let projectId: string
  let devEnvId: string
  let prodEnvId: string
  let authorAId: string
  let authorBId: string

  beforeAll(async () => {
    const owner = await createTestUser({ name: 'DeriveOwner' })
    af = authedFetch(owner.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Derive Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Derive Project', orgId: org.id } }))
    projectId = proj.id
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    devEnvId = envs.environments.find((e) => e.slug === 'dev')!.id
    prodEnvId = envs.environments.find((e) => e.slug === 'prod')!.id

    // Two distinct authors so the resolver must handle >1 userId.
    const authorA = await createTestUser({ name: 'Author A' })
    const authorB = await createTestUser({ name: 'Author B' })
    authorAId = authorA.user.id
    authorBId = authorB.user.id

    const db = getDb()
    const a = await encrypt('alpha-value', { environmentId: devEnvId, name: 'SHARED_KEY' })
    const b = await encrypt('beta-value', { environmentId: devEnvId, name: 'DEV_ONLY' })
    const c = await encrypt('prod-only-value', { environmentId: prodEnvId, name: 'PROD_ONLY' })
    const aProd = await encrypt('alpha-value', { environmentId: prodEnvId, name: 'SHARED_KEY' })
    // dev: SHARED_KEY by author A, DEV_ONLY by author B
    await db.insert(schema.secretEvent).values([
      { environmentId: devEnvId, name: 'SHARED_KEY', operation: 'set', valueEncrypted: a.encrypted, iv: a.iv, userId: authorAId },
      { environmentId: devEnvId, name: 'DEV_ONLY', operation: 'set', valueEncrypted: b.encrypted, iv: b.iv, userId: authorBId },
      // prod: SHARED_KEY + PROD_ONLY so the names union spans envs
      { environmentId: prodEnvId, name: 'SHARED_KEY', operation: 'set', valueEncrypted: aProd.encrypted, iv: aProd.iv, userId: authorAId },
      { environmentId: prodEnvId, name: 'PROD_ONLY', operation: 'set', valueEncrypted: c.encrypted, iv: c.iv, userId: authorBId },
    ])
  })

  test('derives selected env secrets + name union across all envs', async () => {
    const { secrets, allNames } = await deriveEnvironmentSecretsAndNames({
      environmentIds: [devEnvId, prodEnvId],
      selectedEnvId: devEnvId,
    })

    expect(secrets.map((s) => s.name).sort()).toEqual(['DEV_ONLY', 'SHARED_KEY'])
    // names union spans BOTH environments, not just the selected one
    expect(allNames).toMatchInlineSnapshot(`
      [
        "DEV_ONLY",
        "PROD_ONLY",
        "SHARED_KEY",
      ]
    `)
    // both authors are represented across the derived secrets
    const authorIds = new Set(secrets.map((s) => s.actor))
    expect(authorIds).toEqual(new Set([`user:${authorAId}`, `user:${authorBId}`]))
  })

  test('event sourcing: delete removes a name from both secrets and union', async () => {
    const db = getDb()
    // Delete DEV_ONLY in dev — it should vanish from dev secrets, and since it
    // existed only in dev, it should vanish from the cross-env name union too.
    // Through the chain, which first takes in the rows from before it
    await appendSecretEvents({ author: { userId: authorAId, apiTokenId: null }, events: [{ environmentId: devEnvId, name: 'DEV_ONLY', operation: 'delete' }] })

    const { secrets, allNames } = await deriveEnvironmentSecretsAndNames({
      environmentIds: [devEnvId, prodEnvId],
      selectedEnvId: devEnvId,
    })
    expect(secrets.map((s) => s.name)).toEqual(['SHARED_KEY'])
    expect(allNames).toEqual(['PROD_ONLY', 'SHARED_KEY'])
  })

  test('empty env list returns empty results without querying', async () => {
    const result = await deriveEnvironmentSecretsAndNames({ environmentIds: [], selectedEnvId: null })
    expect(result).toEqual({ secrets: [], allNames: [] })
  })

  test('null selected env returns no secrets but the same full name union', async () => {
    // Order-independent: the name union must NOT depend on which env is
    // selected, so a null selection yields the same union as selecting an env.
    const withSelection = await deriveEnvironmentSecretsAndNames({
      environmentIds: [devEnvId, prodEnvId],
      selectedEnvId: devEnvId,
    })
    const withoutSelection = await deriveEnvironmentSecretsAndNames({
      environmentIds: [devEnvId, prodEnvId],
      selectedEnvId: null,
    })
    expect(withoutSelection.secrets).toEqual([])
    expect(withoutSelection.allNames).toEqual(withSelection.allNames)
    // PROD_ONLY + SHARED_KEY are seeded and never deleted, so always present.
    expect(withoutSelection.allNames).toContain('PROD_ONLY')
    expect(withoutSelection.allNames).toContain('SHARED_KEY')
  })
})

// ── Removing a member ───────────────────────────────────────────────

describe('removing a member', () => {
  test('sticks in an org that auto-joins their domain', async () => {
    const domain = `rejoin-${Date.now()}.com`
    const admin = await createTestUser({ email: `admin@${domain}`, name: 'Rejoin Admin' })
    const leaver = await createTestUser({ email: `leaver@${domain}`, name: 'Leaver' })
    await getDb().update(schema.user).set({ emailVerified: true }).where(orm.inArray(schema.user.id, [admin.user.id, leaver.user.id]))
    const orgId = assertOk(await authedFetch(admin.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Rejoin Org', enableAutoJoin: true } })).id
    const session = (await getSession(new Request('http://e.ly/dash', { headers: { authorization: `Bearer ${leaver.token}` } })))!
    const isMember = async () => !!await getDb().query.orgMember.findFirst({ where: { orgId, userId: leaver.user.id } })
    await autoJoinOrgsByDomain(session)
    const joined = await isMember()
    await deleteOrgMember((await getDb().query.orgMember.findFirst({ where: { orgId, userId: leaver.user.id } }))!, { userId: admin.user.id })
    // Their next page load, with the session they still have
    await autoJoinOrgsByDomain(session)
    expect({ joined, afterRemoval: await isMember() }).toEqual({ joined: true, afterRemoval: false })
  })

  test('a demoted admin\'s invite links stop working, as a removed member\'s do', async () => {
    const admin = await createTestUser({ name: 'Staying Admin' })
    const demoted = await createTestUser({ name: 'Demoted Admin' })
    const orgId = assertOk(await authedFetch(admin.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Demote Org' } })).id
    const [member] = await getDb().insert(schema.orgMember).values({ orgId, userId: demoted.user.id, role: 'admin' }).returning()
    await getDb().insert(schema.orgInvitation).values({ orgId, createdBy: demoted.user.id, expiresAt: Date.now() + 60_000 })
    await setOrgMemberRole({ member: member!, role: 'member', by: { userId: admin.user.id } })
    expect(await getDb().query.orgInvitation.findMany({ where: { orgId } })).toEqual([])
  })

  test('revokes the tokens and invite links they created and keeps their secrets', async () => {
    const admin = await createTestUser({ name: 'RemovalAdmin' })
    const leaver = await createTestUser({ name: 'RemovalLeaver' })
    const af = authedFetch(admin.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Removal Org' } }))
    const project = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Removal Project', orgId: org.id } }))
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: project.id } }))
    const devEnvId = envs.environments.find((e) => e.slug === 'dev')!.id

    const db = getDb()
    const [member] = await db.insert(schema.orgMember)
      .values({ orgId: org.id, userId: leaver.user.id, role: 'admin' })
      .returning({ id: schema.orgMember.id, orgId: schema.orgMember.orgId, userId: schema.orgMember.userId, role: schema.orgMember.role })
    const leaverToken = await generateApiToken()
    await db.insert(schema.apiToken).values({
      name: 'leaver-ci', projectId: project.id, prefix: leaverToken.prefix, hashedKey: leaverToken.hashedKey, createdBy: leaver.user.id,
    })
    // Tokens someone else created are not the leaver's to take along
    const adminToken = await generateApiToken()
    await db.insert(schema.apiToken).values({
      name: 'admin-ci', projectId: project.id, prefix: adminToken.prefix, hashedKey: adminToken.hashedKey, createdBy: admin.user.id,
    })
    await db.insert(schema.orgInvitation).values({ orgId: org.id, createdBy: leaver.user.id, expiresAt: Date.now() + 60_000 })
    assertOk(await authedFetch(leaverToken.key)('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST', params: { pid: project.id, eid: devEnvId }, body: { name: 'BY_LEAVER_CI', value: 'v' },
    }))

    await deleteOrgMember(member!, { userId: admin.user.id })

    const listWith = (key: string) => authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: project.id, eid: devEnvId },
    })
    assertErrorStatus(await listWith(leaverToken.key), 401)
    assertOk(await listWith(adminToken.key))
    expect(await db.query.orgInvitation.findMany({ where: { orgId: org.id } })).toEqual([])
    expect((await deriveSecrets(devEnvId)).map((s) => s.name)).toEqual(['BY_LEAVER_CI'])
  })
})

// ── Encryption roundtrip ────────────────────────────────────────────

// ── Secrets list — isEmpty and allNames ─────────────────────────────

describe('secrets list — isEmpty and allNames', () => {
  let af: ReturnType<typeof authedFetch>
  let projectId: string
  let devEnvId: string
  let prodEnvId: string

  beforeAll(async () => {
    const user = await createTestUser({ name: 'ListFieldsUser' })
    af = authedFetch(user.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'ListFields Org' } }))
    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'ListFields Project', orgId: org.id } }))
    projectId = proj.id
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    devEnvId = envs.environments.find((e) => e.slug === 'dev')!.id
    prodEnvId = envs.environments.find((e) => e.slug === 'prod')!.id
  })

  test('isEmpty is true for empty-string secrets', async () => {
    // Set a normal secret and an empty-string secret in dev
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST', params: { pid: projectId, eid: devEnvId },
      body: { name: 'HAS_VALUE', value: 'some-value' },
    }))
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST', params: { pid: projectId, eid: devEnvId },
      body: { name: 'EMPTY_SECRET', value: '' },
    }))

    const result = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))

    const hasValue = result.secrets.find((s) => s.name === 'HAS_VALUE')
    const emptySecret = result.secrets.find((s) => s.name === 'EMPTY_SECRET')
    expect(hasValue!.isEmpty).toBe(false)
    expect(emptySecret!.isEmpty).toBe(true)
  })

  test('allNames includes secrets from all environments', async () => {
    // Set a secret only in prod (not in dev)
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST', params: { pid: projectId, eid: prodEnvId },
      body: { name: 'PROD_ONLY', value: 'prod-value' },
    }))

    const result = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))

    // allNames should include secrets from both dev and prod
    expect(result.allNames).toContain('HAS_VALUE')
    expect(result.allNames).toContain('EMPTY_SECRET')
    expect(result.allNames).toContain('PROD_ONLY')

    // PROD_ONLY should NOT be in the secrets array (it's only in prod)
    const prodOnly = result.secrets.find((s) => s.name === 'PROD_ONLY')
    expect(prodOnly).toBeUndefined()
  })
})

describe('encryption roundtrip', () => {
  const slot = { environmentId: 'env-1', name: 'X' }

  test('encrypt then decrypt returns original', async () => {
    const { encrypted, iv } = await encrypt('hello-world', slot)
    const decrypted = await decrypt(encrypted, iv, slot)
    expect(decrypted).toBe('hello-world')
  })

  test('two encryptions produce different IVs', async () => {
    const a = await encrypt('same-value', slot)
    const b = await encrypt('same-value', slot)
    expect(a.iv).not.toBe(b.iv)
    expect(a.encrypted).not.toBe(b.encrypted)
  })

  test('empty string roundtrip', async () => {
    const { encrypted, iv } = await encrypt('', slot)
    const decrypted = await decrypt(encrypted, iv, slot)
    expect(decrypted).toBe('')
  })

  test('unicode roundtrip', async () => {
    const value = '🔐 Ключ шифрования 密钥'
    const { encrypted, iv } = await encrypt(value, slot)
    const decrypted = await decrypt(encrypted, iv, slot)
    expect(decrypted).toBe(value)
  })
})

describe('encryption v2', () => {
  const slot = { environmentId: 'env-1', name: 'X' }
  // Also in cli/test/selfhost.test.ts, which checks that self-host's
  // re-encryption writes the same bytes
  const vector = {
    key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
    iv: 'c2lnaWxsby12Mml2',
    encrypted: 'v2.t1.04HOaWtJFS4lf19AmZ7SSntwRBs93eL6CAmTPylB1fxE2Y6tqkquxR0BRLSg',
    slot: { environmentId: '01TESTENVIRONMENT', name: 'DATABASE_URL' },
    value: 'postgres://app:hunter2@db/app',
  }
  const outcome = (run: () => Promise<unknown>) => run().then((value) => value, (error: Error) => error.message)
  const withKeys = async <T>(keys: string, run: () => Promise<T>) => {
    const before = process.env.ENCRYPTION_KEYS
    process.env.ENCRYPTION_KEYS = keys
    try {
      return await run()
    } finally {
      if (before === undefined) delete process.env.ENCRYPTION_KEYS
      else process.env.ENCRYPTION_KEYS = before
    }
  }

  test('binds a value to its environment and name, and names its key', async () => {
    const stored = await encrypt('v', slot)
    expect({
      prefix: stored.encrypted.slice(0, 5),
      same: await decrypt(stored.encrypted, stored.iv, slot),
      otherEnvironment: await outcome(() => decrypt(stored.encrypted, stored.iv, { ...slot, environmentId: 'env-2' })),
      otherName: await outcome(() => decrypt(stored.encrypted, stored.iv, { ...slot, name: 'Y' })),
    }).toEqual({ prefix: 'v2.0.', same: 'v', otherEnvironment: "X can't be decrypted", otherName: "Y can't be decrypted" })
  })

  test('new values use the ring\'s current key, older ones keep theirs, and a missing key is named', async () => {
    const underKey0 = await encrypt('under key 0', slot)
    const inRing = await withKeys(JSON.stringify({ current: 't1', keys: { t1: vector.key } }), async () => {
      const underT1 = await encrypt('under t1', slot)
      return {
        underT1,
        prefix: underT1.encrypted.slice(0, 6),
        vector: await decrypt(vector.encrypted, vector.iv, vector.slot),
        key0: await decrypt(underKey0.encrypted, underKey0.iv, slot),
        t1: await decrypt(underT1.encrypted, underT1.iv, slot),
      }
    })
    expect({
      ...inRing,
      underT1: undefined,
      withoutT1: await outcome(() => decrypt(inRing.underT1.encrypted, inRing.underT1.iv, slot)),
      noCurrent: await withKeys(JSON.stringify({ current: 't2', keys: { t1: vector.key } }), () => outcome(() => encrypt('v', slot))),
      shortKey: await withKeys(JSON.stringify({ current: 't1', keys: { t1: 'c2hvcnQ=' } }), () => outcome(() => encrypt('v', slot))),
    }).toEqual({
      underT1: undefined,
      prefix: 'v2.t1.',
      vector: vector.value,
      key0: 'under key 0',
      t1: 'under t1',
      withoutT1: "X is encrypted with the key t1, which this instance doesn't have",
      noCurrent: 'ENCRYPTION_KEYS names no current key it holds',
      shortKey: 'ENCRYPTION_KEYS holds an invalid key: t1',
    })
  })

  test('values from before v2 read next to v2 ones', async () => {
    const user = await createTestUser({ name: 'V1 User' })
    const af = authedFetch(user.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'V1 Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'V1 Project', orgId } })).id
    const envId = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'dev' } })).id
    // A value as the Worker stored it before v2: key 0, no prefix, no additional data
    const key0 = await crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', new TextEncoder().encode(workerEnv.BETTER_AUTH_SECRET)), { name: 'AES-GCM' }, false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key0, new TextEncoder().encode('from v1')))
    await getDb().insert(schema.secretEvent).values({
      environmentId: envId, name: 'OLD', operation: 'set', userId: user.user.id,
      valueEncrypted: btoa(String.fromCharCode(...ciphertext)), iv: btoa(String.fromCharCode(...iv)),
    })
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'POST', params: { pid: projectId, eid: envId }, body: { name: 'NEW', value: 'from v2' } }))
    const res = await app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${envId}/secrets/download?format=json`, { headers: { authorization: `Bearer ${user.token}` } }))
    const stored = await getDb().query.secretEvent.findMany({ where: { environmentId: envId }, orderBy: { createdAt: 'asc' } })
    expect({ values: await res.json(), formats: stored.map((row) => [row.name, row.valueEncrypted!.startsWith('v2.0.')]) })
      .toEqual({ values: { NEW: 'from v2', OLD: 'from v1' }, formats: [['OLD', false], ['NEW', true]] })
  })
})

// ── Auto-join by email domain ───────────────────────────────────────

describe('auto-join by email domain', () => {
  test('creates org with autoJoinDomain when enableAutoJoin is true', async () => {
    const user = await createTestUser({ email: 'admin@acme-test.com', name: 'AcmeAdmin' })
    const db = getDb()
    // Mark email as verified — required before enabling auto-join
    await db.update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, user.user.id)).limit(1)
    const af = authedFetch(user.token)
    const result = assertOk(await af('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'Acme Auto', enableAutoJoin: true },
    }))
    expect(result.ok).toBe(true)

    // Verify the domain was stored
    const org = await db.query.org.findFirst({ where: { id: result.id } })
    expect(org?.autoJoinDomain).toBe('acme-test.com')
  })

  test('creates org without autoJoinDomain by default', async () => {
    const user = await createTestUser({ email: 'admin2@acme-test.com', name: 'AcmeAdmin2' })
    const af = authedFetch(user.token)
    const result = assertOk(await af('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'Acme No Auto' },
    }))

    const db = getDb()
    const org = await db.query.org.findFirst({ where: { id: result.id } })
    expect(org?.autoJoinDomain).toBeNull()
  })

  test('rejects enableAutoJoin for public email domains', async () => {
    const user = await createTestUser({ email: 'user@gmail.com', name: 'GmailUser' })
    const af = authedFetch(user.token)
    const result = await af('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'Gmail Org', enableAutoJoin: true },
    })
    expect(result).toBeInstanceOf(Error)
  })

  test('autoJoinOrgsByDomain adds user to matching org', async () => {
    // Create an org with auto-join domain (admin must be verified)
    const admin = await createTestUser({ email: 'founder@joinme-test.com', name: 'Founder' })
    const db = getDb()
    await db.update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, admin.user.id)).limit(1)
    const adminFetch = authedFetch(admin.token)
    const orgResult = assertOk(await adminFetch('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'JoinMe Org', enableAutoJoin: true },
    }))

    // Create a second user with the same domain
    const employee = await createTestUser({ email: 'employee@joinme-test.com', name: 'Employee' })

    // Mark the employee's email as verified (signUpEmail doesn't verify by default)
    await db.update(schema.user)
      .set({ emailVerified: true })
      .where(orm.eq(schema.user.id, employee.user.id))
      .limit(1)

    // Run auto-join
    await autoJoinOrgsByDomain({
      userId: employee.user.id,
      user: { id: employee.user.id, name: 'Employee', email: 'employee@joinme-test.com', emailVerified: true },
    })

    // Verify the employee is now a member
    const member = await db.query.orgMember.findFirst({
      where: { orgId: orgResult.id, userId: employee.user.id },
    })
    expect(member).toBeTruthy()
    expect(member!.role).toBe('member')
  })

  test('autoJoinOrgsByDomain skips unverified emails', async () => {
    const admin = await createTestUser({ email: 'admin@noverify-test.com', name: 'NoVerifyAdmin' })
    const db = getDb()
    await db.update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, admin.user.id)).limit(1)
    const adminFetch = authedFetch(admin.token)
    const orgResult = assertOk(await adminFetch('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'NoVerify Org', enableAutoJoin: true },
    }))

    const unverified = await createTestUser({ email: 'unverified@noverify-test.com', name: 'Unverified' })

    // Do NOT mark email as verified
    await autoJoinOrgsByDomain({
      userId: unverified.user.id,
      user: { id: unverified.user.id, name: 'Unverified', email: 'unverified@noverify-test.com', emailVerified: false },
    })

    const member = await db.query.orgMember.findFirst({
      where: { orgId: orgResult.id, userId: unverified.user.id },
    })
    expect(member).toBeUndefined()
  })

  test('autoJoinOrgsByDomain is idempotent', async () => {
    const admin = await createTestUser({ email: 'admin@idempotent-test.com', name: 'IdempAdmin' })
    const db = getDb()
    await db.update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, admin.user.id)).limit(1)
    const adminFetch = authedFetch(admin.token)
    const orgResult = assertOk(await adminFetch('/api/v0/orgs', {
      method: 'POST',
      body: { name: 'Idempotent Org', enableAutoJoin: true },
    }))

    const joiner = await createTestUser({ email: 'joiner@idempotent-test.com', name: 'Joiner' })
    await db.update(schema.user)
      .set({ emailVerified: true })
      .where(orm.eq(schema.user.id, joiner.user.id))
      .limit(1)

    const session = {
      userId: joiner.user.id,
      user: { id: joiner.user.id, name: 'Joiner', email: 'joiner@idempotent-test.com', emailVerified: true },
    }

    // Run twice — should not throw
    await autoJoinOrgsByDomain(session)
    await autoJoinOrgsByDomain(session)

    // Should still have exactly one membership
    const members = await db.query.orgMember.findMany({
      where: { orgId: orgResult.id, userId: joiner.user.id },
    })
    expect(members.length).toBe(1)
  })

  test('autoJoinOrgsByDomain skips common email domains', async () => {
    // Even if somehow an org has autoJoinDomain set, users with gmail should not auto-join
    // (the domain blocklist check is in autoJoinOrgsByDomain itself)
    const gmailUser = await createTestUser({ email: 'someone@gmail.com', name: 'GmailSkip' })
    const db = getDb()
    await db.update(schema.user)
      .set({ emailVerified: true })
      .where(orm.eq(schema.user.id, gmailUser.user.id))
      .limit(1)

    // This should be a no-op, not throw
    await autoJoinOrgsByDomain({
      userId: gmailUser.user.id,
      user: { id: gmailUser.user.id, name: 'GmailSkip', email: 'someone@gmail.com', emailVerified: true },
    })
  })

  // AGENTS.md: "First user to claim a domain gets it." Without a unique claim,
  // any verified colleague could create a second org for the same domain and
  // silently enroll everyone who signs in next.
  test('a second org cannot claim a domain another org already auto-joins', async () => {
    const db = getDb()
    const first = await createTestUser({ email: 'it@claimed-test.com', name: 'FirstClaim' })
    const second = await createTestUser({ email: 'mallory@claimed-test.com', name: 'SecondClaim' })
    await db.update(schema.user).set({ emailVerified: true }).where(orm.inArray(schema.user.id, [first.user.id, second.user.id]))
    const org = assertOk(await authedFetch(first.token)('/api/v0/orgs', {
      method: 'POST', body: { name: 'Claimed Co', enableAutoJoin: true },
    }))
    assertErrorStatus(await authedFetch(second.token)('/api/v0/orgs', {
      method: 'POST', body: { name: 'Claimed Co (new)', enableAutoJoin: true },
    }), 400)

    // The next colleague to sign in joins the first claimant's org only
    const colleague = await createTestUser({ email: 'dev@claimed-test.com', name: 'Colleague' })
    await autoJoinOrgsByDomain({
      userId: colleague.user.id,
      user: { id: colleague.user.id, name: 'Colleague', email: 'dev@claimed-test.com', emailVerified: true },
    })
    const memberships = await db.query.orgMember.findMany({ where: { userId: colleague.user.id } })
    expect(memberships.map((m) => m.orgId)).toEqual([org.id])
  })

  test('only the org that owns a domain may turn auto-join back on', async () => {
    const db = getDb()
    const owner = await createTestUser({ email: 'owner@reclaim-test.com', name: 'Owner' })
    await db.update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, owner.user.id))
    const org = assertOk(await authedFetch(owner.token)('/api/v0/orgs', {
      method: 'POST', body: { name: 'Reclaim Co', enableAutoJoin: true },
    }))
    const session = {
      userId: owner.user.id,
      user: { id: owner.user.id, name: 'Owner', email: 'owner@reclaim-test.com', emailVerified: true },
    }
    expect(await getClaimableAutoJoinDomain({ session, orgId: org.id })).toBe('reclaim-test.com')
    expect(await getClaimableAutoJoinDomain({ session })).toBeInstanceOf(Error)
    // The unique index also stops two claims that race past the check
    await expect(db.insert(schema.org).values({ name: 'Racer', autoJoinDomain: 'reclaim-test.com' })).rejects.toThrow()
  })
})

// ── Member access — granular project + secret restrictions ──────────
// Tests for the memberAccess table that gates per-member project access
// restrictions. Admins always bypass them. orgMember.projectAccess 'all'
// ignores the rules; 'selected' only allows listed projects (none if empty).

describe('member access — project scoping', () => {
  let adminToken: string
  let memberToken: string
  let memberId: string // orgMember.id
  let memberUserId: string
  let orgId: string
  let projectAId: string
  let projectBId: string
  let projectADevEnvId: string
  let projectBDevEnvId: string

  beforeAll(async () => {
    const admin = await createTestUser({ name: 'AccessAdmin' })
    adminToken = admin.token
    const member = await createTestUser({ name: 'AccessMember' })
    memberToken = member.token
    memberUserId = member.user.id

    const af = authedFetch(adminToken)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Access Org' } }))
    orgId = org.id

    // Add member to org
    const db = getDb()
    const [memberRow] = await db.insert(schema.orgMember)
      .values({ orgId, userId: memberUserId, role: 'member' })
      .returning({ id: schema.orgMember.id })
    memberId = memberRow!.id

    // Create two projects
    const projA = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Project A', orgId } }))
    const projB = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Project B', orgId } }))
    projectAId = projA.id
    projectBId = projB.id

    // Get env IDs
    const envsA = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectAId } }))
    const envsB = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectBId } }))
    projectADevEnvId = envsA.environments.find((e) => e.slug === 'dev')!.id
    projectBDevEnvId = envsB.environments.find((e) => e.slug === 'dev')!.id

    // Seed secrets in both projects
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT', params: { pid: projectAId, eid: projectADevEnvId },
      body: { secrets: { A_SECRET: 'a-value', A_OTHER: 'a-other' } },
    }))
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT', params: { pid: projectBId, eid: projectBDevEnvId },
      body: { secrets: { B_SECRET: 'b-value' } },
    }))
  })

  const restrictTo = async (projectIds: string[]) => {
    const db = getDb()
    await db.update(schema.orgMember).set({ projectAccess: 'selected' }).where(orm.eq(schema.orgMember.id, memberId))
    for (const projectId of projectIds) await db.insert(schema.memberAccess).values({ orgMemberId: memberId, projectId })
  }
  const unrestrict = async () => {
    const db = getDb()
    await db.update(schema.orgMember).set({ projectAccess: 'all' }).where(orm.eq(schema.orgMember.id, memberId))
    await db.delete(schema.memberAccess).where(orm.eq(schema.memberAccess.orgMemberId, memberId))
  }

  test('projectAccess all = full access', async () => {
    const mf = authedFetch(memberToken)
    // Member with no access rules can see all projects
    const projects = assertOk(await mf('/api/v0/projects'))
    const orgProjects = projects.projects.filter((p) => p.orgId === orgId)
    expect(orgProjects.length).toBe(2)

    // Can access both projects' secrets
    const secretsA = assertOk(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectAId, eid: projectADevEnvId },
    }))
    expect(secretsA.secrets.length).toBeGreaterThanOrEqual(1)

    const secretsB = assertOk(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectBId, eid: projectBDevEnvId },
    }))
    expect(secretsB.secrets.length).toBeGreaterThanOrEqual(1)
  })

  test('access rules restrict to listed projects only', async () => {
    await restrictTo([projectAId])

    const mf = authedFetch(memberToken)

    // Can see Project A
    const projectA = assertOk(await mf('/api/v0/projects/:id', { params: { id: projectAId } }))
    expect(projectA.name).toBe('Project A')

    // Cannot see Project B (403)
    assertErrorStatus(await mf('/api/v0/projects/:id', { params: { id: projectBId } }), 403)

    // Project list only shows Project A
    const projects = assertOk(await mf('/api/v0/projects'))
    const orgProjects = projects.projects.filter((p) => p.orgId === orgId)
    expect(orgProjects.map((p) => p.name)).toEqual(['Project A'])

    // Cannot access Project B secrets (403 from requireSecretsApiAuth)
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectBId, eid: projectBDevEnvId },
    }), 403)

    await unrestrict()
  })

  test('admin always has full access regardless of access rules', async () => {
    const access = await getMemberProjectAccess({ userId: memberUserId, orgId, projectId: projectBId })
    // After cleanup, member should have full access again
    expect(access).toBe(true)

    // Admin always has full access
    const af = authedFetch(adminToken)
    const projectB = assertOk(await af('/api/v0/projects/:id', { params: { id: projectBId } }))
    expect(projectB.name).toBe('Project B')
  })

  test('getAccessibleProjectIds returns null for unrestricted member', async () => {
    const ids = await getAccessibleProjectIds(memberUserId, orgId)
    expect(ids).toBeNull()
  })

  test('getAccessibleProjectIds returns project list for restricted member', async () => {
    await restrictTo([projectAId])
    expect(await getAccessibleProjectIds(memberUserId, orgId)).toEqual([projectAId])
    await unrestrict()
  })

  // Regression: zero member_access rows used to mean "all projects", so
  // deleting a member's last allowed project (FK cascade) unlocked every project.
  test('deleting the last allowed project does not unlock the others', async () => {
    const af = authedFetch(adminToken)
    const temp = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Temp', orgId } }))
    await restrictTo([temp.id])
    assertOk(await authedFetch(memberToken)('/api/v0/projects/:id', { method: 'DELETE', params: { id: temp.id } }))
    expect(await getAccessibleProjectIds(memberUserId, orgId)).toEqual([])
    assertErrorStatus(await authedFetch(memberToken)('/api/v0/projects/:id', { params: { id: projectBId } }), 403)
    await unrestrict()
  })
})

describe('landing on the dashboard', () => {
  test('a member who can open none of the newest organization\'s projects lands on a page, not in a redirect loop', async () => {
    const admin = await createTestUser({ name: 'Landing Admin' })
    const member = await createTestUser({ name: 'Landing Member' })
    const af = authedFetch(admin.token)
    const olderOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Older Org' } })).id
    const reachable = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Reachable', orgId: olderOrg } })).id
    const newerOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Newer Org' } })).id
    await getDb().update(schema.org).set({ createdAt: Date.now() + 1000 }).where(orm.eq(schema.org.id, newerOrg))
    assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Not Theirs', orgId: newerOrg } }))
    await getDb().insert(schema.orgMember).values([
      { orgId: olderOrg, userId: member.user.id, role: 'member' },
      { orgId: newerOrg, userId: member.user.id, role: 'member', projectAccess: 'selected' },
    ])
    // Follows redirects, as a browser would, for a few hops
    const follow = async (path: string) => {
      for (let hop = 0; hop < 5; hop++) {
        const res = await app.handle(new Request(`http://e.ly${path}`, { headers: { authorization: `Bearer ${member.token}` }, redirect: 'manual' }))
        if (res.status < 300 || res.status >= 400) return { path: path.split('/').slice(0, 4).join('/'), status: res.status }
        path = new URL(res.headers.get('location')!, 'http://e.ly').pathname
      }
      return { path, status: 'loop' }
    }
    expect({ dash: await follow('/dash'), newerOrg: await follow(`/dash/orgs/${newerOrg}`) }).toEqual({
      dash: { path: `/dash/projects/${reachable}`, status: 200 },
      newerOrg: { path: `/dash/orgs/${newerOrg}`, status: 200 },
    })
  })
})

describe('environment access roles', () => {
  let adminToken: string
  let memberToken: string
  let orgId: string
  let projectId: string
  let devEnvId: string
  let prodEnvId: string

  beforeAll(async () => {
    const admin = await createTestUser({ name: 'EnvRoleAdmin' })
    adminToken = admin.token
    const member = await createTestUser({ name: 'EnvRoleMember' })
    memberToken = member.token

    const af = authedFetch(adminToken)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'EnvRole Org' } }))
    orgId = org.id

    const db = getDb()
    await db.insert(schema.orgMember)
      .values({ orgId, userId: member.user.id, role: 'member' })

    const proj = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'EnvRole Project', orgId } }))
    projectId = proj.id
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectId } }))
    devEnvId = envs.environments.find((e) => e.slug === 'dev')!.id
    prodEnvId = envs.environments.find((e) => e.slug === 'prod')!.id

    // Restrict prod environment to admin-only BEFORE any secret operations
    await db.update(schema.environment)
      .set({ accessRole: 'admin' })
      .where(orm.eq(schema.environment.id, prodEnvId))
      .limit(1)

    // Seed secrets in both environments (admin token bypasses prod restriction)
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT', params: { pid: projectId, eid: devEnvId },
      body: { secrets: { DEV_SECRET: 'dev-value' } },
    }))
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'PUT', params: { pid: projectId, eid: prodEnvId },
      body: { secrets: { PROD_SECRET: 'prod-value' } },
    }))
  })

  test('member can access dev environment (accessRole=member)', async () => {
    const mf = authedFetch(memberToken)
    const result = assertOk(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))
    expect(result.secrets.length).toBeGreaterThanOrEqual(1)
    // Regression: allNames included names from every env, even admin-only ones.
    expect(result.allNames).toContain('DEV_SECRET')
    expect(result.allNames).not.toContain('PROD_SECRET')
    const admin = assertOk(await authedFetch(adminToken)('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))
    expect(admin.allNames).toContain('PROD_SECRET')
  })

  test('env-scoped token only sees names from its own envs', async () => {
    const db = getDb()
    const admin = await db.query.orgMember.findFirst({ where: { orgId, role: 'admin' }, columns: { userId: true } })
    const { key } = await insertApiToken({ name: 'dev-only', projectId, createdBy: admin!.userId, environmentIds: [devEnvId] })
    const result = assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: devEnvId },
    }))
    expect(result.allNames).not.toContain('PROD_SECRET')
  })

  test('member cannot access prod environment (accessRole=admin) — 403', async () => {
    const mf = authedFetch(memberToken)
    // List secrets
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      params: { pid: projectId, eid: prodEnvId },
    }), 403)
    // Get secret value
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: prodEnvId, name: 'PROD_SECRET' },
    }), 403)
    // Set secret
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:eid/secrets', {
      method: 'POST',
      params: { pid: projectId, eid: prodEnvId },
      body: { name: 'INJECTED', value: 'evil' },
    }), 403)
    // Delete secret
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      method: 'DELETE',
      params: { pid: projectId, eid: prodEnvId, name: 'PROD_SECRET' },
    }), 403)
  })

  test('admin can always access admin-restricted environments', async () => {
    const af = authedFetch(adminToken)
    const result = assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: prodEnvId, name: 'PROD_SECRET' },
    }))
    expect(result.value).toBe('prod-value')
  })

  test('member can still access dev secrets normally', async () => {
    const mf = authedFetch(memberToken)
    const result = assertOk(await mf('/api/v0/projects/:pid/environments/:eid/secrets/:name', {
      params: { pid: projectId, eid: devEnvId, name: 'DEV_SECRET' },
    }))
    expect(result.value).toBe('dev-value')
  })

  test('download blocked for member on admin-only environment', async () => {
    const res = await app.handle(new Request(
      `http://e.ly/api/v0/projects/${projectId}/environments/${prodEnvId}/secrets/download?format=json`,
      { headers: { authorization: `Bearer ${memberToken}` } },
    ))
    expect(res.status).toBe(403)
  })

  // Regression: the API-token branch never checked accessRole, so a member
  // could create a project-wide token and read admin-only envs with it.
  test('admin-only env needs a token created by a current admin', async () => {
    const db = getDb()
    const admin = await db.query.orgMember.findFirst({ where: { orgId, role: 'admin' }, columns: { userId: true } })
    const member = await db.query.orgMember.findFirst({ where: { orgId, role: 'member' }, columns: { userId: true } })
    const memberKey = (await insertApiToken({ name: 'member-token', projectId, createdBy: member!.userId })).key
    const adminKey = (await insertApiToken({ name: 'admin-token', projectId, createdBy: admin!.userId })).key
    const path = '/api/v0/projects/:pid/environments/:eid/secrets/:name' as const

    assertErrorStatus(await authedFetch(memberKey)(path, { params: { pid: projectId, eid: prodEnvId, name: 'PROD_SECRET' } }), 403)
    assertOk(await authedFetch(memberKey)(path, { params: { pid: projectId, eid: devEnvId, name: 'DEV_SECRET' } }))
    expect(assertOk(await authedFetch(adminKey)(path, { params: { pid: projectId, eid: prodEnvId, name: 'PROD_SECRET' } })).value).toBe('prod-value')
  })

  // Regression: authz lookups were memoized for up to 15 minutes.
  test('making an env admin-only takes effect immediately', async () => {
    const db = getDb()
    const mf = authedFetch(memberToken)
    const path = '/api/v0/projects/:pid/environments/:eid/secrets/:name' as const
    assertOk(await mf(path, { params: { pid: projectId, eid: devEnvId, name: 'DEV_SECRET' } }))
    await db.update(schema.environment).set({ accessRole: 'admin' }).where(orm.eq(schema.environment.id, devEnvId))
    assertErrorStatus(await mf(path, { params: { pid: projectId, eid: devEnvId, name: 'DEV_SECRET' } }), 403)
    await db.update(schema.environment).set({ accessRole: 'member' }).where(orm.eq(schema.environment.id, devEnvId))
  })
})

// ── Authorization outside the secrets API ───────────────────────────
// Environment and project routes used to check org membership only, so a
// member scoped to one project could delete another project's admin-only
// prod. Tests adapted from #13 and #15 by Nikolai Kolodziej.
describe('authorization — project scoping and admin-only environments', () => {
  let adminToken: string
  let memberToken: string
  let scopedToken: string
  let orgId: string
  let projectAId: string
  let aDevEnvId: string
  let aProdEnvId: string

  beforeAll(async () => {
    const admin = await createTestUser({ name: 'AuthzAdmin' })
    const member = await createTestUser({ name: 'AuthzMember' })
    const scoped = await createTestUser({ name: 'AuthzScoped' })
    adminToken = admin.token
    memberToken = member.token
    scopedToken = scoped.token
    const af = authedFetch(adminToken)
    orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Authz Org' } })).id
    projectAId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Authz A', orgId } })).id
    const projectBId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Authz B', orgId } })).id
    const envs = assertOk(await af('/api/v0/projects/:pid/environments', { params: { pid: projectAId } }))
    aDevEnvId = envs.environments.find((e) => e.slug === 'dev')!.id
    aProdEnvId = envs.environments.find((e) => e.slug === 'prod')!.id

    const db = getDb()
    await db.insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const [scopedRow] = await db.insert(schema.orgMember)
      .values({ orgId, userId: scoped.user.id, role: 'member' })
      .returning({ id: schema.orgMember.id })
    await db.update(schema.orgMember).set({ projectAccess: 'selected' }).where(orm.eq(schema.orgMember.id, scopedRow!.id))
    await db.insert(schema.memberAccess).values({ orgMemberId: scopedRow!.id, projectId: projectBId })
    await db.update(schema.environment).set({ accessRole: 'admin' }).where(orm.eq(schema.environment.id, aProdEnvId))
  })

  test('a member scoped to another project gets 403 on every environment route', async () => {
    const sf = authedFetch(scopedToken)
    assertErrorStatus(await sf('/api/v0/projects/:pid/environments', { params: { pid: projectAId } }), 403)
    assertErrorStatus(await sf('/api/v0/projects/:pid/environments/:id', { params: { pid: projectAId, id: aDevEnvId } }), 403)
    assertErrorStatus(await sf('/api/v0/projects/:pid/environments', {
      method: 'POST', params: { pid: projectAId }, body: { name: 'Staging', slug: 'staging' },
    }), 403)
    assertErrorStatus(await sf('/api/v0/projects/:pid/environments/:id', {
      method: 'PATCH', params: { pid: projectAId, id: aDevEnvId }, body: { name: 'Renamed' },
    }), 403)
    assertErrorStatus(await sf('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE', params: { pid: projectAId, id: aDevEnvId },
    }), 403)
  })

  test('a member cannot rename or delete an admin-only env, or its project', async () => {
    const mf = authedFetch(memberToken)
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:id', {
      method: 'PATCH', params: { pid: projectAId, id: aProdEnvId }, body: { name: 'Pwned' },
    }), 403)
    assertErrorStatus(await mf('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE', params: { pid: projectAId, id: aProdEnvId },
    }), 403)
    assertErrorStatus(await mf('/api/v0/projects/:id', { method: 'DELETE', params: { id: projectAId } }), 403)
    expect(await getDb().query.environment.findFirst({ where: { id: aProdEnvId } })).toBeDefined()
  })

  test('a member manages the environments they can read', async () => {
    const mf = authedFetch(memberToken)
    const created = assertOk(await mf('/api/v0/projects/:pid/environments', {
      method: 'POST', params: { pid: projectAId }, body: { name: 'QA', slug: 'qa' },
    }))
    assertOk(await mf('/api/v0/projects/:pid/environments/:id', {
      method: 'PATCH', params: { pid: projectAId, id: created.id }, body: { name: 'QA 2' },
    }))
    assertOk(await mf('/api/v0/projects/:pid/environments/:id', {
      method: 'DELETE', params: { pid: projectAId, id: created.id },
    }))
  })

  test('a removed member loses org access on the next request', async () => {
    const extra = await createTestUser({ name: 'AuthzRemoved' })
    await getDb().insert(schema.orgMember).values({ orgId, userId: extra.user.id, role: 'member' })
    const xf = authedFetch(extra.token)
    const createProject = (name: string) => xf('/api/v0/projects', { method: 'POST', body: { name, orgId } })
    assertOk(await createProject('Before removal'))
    await getDb().delete(schema.orgMember).where(orm.and(
      orm.eq(schema.orgMember.orgId, orgId),
      orm.eq(schema.orgMember.userId, extra.user.id),
    ))
    assertErrorStatus(await createProject('After removal'), 403)
  })
})

// ── Time formatting ─────────────────────────────────────────────────
//
// These guard the hydration bug class described in lib/utils.ts: the worker
// renders in UTC and the browser renders in the visitor's zone, so any
// formatter that reads the ambient timezone or Date.now() produces different
// text on each side. React reports that as error #418 and shows the user a
// date that is not theirs.

describe('formatTime', () => {
  // 2026-07-29T23:16Z — a real production timestamp that rendered as
  // "Jul 29" on the worker and "Jul 30" in a UTC+2 browser.
  const nearMidnightUtc = Date.UTC(2026, 6, 29, 23, 16)

  test('same timestamp formats to a different day per timezone', () => {
    expect(formatAbsoluteDate({ ts: nearMidnightUtc, timeZone: 'UTC' })).toMatchInlineSnapshot(`"Jul 29, 2026"`)
    expect(formatAbsoluteDate({ ts: nearMidnightUtc, timeZone: 'Europe/Rome' })).toMatchInlineSnapshot(`"Jul 30, 2026"`)
  })

  test('output depends only on its arguments, never on ambient state', () => {
    // Called twice, seconds apart in wall-clock terms, with the same inputs.
    const now = Date.UTC(2026, 6, 31, 12, 0)
    const first = formatTime({ ts: nearMidnightUtc, now, timeZone: 'UTC' })
    const second = formatTime({ ts: nearMidnightUtc, now, timeZone: 'UTC' })
    expect(first).toBe(second)
    expect(first).toMatchInlineSnapshot(`"Jul 29, 2026"`)
  })

  test('relative buckets', () => {
    const now = Date.UTC(2026, 6, 31, 12, 0)
    expect(formatTime({ ts: now - 30_000, now, timeZone: 'UTC' })).toMatchInlineSnapshot(`"just now"`)
    expect(formatTime({ ts: now - 5 * 60_000, now, timeZone: 'UTC' })).toMatchInlineSnapshot(`"5m ago"`)
    expect(formatTime({ ts: now - 3 * 3_600_000, now, timeZone: 'UTC' })).toMatchInlineSnapshot(`"3h ago"`)
    expect(formatTime({ ts: now - 3 * 86_400_000, now, timeZone: 'UTC' })).toMatchInlineSnapshot(`"Jul 28, 2026"`)
    // A future time (a token's expiry) is a date, not "just now"
    expect(formatTime({ ts: now + 90 * 86_400_000, now, timeZone: 'UTC' })).toBe(formatAbsoluteDate({ ts: now + 90 * 86_400_000, timeZone: 'UTC' }))
  })

  test('a bucket boundary crossing between SSR and hydration changes the text', () => {
    // This is precisely why <TimeAgo> renders the absolute UTC date on the
    // first pass instead of a relative bucket: the server and the hydrating
    // client do not share a clock.
    const ssr = Date.UTC(2026, 6, 31, 12, 0, 0)
    const hydration = ssr + 400 // ~400ms later, crossing the minute boundary
    const ts = ssr - 119_600
    expect(formatTime({ ts, now: ssr, timeZone: 'UTC' })).toMatchInlineSnapshot(`"1m ago"`)
    expect(formatTime({ ts, now: hydration, timeZone: 'UTC' })).toMatchInlineSnapshot(`"2m ago"`)
  })
})

describe('oauthClientRegistration', () => {
  // oauth-provider 1.7.6 refuses http redirect URIs for web clients
  test('registers local dev as a native client and a deployment as a web client', () => {
    const local = oauthClientRegistration({ origin: 'http://localhost:5188', callbackUrl: 'http://localhost:5188/api/auth/callback/sigillo', isLocal: true })
    const deployed = oauthClientRegistration({ origin: 'https://secrets.example.com', callbackUrl: 'https://secrets.example.com/api/auth/callback/sigillo', isLocal: false })
    expect({ local: local.application_type, deployed: 'application_type' in deployed }).toEqual({ local: 'native', deployed: false })
  })
})

describe('session tokens read out of D1', () => {
  const call = (path: string, init: { body?: unknown; token?: string } = {}) => app.handle(new Request(`http://e.ly${path}`, {
    method: init.body === undefined ? 'GET' : 'POST',
    headers: {
      'content-type': 'application/json',
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  }))

  test('a raw session token copied out of D1 is refused', async () => {
    const { user } = await createTestUser()
    const [row] = await getDb().select().from(schema.session).where(orm.eq(schema.session.userId, user.id))
    const res = await call('/api/v0/me', { token: row!.token })
    // CLI logins from before this change are raw tokens too: tell them what to do
    expect({ status: res.status, body: await res.json() }).toEqual({
      status: 401,
      body: { error: 'not signed in, or the session expired: run `sigillo login`' },
    })
  })

  test('an id_token copied out of D1 cannot be used to sign in', async () => {
    // account.id_token is stored as is; /sign-in/social would verify it and sign in
    const res = await call('/api/auth/sign-in/social', { body: { provider: 'sigillo', idToken: { token: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln' } } })
    expect({ status: res.status, body: await res.json() }).toEqual({ status: 400, body: { message: 'id_token sign-in is disabled', code: 'ID_TOKEN_SIGN_IN_DISABLED' } })
  })

  test('the device flow hands the CLI a signed token, and its raw part alone is refused', async () => {
    const { token: approver } = await createTestUser()
    const code = await (await call('/api/auth/device/code', { body: { client_id: 'sigillo-cli' } })).json() as { device_code: string; user_code: string }
    // Like the /device page: claim the code while signed in, then approve it
    expect((await call(`/api/auth/device?user_code=${code.user_code}`, { token: approver })).status).toBe(200)
    expect((await call('/api/auth/device/approve', { body: { userCode: code.user_code }, token: approver })).status).toBe(200)
    const issued = await (await call('/api/auth/device/token', {
      body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: code.device_code, client_id: 'sigillo-cli' },
    })).json() as { access_token: string }
    expect({
      signed: (await call('/api/v0/me', { token: issued.access_token })).status,
      raw: (await call('/api/v0/me', { token: issued.access_token.split('.')[0] })).status,
    }).toEqual({ signed: 200, raw: 401 })
  })

  test('a device code read out of D1 during a CLI login can\'t be exchanged for the session', async () => {
    const { token: approver } = await createTestUser()
    const code = await (await call('/api/auth/device/code', { body: { client_id: 'sigillo-cli' } })).json() as { device_code: string; user_code: string }
    const stored = (await getDb().query.deviceCode.findFirst({ where: { userCode: code.user_code } }))!.deviceCode
    await call(`/api/auth/device?user_code=${code.user_code}`, { token: approver })
    await call('/api/auth/device/approve', { body: { userCode: code.user_code }, token: approver })
    const exchange = async (deviceCode: string) => {
      const res = await call('/api/auth/device/token', { body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode, client_id: 'sigillo-cli' } })
      return { status: res.status, token: typeof (await res.json() as { access_token?: unknown }).access_token }
    }
    expect({ storedRaw: stored === code.device_code, fromD1: await exchange(stored), fromCli: await exchange(code.device_code) }).toEqual({
      storedRaw: false,
      fromD1: { status: 400, token: 'undefined' },
      fromCli: { status: 200, token: 'string' },
    })
  })
})

describe('sign-in allowlist (ALLOWED_USERS)', () => {
  // Assigning undefined to process.env stores the string "undefined": delete instead
  const setAllowed = (value: string | undefined) => {
    if (value === undefined) delete process.env.ALLOWED_USERS
    else process.env.ALLOWED_USERS = value
  }
  const withAllowed = async (value: string, fn: () => Promise<void>) => {
    const before = process.env.ALLOWED_USERS
    setAllowed(value)
    try { await fn() } finally { setAllowed(before) }
  }
  const me = (token: string) => app.handle(new Request('http://e.ly/api/v0/me', { headers: { authorization: `Bearer ${token}` } }))

  test('an API token stops working once its creator is off the list', async () => {
    const creator = await createTestUser({ name: 'Leaver' })
    const af = authedFetch(creator.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Leaver Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Leaver Project', orgId } })).id
    const { key } = await insertApiToken({ name: 'CI', projectId, createdBy: creator.user.id })
    const listed = (await me(key)).status
    await withAllowed('someone-else@example.com', async () => {
      expect({ listed, unlisted: (await me(key)).status }).toEqual({ listed: 200, unlisted: 401 })
    })
  })

  test('only verified emails match: an address itself, a domain exactly', () => {
    const list = 'Ops@Partner.io, acme.com'
    expect({
      address: isUserAllowed({ email: 'ops@partner.io', emailVerified: true }, list),
      otherAddress: isUserAllowed({ email: 'dev@partner.io', emailVerified: true }, list),
      domain: isUserAllowed({ email: 'Jane@ACME.com', emailVerified: true }, list),
      subdomain: isUserAllowed({ email: 'jane@eu.acme.com', emailVerified: true }, list),
      unverified: isUserAllowed({ email: 'jane@acme.com', emailVerified: false }, list),
      emptyList: isUserAllowed({ email: 'anyone@example.com', emailVerified: false }, ' , '),
      unset: isUserAllowed({ email: 'anyone@example.com', emailVerified: false }, undefined),
    }).toEqual({ address: true, otherAddress: false, domain: true, subdomain: false, unverified: false, emptyList: true, unset: true })
  })

  test('a refused sign-in explains itself on /login, whichever way the callback spells it', () => {
    const refused = loginErrorMessage('USER_NOT_ALLOWED')
    expect({
      sessionRefused: refused,
      newUserRefused: loginErrorMessage('user_not_allowed') === refused,
      other: loginErrorMessage('state_not_found'),
    }).toMatchInlineSnapshot(`
      {
        "newUserRefused": true,
        "other": "Signing in failed (state_not_found).",
        "sessionRefused": "This account may not sign in here. Ask whoever runs this Sigillo instance to add your email address or domain.",
      }
    `)
  })

  test('someone not on the list cannot sign up', async () => {
    await withAllowed('allowed.example', async () => {
      const auth = await getTestAuth()
      const result = await auth.api.signUpEmail({ body: { email: `x-${Date.now()}@elsewhere.example`, name: 'X', password: 'test-password-123' } }).catch((error) => error)
      expect(result).toBeInstanceOf(Error)
    })
  })

  test('an existing session stops working once its user is off the list', async () => {
    const { user, token } = await createTestUser({ email: `listed-${Date.now()}@allowed.example` })
    await getDb().update(schema.user).set({ emailVerified: true }).where(orm.eq(schema.user.id, user.id))
    const statuses: Record<string, number> = {}
    await withAllowed('allowed.example', async () => { statuses.listed = (await me(token)).status })
    await withAllowed('other.example', async () => { statuses.unlisted = (await me(token)).status })
    expect(statuses).toEqual({ listed: 200, unlisted: 401 })
  })
})

describe('your sessions', () => {
  test('a login ends 30 days after its sign-in, however often it is used', async () => {
    const user = await createTestUser({ name: 'Old Login' })
    const sessionId = await sessionIdOf(user.token)
    const age = (days: number) => getDb().update(schema.session).set({ createdAt: Date.now() - days * 24 * 60 * 60 * 1000 }).where(orm.eq(schema.session.id, sessionId))
    const me = async () => (await app.handle(new Request('http://e.ly/api/v0/me', { headers: { authorization: `Bearer ${user.token}` } }))).status
    await age(29)
    const at29 = await me()
    await age(31)
    const at31 = await me()
    expect({ at29, at31, left: !!await getDb().query.session.findFirst({ where: { id: sessionId } }) }).toEqual({ at29: 200, at31: 401, left: false })
  })

  const me = (headers: Record<string, string>) => app.handle(new Request('http://e.ly/api/v0/me', { headers }))
  const bearer = (token: string) => ({ authorization: `Bearer ${token}` })
  const as = (token: string) => new Request('http://e.ly/dash/sessions', { headers: bearer(token) })
  const sessionIds = async (userId: string) =>
    (await getDb().select({ id: schema.session.id }).from(schema.session).where(orm.eq(schema.session.userId, userId))).map((row) => row.id)
  const signed = async (token: string) => `${token}.${await makeSignature(token, (await (await getTestAuth()).$context).secret)}`
  // A second session for the same user, like signing in on another device
  const signInAgain = async (email: string) => {
    const auth = await getTestAuth()
    return signed((await auth.api.signInEmail({ body: { email, password: 'test-password-123' } })).token)
  }

  test('lists only your own sessions and marks the current one', async () => {
    const alice = await createTestUser({ email: `alice-${Date.now()}@example.com` })
    await signInAgain(alice.user.email)
    await createTestUser()
    const listed = await listUserSessions(as(alice.token))
    expect({ count: listed.length, current: listed.filter((row) => row.isCurrent).length, tokens: listed.some((row) => 'token' in row) })
      .toEqual({ count: 2, current: 1, tokens: false })
  })

  test('ends only your own sessions, and an ended one stops working at once', async () => {
    const alice = await createTestUser({ email: `alice2-${Date.now()}@example.com` })
    const other = await signInAgain(alice.user.email)
    const bob = await createTestUser()
    const [bobSession] = await sessionIds(bob.user.id)
    await endUserSession(as(alice.token), bobSession!)
    const aliceOther = (await listUserSessions(as(alice.token))).find((row) => !row.isCurrent)!.id
    await endUserSession(as(alice.token), aliceOther)
    expect({
      bob: (await me(bearer(bob.token))).status,
      aliceEnded: (await me(bearer(other))).status,
      aliceCurrent: (await me(bearer(alice.token))).status,
    }).toEqual({ bob: 200, aliceEnded: 401, aliceCurrent: 200 })
  })

  test('ends all your other sessions, but not this one', async () => {
    const alice = await createTestUser({ email: `alice3-${Date.now()}@example.com` })
    await signInAgain(alice.user.email)
    await signInAgain(alice.user.email)
    await endOtherUserSessions(as(alice.token))
    const listed = await listUserSessions(as(alice.token))
    expect(listed.map((row) => row.isCurrent)).toEqual([true])
  })

  test('records the IP from cf-connecting-ip, and none when a request has no IP', async () => {
    const email = `ip-${Date.now()}@example.com`
    const signUp = await app.handle(new Request('http://e.ly/api/auth/sign-up/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://e.ly', 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '198.51.100.1' },
      body: JSON.stringify({ email, name: 'IP', password: 'test-password-123' }),
    }))
    expect(signUp.status).toBe(200)
    const withoutIp = await signInAgain(email)
    const listed = await listUserSessions(as(withoutIp))
    expect(listed.map((row) => row.ipAddress).sort()).toEqual(['203.0.113.7', null])
  })

  test('an ended browser session stops at its next request, not minutes later', async () => {
    const email = `browser-${Date.now()}@example.com`
    const signUp = await app.handle(new Request('http://e.ly/api/auth/sign-up/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://e.ly' },
      body: JSON.stringify({ email, name: 'Browser', password: 'test-password-123' }),
    }))
    const cookie = signUp.headers.getSetCookie().map((header) => header.split(';')[0]).join('; ')
    const before = (await me({ cookie })).status
    const other = await signInAgain(email)
    const [browserSession] = (await listUserSessions(as(other))).filter((row) => !row.isCurrent)
    await endUserSession(as(other), browserSession!.id)
    expect({ before, after: (await me({ cookie })).status }).toEqual({ before: 200, after: 401 })
  })
})

describe('formatIp', () => {
  test('writes IPv6 short, and leaves IPv4 and short forms as they are', () => {
    expect([
      '2a01:04f8:0c17:6611:0000:0000:0000:0000',
      '2001:0db8:0000:0000:0001:0000:0000:0001',
      '2001:0db8:0001:0002:0003:0004:0005:0006',
      '2a01:4f8:c17:6611::1',
      '203.0.113.7',
      null,
    ].map(formatIp)).toEqual([
      '2a01:4f8:c17:6611::',
      '2001:db8::1:0:0:1',
      '2001:db8:1:2:3:4:5:6',
      '2a01:4f8:c17:6611::1',
      '203.0.113.7',
      null,
    ])
  })
})

describe('instance', () => {
  test('sends / to the dashboard, serves no docs, and asks search engines not to list it', async () => {
    const fetchPath = async (path: string) => {
      const res = await worker.fetch(new Request(`http://localhost${path}`))
      return { status: res.status, location: res.headers.get('location'), robots: res.headers.get('x-robots-tag') }
    }
    expect({
      root: await fetchPath('/'),
      docs: (await fetchPath('/docs/self-hosting')).status,
      llms: (await fetchPath('/llms.txt')).status,
      login: await fetchPath('/login'),
    }).toEqual({
      root: { status: 302, location: 'http://localhost/dash', robots: 'noindex, nofollow' },
      docs: 404,
      llms: 404,
      login: { status: 200, location: null, robots: 'noindex, nofollow' },
    })
  })
})

describe('log pages', () => {
  test('send someone who can\'t open the project away before naming its environments', async () => {
    const owner = await createTestUser({ name: 'Log Owner' })
    const outsider = await createTestUser({ name: 'Log Outsider' })
    const af = authedFetch(owner.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Log Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Log Project', orgId } })).id
    const open = async (path: string, token?: string) => {
      const res = await app.handle(new Request(`http://e.ly/dash/projects/${projectId}/${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {}, redirect: 'manual' }))
      return new URL(res.headers.get('location') ?? '', 'http://e.ly').pathname
    }
    expect({
      signedOut: await open('history'),
      outsider: await open('history', outsider.token),
    }).toEqual({ signedOut: '/login', outsider: '/dash' })
  })

  test('members are the organization\'s page, not a project\'s', async () => {
    const owner = await createTestUser({ name: 'Members Owner' })
    const outsider = await createTestUser({ name: 'Members Outsider' })
    const orgId = assertOk(await authedFetch(owner.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Members Org' } })).id
    const open = (path: string, token: string) => app.handle(new Request(`http://e.ly${path}`, { headers: { authorization: `Bearer ${token}` }, redirect: 'manual' }))
    const members = await open(`/dash/orgs/${orgId}/members`, owner.token)
    const outsiders = await open(`/dash/orgs/${orgId}/members`, outsider.token)
    expect({ owner: members.status, outsider: new URL(outsiders.headers.get('location') ?? '', 'http://e.ly').pathname })
      .toEqual({ owner: 200, outsider: '/' })
  })
})

describe('instance headers', () => {
  test('no page can be framed or cached, and the API refuses cookie writes from another origin', async () => {
    const user = await createTestUser({ name: 'Header User' })
    const af = authedFetch(user.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Header Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Header Project', orgId } })).id
    const dev = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'dev' } })).id
    // A browser's cookie on the http test host
    const cookie = `better-auth.session_token=${encodeURIComponent(user.token)}`
    const headersOf = async (path: string) => {
      const res = await worker.fetch(new Request(`http://e.ly${path}`, { headers: { cookie } }))
      return [res.headers.get('x-frame-options'), res.headers.get('content-security-policy'), res.headers.get('cache-control'), res.headers.get('strict-transport-security')]
    }
    // What a form on another page sends: the cookie rides along, the body parses as JSON
    const write = (origin: string, name: string) => worker.fetch(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${dev}/secrets`, {
      method: 'POST', headers: { cookie, origin, 'content-type': 'text/plain' }, body: JSON.stringify({ name, value: 'v' }),
    }))
    expect({
      device: await headersOf('/device'),
      secrets: await headersOf(`/api/v0/projects/${projectId}/environments/${dev}/secrets`),
      crossOrigin: (await write('http://evil.e.ly', 'PLANTED')).status,
      sameOrigin: (await write('http://e.ly', 'MINE')).status,
    }).toEqual({
      device: ['DENY', "frame-ancestors 'none'", 'no-store', 'max-age=31536000'],
      secrets: ['DENY', "frame-ancestors 'none'", 'no-store', 'max-age=31536000'],
      crossOrigin: 403,
      sameOrigin: 200,
    })
  })
})

describe('better-auth endpoints', () => {
  test('rate limits are counted per IP in D1', async () => {
    // The app's own rate limits are off in tests: their requests have no IP
    const limited = betterAuth({
      database: drizzleAdapter(getDb(), { provider: 'sqlite' }),
      secret: 'test-secret-at-least-32-characters-long!!',
      baseURL: 'http://e.ly',
      advanced: { ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] } },
      rateLimit: { enabled: true, storage: 'database', customRules: { '/ok': { window: 60, max: 2 } } },
    })
    const ok = (ip: string) => limited.handler(new Request('http://e.ly/api/auth/ok', { headers: { 'cf-connecting-ip': ip } })).then((res) => res.status)
    const statuses = [await ok('203.0.113.50'), await ok('203.0.113.50'), await ok('203.0.113.50'), await ok('203.0.113.51')]
    expect(statuses).toEqual([200, 200, 429, 200])
  })

  test('the ones the app never uses are off, so nobody renames themselves', async () => {
    const user = await createTestUser({ name: 'Real Name' })
    const post = (path: string, body: unknown) => app.handle(new Request(`http://e.ly/api/auth${path}`, {
      method: 'POST', headers: { authorization: `Bearer ${user.token}`, origin: 'http://e.ly', 'content-type': 'application/json' }, body: JSON.stringify(body),
    }))
    const renamed = await post('/update-user', { name: 'The Admin', image: 'https://attacker.example/pixel.png' })
    const listed = await app.handle(new Request('http://e.ly/api/auth/list-sessions', { headers: { authorization: `Bearer ${user.token}` } }))
    const me = await (await app.handle(new Request('http://e.ly/api/v0/me', { headers: { authorization: `Bearer ${user.token}` } }))).json() as { user: { name: string } }
    expect({ renamed: renamed.status, listed: listed.status, name: me.user.name }).toEqual({ renamed: 404, listed: 404, name: 'Real Name' })
  })
})

describe('formatUserCode', () => {
  test('writes a code as XXXX-XXXX however it was typed, also partly typed', () => {
    expect(['abcdefgh', 'ABCD-EFGH', ' bcdf ghjk ', 'BCDFGHJ', 'ABCD-', 'AB', ''].map(formatUserCode)).toEqual([
      'ABCD-EFGH',
      'ABCD-EFGH',
      'BCDF-GHJK',
      'BCDF-GHJ',
      'ABCD',
      'AB',
      '',
    ])
  })
})

describe('describeUserAgent', () => {
  test('names the CLI, a browser and its OS, or else the client itself', () => {
    expect([
      'sigillo-cli/0.14.1',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1',
      'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
      'zig/0.15.2 (std.http)',
      'curl/8.15.0',
      null,
    ].map(describeUserAgent)).toEqual([
      'Sigillo CLI 0.14.1',
      'Edge on Windows',
      'Safari on macOS',
      'Safari on iOS',
      'Chrome on Android',
      'Firefox on Linux',
      'zig/0.15.2',
      'curl/8.15.0',
      'Unknown device',
    ])
  })
})

describe('tamper-evident history', () => {
  let admin: Awaited<ReturnType<typeof createTestUser>>
  let member: Awaited<ReturnType<typeof createTestUser>>
  let projectId: string
  let orgId: string

  beforeAll(async () => {
    admin = await createTestUser({ name: 'Chain Admin' })
    member = await createTestUser({ name: 'Chain Member' })
    const af = authedFetch(admin.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Chain Org' } }))
    orgId = org.id
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Chain Project', orgId } })).id
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
  })

  // A fresh environment per test, so each chain starts at 1
  const newEnv = async () => {
    const slug = `env-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    return assertOk(await authedFetch(admin.token)('/api/v0/projects/:projectId/environments', {
      method: 'POST', params: { projectId }, body: { name: slug, slug },
    })).id
  }
  const setSecret = (token: string, envId: string, name: string, value: string, headers: Record<string, string> = {}) =>
    app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${envId}/secrets`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ name, value }),
    }))
  const get = (token: string, path: string, headers: Record<string, string> = {}) =>
    app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${path}`, { headers: { authorization: `Bearer ${token}`, ...headers } }))
  const verify = async (envId: string) => {
    const res = await get(admin.token, `${envId}/audit`)
    expect(res.status).toBe(200)
    const chains = await res.json() as Awaited<ReturnType<typeof getAuditChains>>
    return {
      events: await verifyChain(chains.publicKey, chains.events.rows),
      reads: await verifyChain(chains.publicKey, chains.reads.rows),
      outside: chains.events.outside,
      chains,
    }
  }
  const eventRow = async (envId: string, seq: number) =>
    (await getDb().query.secretEvent.findFirst({ where: { environmentId: envId, seq } }))!
  const readKinds = async (envId: string) =>
    (await getDb().query.secretRead.findMany({ where: { environmentId: envId }, orderBy: { seq: 'asc' } })).map((row) => row.kind)

  test('every secret change is a signed row of its environment\'s chain, also after its author is deleted', async () => {
    const envId = await newEnv()
    const author = await createTestUser({ name: 'Leaving Author' })
    await getDb().insert(schema.orgMember).values({ orgId, userId: author.user.id, role: 'admin' })
    expect((await setSecret(author.token, envId, 'A', '1')).status).toBe(200)
    const { key } = await insertApiToken({ name: 'chain-writer', projectId, createdBy: admin.user.id })
    assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'PUT', params: { pid: projectId, eid: envId }, body: { secrets: { B: '2', C: '3' } } }))
    assertOk(await authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets/:name', { method: 'DELETE', params: { pid: projectId, eid: envId, name: 'A' } }))
    await getDb().delete(schema.user).where(orm.eq(schema.user.id, author.user.id))
    const result = await verify(envId)
    expect({ events: result.events, rows: result.chains.events.rows.map((row) => row.seq), outside: result.outside })
      .toEqual({ events: { ok: true, head: { seq: 4, hash: result.chains.events.rows[3]!.hash } }, rows: [1, 2, 3, 4], outside: 0 })
    expect(result.chains.publicKey).toBe(await getAuditPublicKey())
  })

  test('an edited row breaks the chain at that row', async () => {
    const envId = await newEnv()
    for (const [name, value] of [['X', '1'], ['X', '2'], ['Y', '3']] as const) await setSecret(admin.token, envId, name, value)
    await getDb().update(schema.secretEvent).set({ name: 'Z' }).where(orm.eq(schema.secretEvent.id, (await eventRow(envId, 2)).id))
    expect((await verify(envId)).events).toEqual({ ok: false, problem: 'row 2 does not match its hash' })
  })

  test('another row\'s ciphertext swapped in breaks the chain', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'old')
    await setSecret(admin.token, envId, 'X', 'new')
    const old = await eventRow(envId, 1)
    // Rolls X back to its old value without the encryption key
    await getDb().update(schema.secretEvent).set({ valueEncrypted: old.valueEncrypted, iv: old.iv }).where(orm.eq(schema.secretEvent.id, (await eventRow(envId, 2)).id))
    expect((await verify(envId)).events).toEqual({ ok: false, problem: 'row 2 does not match its hash' })
  })

  test('a deleted row shows as missing', async () => {
    const envId = await newEnv()
    for (const name of ['X', 'Y', 'Z']) await setSecret(admin.token, envId, name, 'v')
    await getDb().delete(schema.secretEvent).where(orm.eq(schema.secretEvent.id, (await eventRow(envId, 2)).id))
    expect((await verify(envId)).events).toEqual({ ok: false, problem: 'row 2 is missing' })
  })

  test('a forged row fails its signature even with the right hash', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'v')
    const first = await eventRow(envId, 1)
    const encrypted = await encrypt('forged', { environmentId: envId, name: 'X' })
    await getDb().insert(schema.secretEvent).values({
      environmentId: envId, name: 'X', operation: 'set', valueEncrypted: encrypted.encrypted, iv: encrypted.iv,
      userId: admin.user.id, actor: `user:${admin.user.id}`, seq: 2, hash: 'x', signature: first.signature,
    })
    // Whoever forges it can compute the hash, not the signature
    const forged = (await getAuditChains(envId)).events.rows[1]!
    const { chainHash } = await import('./audit.js')
    await getDb().update(schema.secretEvent).set({ hash: await chainHash(first.hash!, forged.preimage) }).where(orm.and(orm.eq(schema.secretEvent.environmentId, envId), orm.eq(schema.secretEvent.seq, 2)))
    expect((await verify(envId)).events).toEqual({ ok: false, problem: 'row 2 has an invalid signature' })
  })

  test('a row added around the chain is counted and ignored', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'real')
    const encrypted = await encrypt('planted', { environmentId: envId, name: 'X' })
    await getDb().insert(schema.secretEvent).values({ environmentId: envId, name: 'X', operation: 'set', valueEncrypted: encrypted.encrypted, iv: encrypted.iv })
    const derived = await deriveSecrets(envId)
    const result = await verify(envId)
    expect({ ok: result.events.ok, outside: result.outside, value: await decrypt(derived[0]!.valueEncrypted, derived[0]!.iv, derived[0]!) })
      .toEqual({ ok: true, outside: 1, value: 'real' })
  })

  test('purging old values removes all but each secret\'s current one, and the history still verifies', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'one')
    await setSecret(admin.token, envId, 'X', 'two')
    await setSecret(admin.token, envId, 'GONE', 'was here')
    await app.handle(new Request(`http://e.ly/api/v0/projects/${projectId}/environments/${envId}/secrets/GONE`, { method: 'DELETE', headers: { authorization: `Bearer ${admin.token}` } }))
    const before = await verify(envId)
    const author = { userId: admin.user.id, apiTokenId: null, sessionId: await sessionIdOf(admin.token) }
    const purged = await purgeOldValues({ environmentId: envId, author })
    const rows = await getDb().query.secretEvent.findMany({ where: { environmentId: envId }, orderBy: { seq: 'asc' } })
    const after = await verify(envId)
    const values = Object.fromEntries(await Promise.all((await deriveSecrets(envId)).map(async (s) => [s.name, await decrypt(s.valueEncrypted, s.iv, s)] as const)))
    expect({
      before: before.events.ok,
      purged,
      rows: rows.map((row) => [row.seq, row.name, row.operation, !!row.valueEncrypted, !!row.valueDigest]),
      after: after.events.ok,
      values,
      again: await purgeOldValues({ environmentId: envId, author }),
    }).toEqual({
      before: true,
      purged: { purged: 2 },
      rows: [
        [1, 'X', 'set', false, true],
        [2, 'X', 'set', true, false],
        [3, 'GONE', 'set', false, true],
        [4, 'GONE', 'delete', false, false],
        [5, 'X', 'purge', false, false],
        [6, 'GONE', 'purge', false, false],
      ],
      after: true,
      values: { X: 'two' },
      again: { purged: 0 },
    })
  })

  test('a purged value put back or cleared by hand breaks the history', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'one')
    await setSecret(admin.token, envId, 'X', 'two')
    // Someone with the database clears a value without purging
    const first = await eventRow(envId, 1)
    await getDb().update(schema.secretEvent).set({ valueEncrypted: null, iv: null }).where(orm.eq(schema.secretEvent.id, first.id))
    const cleared = await verify(envId)
    // or, once it is purged for real, clears the current value and gives it
    // the purged one's digest
    await getDb().update(schema.secretEvent).set({ valueEncrypted: first.valueEncrypted, iv: first.iv }).where(orm.eq(schema.secretEvent.id, first.id))
    await purgeOldValues({ environmentId: envId, author: { userId: admin.user.id, apiTokenId: null, sessionId: null } })
    const second = await eventRow(envId, 2)
    await getDb().update(schema.secretEvent).set({ valueEncrypted: null, iv: null, valueDigest: (await eventRow(envId, 1)).valueDigest }).where(orm.eq(schema.secretEvent.id, second.id))
    expect({ cleared: cleared.events, swapped: (await verify(envId)).events })
      .toEqual({ cleared: { ok: false, problem: 'row 1 does not match its hash' }, swapped: { ok: false, problem: 'row 2 does not match its hash' } })
  })

  test('a value removed by hand with its own digest breaks the history, and the history page says so', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'WEBHOOK_URL', 'https://hooks.example/real')
    await setSecret(admin.token, envId, 'OTHER', 'x')
    // The audit output hands out every set row's digest in its preimage
    const digest = JSON.parse((await verify(envId)).chains.events.rows[0]!.preimage)[6] as string
    // Someone with the database removes the current value as a purge would,
    // but with no purge row
    const first = await eventRow(envId, 1)
    await getDb().update(schema.secretEvent).set({ valueEncrypted: null, iv: null, valueDigest: digest }).where(orm.eq(schema.secretEvent.id, first.id))
    const after = await verify(envId)
    expect({
      events: after.events,
      valueGone: after.chains.events.rows.map((row) => row.valueGone),
      // What the history page shows for its rows
      shown: [...goneValues(await getDb().query.secretEvent.findMany({ where: { environmentId: envId } }))],
    }).toEqual({
      events: { ok: false, problem: 'row 1 lost its value without a purge' },
      valueGone: [true, false],
      shown: [[first.id, 'removed']],
    })
  })

  test('a value emptied or left without its IV by hand counts as removed too', async () => {
    const emptied = await newEnv()
    const withoutIv = await newEnv()
    for (const envId of [emptied, withoutIv]) {
      await setSecret(admin.token, envId, 'A', 'a')
      await setSecret(admin.token, envId, 'B', 'b')
    }
    const digestOf = async (envId: string) => JSON.parse((await verify(envId)).chains.events.rows[0]!.preimage)[6] as string
    const first = { emptied: await eventRow(emptied, 1), withoutIv: await eventRow(withoutIv, 1) }
    // Either way the row takes its digest from value_digest
    await getDb().update(schema.secretEvent).set({ valueEncrypted: '', valueDigest: await digestOf(emptied) }).where(orm.eq(schema.secretEvent.id, first.emptied.id))
    await getDb().update(schema.secretEvent).set({ iv: null, valueDigest: await digestOf(withoutIv) }).where(orm.eq(schema.secretEvent.id, first.withoutIv.id))
    const outcome = async (envId: string) => {
      const result = await verify(envId)
      return {
        events: result.events,
        valueGone: result.chains.events.rows.map((row) => row.valueGone),
        shown: [...goneValues(await getDb().query.secretEvent.findMany({ where: { environmentId: envId } }))],
      }
    }
    expect({ emptied: await outcome(emptied), withoutIv: await outcome(withoutIv) }).toEqual({
      emptied: { events: { ok: false, problem: 'row 1 lost its value without a purge' }, valueGone: [true, false], shown: [[first.emptied.id, 'removed']] },
      withoutIv: { events: { ok: false, problem: 'row 1 lost its value without a purge' }, valueGone: [true, false], shown: [[first.withoutIv.id, 'removed']] },
    })
  })

  test('a purge accounts only for values a later set or delete replaced', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'one')
    await setSecret(admin.token, envId, 'X', 'two')
    await purgeOldValues({ environmentId: envId, author: { userId: admin.user.id, apiTokenId: null, sessionId: null } })
    const purged = await verify(envId)
    // The current value, removed by hand after the purge with its own
    // digest: the purge row follows it, but no set or delete in between
    const current = await eventRow(envId, 2)
    const digest = JSON.parse(purged.chains.events.rows[1]!.preimage)[6] as string
    await getDb().update(schema.secretEvent).set({ valueEncrypted: null, iv: null, valueDigest: digest }).where(orm.eq(schema.secretEvent.id, current.id))
    const after = await verify(envId)
    const first = await eventRow(envId, 1)
    expect({
      purged: purged.events.ok,
      purgedGone: purged.chains.events.rows.map((row) => row.valueGone),
      after: after.events,
      afterGone: after.chains.events.rows.map((row) => row.valueGone),
      shown: Object.fromEntries(goneValues(await getDb().query.secretEvent.findMany({ where: { environmentId: envId } }))),
    }).toEqual({
      purged: true,
      purgedGone: [true, false, false],
      after: { ok: false, problem: 'row 2 lost its value without a purge' },
      afterGone: [true, true, false],
      shown: { [first.id]: 'purged', [current.id]: 'removed' },
    })
  })

  test('a purge removes nothing when a value was re-encrypted after it read them, and all of them once it reads again', async () => {
    const envId = await newEnv()
    for (const [name, value] of [['X', 'one'], ['X', 'two'], ['Y', 'old'], ['Y', 'new']] as const) await setSecret(admin.token, envId, name, value)
    const author = { userId: admin.user.id, apiTokenId: null, sessionId: null }
    const rows = async () => (await getDb().query.secretEvent.findMany({ where: { environmentId: envId }, orderBy: { seq: 'asc' } }))
      .map((row) => [row.seq, row.name, row.operation, !!row.valueEncrypted])
    const logged = async () => (await getDb().query.securityEvent.findMany({ where: { subjectId: envId, kind: 'values.purged' } })).map((event) => event.details)
    const old = await readOldValues(envId)
    // A key rotation re-encrypts X's old value in between
    const first = await eventRow(envId, 1)
    const rotated = await encrypt('one', { environmentId: envId, name: 'X' })
    await getDb().update(schema.secretEvent).set({ valueEncrypted: rotated.encrypted, iv: rotated.iv }).where(orm.eq(schema.secretEvent.id, first.id))
    const refused = await removeOldValues({ environmentId: envId, old, author }).then(() => 'ok', (error: Error) => error.message)
    const afterRefusal = { rows: await rows(), logged: await logged() }
    const purged = await purgeOldValues({ environmentId: envId, author })
    expect({ refused, afterRefusal, purged, rows: await rows(), logged: await logged(), verified: (await verify(envId)).events.ok }).toEqual({
      refused: 'Old values changed while purging them, so nothing was purged: try again',
      afterRefusal: {
        rows: [[1, 'X', 'set', true], [2, 'X', 'set', true], [3, 'Y', 'set', true], [4, 'Y', 'set', true]],
        logged: [],
      },
      purged: { purged: 2 },
      rows: [
        [1, 'X', 'set', false], [2, 'X', 'set', true], [3, 'Y', 'set', false], [4, 'Y', 'set', true],
        [5, 'X', 'purge', false], [6, 'Y', 'purge', false],
      ],
      logged: [{ values: 2, names: 2 }],
      verified: true,
    })
  })

  test('only an org admin purges, with their passkey even where nothing is protected', async () => {
    const envId = await newEnv()
    const outcome = (user: typeof admin, sessionId: Promise<string>) => sessionId.then((id) => requireOldValuesPurge({ userId: user.user.id, sessionId: id, environmentId: envId }))
      .then(() => 'ok', (error) => error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message)
    const auth = await getTestAuth()
    const signIn = await auth.api.signInEmail({ body: { email: admin.user.email, password: 'test-password-123' } })
    const login = `${signIn.token}.${await makeSignature(signIn.token, (await auth.$context).secret)}`
    const byMember = await outcome(member, sessionIdOf(member.token))
    const withoutPasskey = await outcome(admin, sessionIdOf(login))
    await grantAdmin(login)
    expect({ byMember, withoutPasskey, approved: await outcome(admin, sessionIdOf(login)) })
      .toEqual({ byMember: 'Only admins can do this', withoutPasskey: 'step-up:admin', approved: 'ok' })
  })

  test('rows from before the chain join it in their order', async () => {
    const envId = await newEnv()
    const values = await Promise.all(['1', '2'].map((value) => encrypt(value, { environmentId: envId, name: 'OLD' })))
    await getDb().insert(schema.secretEvent).values(values.map((value, i) => ({
      environmentId: envId, name: 'OLD', operation: 'set' as const, valueEncrypted: value.encrypted, iv: value.iv, createdAt: 1000 + i,
    })))
    await setSecret(admin.token, envId, 'NEW', '3')
    const result = await verify(envId)
    const derived = await deriveSecrets(envId)
    expect({
      events: result.events.ok, rows: result.chains.events.rows.length, outside: result.outside, adopted: result.chains.events.adopted,
      old: await decrypt(derived.find((d) => d.name === 'OLD')!.valueEncrypted, derived.find((d) => d.name === 'OLD')!.iv, derived.find((d) => d.name === 'OLD')!),
    }).toEqual({ events: true, rows: 3, outside: 0, adopted: 2, old: '2' })
  })

  test('a chain taken apart in the database and adopted again no longer matches the head verify saved', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'WEBHOOK_URL', 'https://hooks.example/real')
    const before = await verify(envId)
    if (!before.events.ok || !before.events.head) throw new Error('expected an intact chain')
    const witness = before.events.head
    // Someone with the database drops every seq, and adds a row in the admin's name
    const planted = await encrypt('https://attacker.example/hook', { environmentId: envId, name: 'WEBHOOK_URL' })
    await getDb().update(schema.secretEvent).set({ seq: null }).where(orm.eq(schema.secretEvent.environmentId, envId))
    await getDb().insert(schema.secretEvent).values({
      environmentId: envId, name: 'WEBHOOK_URL', operation: 'set', valueEncrypted: planted.encrypted, iv: planted.iv, userId: admin.user.id, createdAt: Date.now() + 1000,
    })
    const after = await verify(envId)
    const rows = after.chains.events.rows
    // What `sigillo audit verify` compares with the head it saved
    const witnessHolds = rows.length >= witness.seq && rows[witness.seq - 1]!.hash === witness.hash
    expect({ witnessHolds, adopted: after.chains.events.adopted }).toEqual({ witnessHolds: false, adopted: 2 })
  })

  test('racing writes take turns instead of forking the chain', async () => {
    const envId = await newEnv()
    const statuses = await Promise.all(Array.from({ length: 12 }, (_, i) => setSecret(admin.token, envId, `RACE_${i}`, String(i)).then((res) => res.status)))
    const result = await verify(envId)
    expect({ statuses: [...new Set(statuses)], ok: result.events.ok, rows: result.chains.events.rows.map((row) => row.seq) })
      .toEqual({ statuses: [200], ok: true, rows: Array.from({ length: 12 }, (_, i) => i + 1) })
  })

  test('reads of an unprotected environment are not recorded', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'v')
    expect((await get(admin.token, `${envId}/secrets/X`)).status).toBe(200)
    expect(await readKinds(envId)).toEqual([])
  })

  test('each read of a protected environment is recorded, with who, what and the IP', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'v')
    await setSecret(admin.token, envId, 'Y', 'w')
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const { key, tokenId } = await insertApiToken({ name: 'reader', projectId, createdBy: admin.user.id, protectedAccess: true })
    await grantRead(admin.token, [envId])
    const ip = { 'cf-connecting-ip': '203.0.113.9' }
    expect((await get(key, `${envId}/secrets/X`, ip)).status).toBe(200)
    expect((await get(key, `${envId}/secrets/download?format=json`, ip)).status).toBe(200)
    expect((await get(admin.token, `${envId}/secrets`)).status).toBe(200)
    const rows = await getDb().query.secretRead.findMany({ where: { environmentId: envId }, orderBy: { seq: 'asc' } })
    expect(rows.map(({ kind, names, actor, ipAddress }) => ({ kind, names, actor, ipAddress }))).toEqual([
      { kind: 'protected', names: [], actor: `user:${admin.user.id}`, ipAddress: null },
      { kind: 'value', names: ['X'], actor: `token:${tokenId}`, ipAddress: '203.0.113.9' },
      { kind: 'download', names: ['X', 'Y'], actor: `token:${tokenId}`, ipAddress: '203.0.113.9' },
      { kind: 'list', names: ['X', 'Y'], actor: `user:${admin.user.id}`, ipAddress: null },
    ])
    expect((await verify(envId)).reads).toEqual({ ok: true, head: { seq: 4, hash: rows[3]!.hash } })
  })

  test('a read that can\'t be recorded fails instead of returning values', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'do-not-leak')
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    await grantRead(admin.token, [envId])
    await getDb().run(orm.sql.raw(`CREATE TRIGGER refuse_reads BEFORE INSERT ON secret_read BEGIN SELECT RAISE(ABORT, 'read log unavailable'); END`))
    try {
      const res = await get(admin.token, `${envId}/secrets/X`)
      expect({ status: res.status, leaked: (await res.text()).includes('do-not-leak') }).toEqual({ status: 500, leaked: false })
    } finally {
      await getDb().run(orm.sql.raw('DROP TRIGGER refuse_reads'))
    }
  })

  test('turning protection off is recorded, and reads after it are not', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'v')
    const author = { userId: admin.user.id, apiTokenId: null, sessionId: await sessionIdOf(admin.token) }
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: true, author })
    await grantRead(admin.token, [envId])
    await get(admin.token, `${envId}/secrets/X`)
    await grantAdmin(admin.token)
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: false, author })
    await get(admin.token, `${envId}/secrets/X`)
    expect(await readKinds(envId)).toEqual(['protected', 'value', 'unprotected'])
  })

  test('the web UI gets a value when it is revealed, and only that is recorded', async () => {
    const envId = await newEnv()
    for (const [name, value] of [['X', 'x1'], ['X', 'x2'], ['Y', 'y']] as const) await setSecret(admin.token, envId, name, value)
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const request = new Request('http://e.ly', { headers: { 'cf-connecting-ip': '203.0.113.5' } })
    const sessionId = await sessionIdOf(admin.token)
    await grantRead(admin.token, [envId])
    const revealed = await readSecretValues({ request, userId: admin.user.id, sessionId, environmentId: envId, names: ['X'], kind: 'value' })
    const downloaded = await readSecretValues({ request, userId: admin.user.id, sessionId, environmentId: envId, names: null, kind: 'download' })
    const old = await readEventValue({ request, userId: admin.user.id, sessionId, eventId: (await eventRow(envId, 1)).id })
    const rows = await getDb().query.secretRead.findMany({ where: { environmentId: envId }, orderBy: { seq: 'asc' } })
    expect({ revealed, downloaded, old, reads: rows.map(({ kind, names, ipAddress }) => ({ kind, names, ipAddress })) }).toEqual({
      revealed: { X: 'x2' },
      downloaded: { X: 'x2', Y: 'y' },
      old: 'x1',
      reads: [
        { kind: 'protected', names: [], ipAddress: null },
        { kind: 'value', names: ['X'], ipAddress: '203.0.113.5' },
        { kind: 'download', names: ['X', 'Y'], ipAddress: '203.0.113.5' },
        { kind: 'event-log', names: ['X'], ipAddress: '203.0.113.5' },
      ],
    })
  })

  test('revealing needs the same access as the environment, and records nothing when refused', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'admins-only')
    await getDb().update(schema.environment).set({ accessRole: 'admin' }).where(orm.eq(schema.environment.id, envId))
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: envId, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const request = new Request('http://e.ly')
    const sessionId = await sessionIdOf(member.token)
    const value = await readSecretValues({ request, userId: member.user.id, sessionId, environmentId: envId, names: null, kind: 'value' }).catch((error: Error) => error.message)
    const old = await readEventValue({ request, userId: member.user.id, sessionId, eventId: (await eventRow(envId, 1)).id }).catch((error: Error) => error.message)
    expect({ value, old, reads: await readKinds(envId) }).toEqual({
      value: 'admin access required for this environment', old: 'admin access required for this environment', reads: ['protected'],
    })
  })

  test('only org admins with a login get the audit chains', async () => {
    const envId = await newEnv()
    const { key } = await insertApiToken({ name: 'auditor', projectId, createdBy: admin.user.id })
    expect({
      member: (await get(member.token, `${envId}/audit`)).status,
      token: (await get(key, `${envId}/audit`)).status,
      admin: (await get(admin.token, `${envId}/audit`)).status,
    }).toEqual({ member: 403, token: 403, admin: 200 })
  })
  test('a value starting with a byte order mark keeps it, and keeps its history intact', async () => {
    const envId = await newEnv()
    expect((await setSecret(admin.token, envId, 'CERT', '\uFEFF-----BEGIN CERTIFICATE-----')).status).toBe(200)
    const { value } = await (await get(admin.token, `${envId}/secrets/CERT`)).json() as { value: string }
    expect({ value, intact: (await verify(envId)).events.ok }).toEqual({ value: '\uFEFF-----BEGIN CERTIFICATE-----', intact: true })
  })

  test('text that isn\'t valid is refused, so it can\'t break the history', async () => {
    const envId = await newEnv()
    const res = await setSecret(admin.token, envId, 'X', 'a\uD800b')
    expect({ status: res.status, body: await res.json() }).toEqual({ status: 400, body: { error: 'Secret names and values must be valid text' } })
  })

  test('the pages name a change\'s author as its chain row does', async () => {
    const envId = await newEnv()
    await setSecret(admin.token, envId, 'X', 'v')
    // Someone with the database pins the change on a member
    await getDb().update(schema.secretEvent).set({ userId: member.user.id }).where(orm.eq(schema.secretEvent.environmentId, envId))
    const [secret] = await deriveSecrets(envId)
    expect({ intact: (await verify(envId)).events.ok, author: secret!.actor }).toEqual({ intact: true, author: `user:${admin.user.id}` })
  })

})

describe('remembered environment', () => {
  let token: string
  let projectId: string
  beforeAll(async () => {
    const user = await createTestUser({ name: 'Env Rememberer' })
    token = user.token
    const af = authedFetch(token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Env Org' } }))
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Env Project', orgId: org.id } })).id
  })
  const get = (path: string, cookie = '') => app.handle(new Request(`http://e.ly${path}`, {
    headers: { authorization: `Bearer ${token}`, ...(cookie ? { cookie } : {}) },
    redirect: 'manual',
  }))

  test('the tabs without an environment go back to the one last opened, while it exists', async () => {
    const where = async (path: string, cookie?: string) => new URL((await get(path, cookie)).headers.get('location') ?? '', 'http://e.ly').pathname
    expect({
      none: await where(`/dash/projects/${projectId}/history`),
      remembered: await where(`/dash/projects/${projectId}/history`, `sigillo-env-${projectId}=prod`),
      deleted: await where(`/dash/projects/${projectId}/history`, `sigillo-env-${projectId}=gone`),
      otherProject: await where(`/dash/projects/${projectId}/history`, `sigillo-env-other=prod`),
    }).toEqual({
      none: `/dash/projects/${projectId}/envs/dev/history`,
      remembered: `/dash/projects/${projectId}/envs/prod/history`,
      deleted: `/dash/projects/${projectId}/envs/dev/history`,
      otherProject: `/dash/projects/${projectId}/envs/dev/history`,
    })
  })

  test('the dashboard goes to the one last opened too', async () => {
    let path = '/dash'
    for (let hop = 0; hop < 3 && !path.includes('/envs/'); hop++) {
      path = new URL((await get(path, `sigillo-env-${projectId}=prod`)).headers.get('location') ?? '', 'http://e.ly').pathname
    }
    expect(path).toBe(`/dash/projects/${projectId}/envs/prod`)
  })

  test('opening an environment page remembers it', async () => {
    const opened = async (path: string) => {
      const res = await get(path)
      return { status: res.status, cookie: res.headers.getSetCookie().find((c) => c.startsWith('sigillo-env-')) }
    }
    const remembered = (slug: string) => ({ status: 200, cookie: `sigillo-env-${projectId}=${slug}; Path=/dash; Max-Age=31536000; SameSite=Lax; HttpOnly` })
    expect({
      changes: await opened(`/dash/projects/${projectId}/envs/preview/history`),
      reads: await opened(`/dash/projects/${projectId}/envs/prod/history/reads`),
    }).toEqual({ changes: remembered('preview'), reads: remembered('prod') })
  })
})

describe('passkeys', () => {
  const origin = 'http://e.ly'
  const rpID = 'e.ly'
  const call = (path: string, token: string, init: { body?: unknown; cookie?: string } = {}) => app.handle(new Request(`${origin}${path}`, {
    method: init.body === undefined ? 'GET' : 'POST',
    headers: {
      authorization: `Bearer ${token}`, origin, 'content-type': 'application/json',
      ...(init.cookie ? { cookie: init.cookie } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  }))
  // Adds a passkey through better-auth's plugin, like the settings page will
  const addPasskey = async (token: string) => {
    const authenticator = await createSoftAuthenticator({ rpID, origin })
    const optionsRes = await call('/api/auth/passkey/generate-register-options', token)
    const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    const options = await optionsRes.json() as { challenge: string }
    const res = await call('/api/auth/passkey/verify-registration', token, { body: { response: await authenticator.register(options), name: 'Test key' }, cookie })
    return { authenticator, status: res.status }
  }

  test('a passkey is added through the plugin, and cannot sign anyone in', async () => {
    const { user, token } = await createTestUser()
    const { status } = await addPasskey(token)
    const rows = await getDb().query.passkey.findMany({ where: { userId: user.id } })
    expect({
      status,
      rows: rows.map(({ name, deviceType }) => ({ name, deviceType })),
      signInOptions: (await call('/api/auth/passkey/generate-authenticate-options', token)).status,
      signIn: (await call('/api/auth/passkey/verify-authentication', token, { body: {} })).status,
    }).toEqual({ status: 200, rows: [{ name: 'Test key', deviceType: 'singleDevice' }], signInOptions: 404, signIn: 404 })
  })

  test('an approval needs a user-verified signature of the challenge by one of your own passkeys', async () => {
    const alice = await createTestUser()
    const bob = await createTestUser()
    const { authenticator } = await addPasskey(alice.token)
    await addPasskey(bob.token)
    const verify = async (userId: string, sign: (options: { challenge: string }) => Promise<AuthenticationResponseJSON>) => {
      const options = await passkeyChallenge({ userId, rpID })
      return verifyPasskey({ userId, response: await sign(options), expectedChallenge: options.challenge, origin, rpID })
    }
    const before = (await getDb().query.passkey.findFirst({ where: { userId: alice.user.id } }))!.counter
    expect({
      verified: await verify(alice.user.id, (o) => authenticator.authenticate(o)),
      counterAdvanced: (await getDb().query.passkey.findFirst({ where: { userId: alice.user.id } }))!.counter > before,
      withoutUserVerification: await verify(alice.user.id, (o) => authenticator.authenticate(o, { userVerified: false })),
      otherChallenge: await verify(alice.user.id, () => authenticator.authenticate({ challenge: 'c29tZXRoaW5nIGVsc2U' })),
      otherOrigin: await verify(alice.user.id, (o) => authenticator.authenticate(o, { origin: 'https://evil.example' })),
      someoneElsesUser: await verify(bob.user.id, (o) => authenticator.authenticate(o)),
    }).toEqual({ verified: true, counterAdvanced: true, withoutUserVerification: false, otherChallenge: false, otherOrigin: false, someoneElsesUser: false })
  })
})

describe('step-up', () => {
  const origin = 'http://e.ly'
  let admin: Awaited<ReturnType<typeof createTestUser>>
  let projectId: string
  let protectedEnv: string
  let otherEnv: string

  beforeAll(async () => {
    admin = await createTestUser({ name: 'Step-up Admin' })
    const af = authedFetch(admin.token)
    const org = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Step-up Org' } }))
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Step-up Project', orgId: org.id } })).id
    const envs = assertOk(await af('/api/v0/projects/:projectId/environments', { params: { projectId } })).environments
    protectedEnv = envs.find((e) => e.slug === 'prod')!.id
    otherEnv = envs.find((e) => e.slug === 'preview')!.id
    for (const envId of [protectedEnv, otherEnv]) {
      assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'PUT', params: { pid: projectId, eid: envId }, body: { secrets: { KEY: 'v' } } }))
      await setEnvironmentProtection({ request: new Request(origin), environmentId: envId, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    }
  })

  const call = (token: string, path: string, init: { method?: string; body?: unknown } = {}) => app.handle(new Request(`${origin}${path}`, {
    method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
    headers: { authorization: `Bearer ${token}`, origin, 'content-type': 'application/json' },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  }))
  // Every API route that returns values or what they look like
  const reads = (envId: string) => [
    `/api/v0/projects/${projectId}/environments/${envId}/secrets`,
    `/api/v0/projects/${projectId}/environments/${envId}/secrets/KEY`,
    `/api/v0/projects/${projectId}/environments/${envId}/secrets/download?format=json`,
  ]
  const statuses = async (token: string, envId: string) => Promise.all(reads(envId).map(async (path) => (await call(token, path)).status))
  // A second login of the same user, like another machine
  const secondSession = async () => {
    const auth = await getTestAuth()
    const res = await auth.api.signInEmail({ body: { email: admin.user.email, password: 'test-password-123' } })
    return `${res.token}.${await makeSignature(res.token, (await auth.$context).secret)}`
  }

  test('a session reads a protected environment only with a live grant for it', async () => {
    const user = await createTestUser()
    await getDb().insert(schema.orgMember).values({ orgId: (await getDb().query.project.findFirst({ where: { id: projectId } }))!.orgId, userId: user.user.id, role: 'admin' })
    const without = await call(user.token, reads(protectedEnv)[1]!)
    const denied = { status: without.status, body: await without.json() }
    const none = await statuses(user.token, protectedEnv)
    await grantRead(user.token, [otherEnv])
    const wrongEnv = await statuses(user.token, protectedEnv)
    await grantRead(user.token, [protectedEnv], Date.now() - 1)
    const expired = await statuses(user.token, protectedEnv)
    await grantRead(user.token, [protectedEnv])
    const granted = await statuses(user.token, protectedEnv)
    expect({ denied, none, wrongEnv, expired, granted }).toEqual({
      denied: { status: 403, body: { error: 'this environment is protected: approve with your passkey', code: 'STEP_UP_REQUIRED', purpose: 'access', environmentIds: [protectedEnv] } },
      none: [403, 403, 403], wrongEnv: [403, 403, 403], expired: [403, 403, 403], granted: [200, 200, 200],
    })
  })

  test('a grant belongs to the session that asked, not to other logins of the same user', async () => {
    const other = await secondSession()
    await grantRead(other, [protectedEnv])
    const mine = await secondSession()
    expect({ other: await statuses(other, protectedEnv), mine: await statuses(mine, protectedEnv) }).toEqual({ other: [200, 200, 200], mine: [403, 403, 403] })
  })

  test('only a machine token reads a protected environment, and unprotected ones need nothing', async () => {
    const plain = await insertApiToken({ name: 'plain', projectId, createdBy: admin.user.id })
    const machine = await insertApiToken({ name: 'machine', projectId, createdBy: admin.user.id, protectedAccess: true })
    const dev = assertOk(await authedFetch(admin.token)('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'dev' } })).id
    assertOk(await authedFetch(admin.token)('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'PUT', params: { pid: projectId, eid: dev }, body: { secrets: { KEY: 'v' } } }))
    const plainRes = await call(plain.key, reads(protectedEnv)[1]!)
    expect({
      plain: await statuses(plain.key, protectedEnv),
      plainBody: (await plainRes.json() as { code: string }).code,
      machine: await statuses(machine.key, protectedEnv),
      unprotected: await statuses(plain.key, dev),
    }).toEqual({ plain: [403, 403, 403], plainBody: 'MACHINE_TOKEN_REQUIRED', machine: [200, 200, 200], unprotected: [200, 200, 200] })
  })

  test('the web reads go through the same gate', async () => {
    const session = await secondSession()
    const sessionId = await sessionIdOf(session)
    const request = new Request(origin)
    const eventId = (await getDb().query.secretEvent.findFirst({ where: { environmentId: protectedEnv } }))!.id
    const attempt = (read: () => Promise<unknown>) => read().then(() => 'read', (e) => e instanceof StepUpRequiredError ? 'step-up' : String(e))
    const before = {
      value: await attempt(() => readSecretValues({ request, userId: admin.user.id, sessionId, environmentId: protectedEnv, names: null, kind: 'value' })),
      event: await attempt(() => readEventValue({ request, userId: admin.user.id, sessionId, eventId })),
    }
    await grantRead(session, [protectedEnv])
    const after = {
      value: await attempt(() => readSecretValues({ request, userId: admin.user.id, sessionId, environmentId: protectedEnv, names: null, kind: 'value' })),
      event: await attempt(() => readEventValue({ request, userId: admin.user.id, sessionId, eventId })),
    }
    expect({ before, after }).toEqual({ before: { value: 'step-up', event: 'step-up' }, after: { value: 'read', event: 'read' } })
  })

  test('the CLI asks, its user approves on /approve with a passkey, and then the CLI reads', async () => {
    const cli = await secondSession()
    const authenticator = await createSoftAuthenticator({ rpID: 'e.ly', origin })
    // The browser session, fresh enough for a first passkey
    const optionsRes = await call(admin.token, '/api/auth/passkey/generate-register-options')
    const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    const regOptions = await optionsRes.json() as { challenge: string }
    const added = await app.handle(new Request(`${origin}/api/auth/passkey/verify-registration`, {
      method: 'POST',
      headers: { authorization: `Bearer ${admin.token}`, origin, 'content-type': 'application/json', cookie },
      body: JSON.stringify({ response: await authenticator.register(regOptions), name: 'Laptop' }),
    }))
    expect(added.status).toBe(200)

    const asked = await call(cli, '/api/v0/step-up', { body: { environmentIds: [protectedEnv] } })
    const request = await asked.json() as { id: string; userCode: string; approveUrl: string }
    const statusOf = async (token: string) => { const res = await call(token, `/api/v0/step-up/${request.id}`); return res.status === 200 ? (await res.json() as { status: string }).status : res.status }
    const stranger = await createTestUser()
    const beforeApproval = { status: await statusOf(cli), read: (await call(cli, reads(protectedEnv)[1]!)).status }
    // Typed without the dash and in lowercase
    const found = await findStepUpRequest({ userId: admin.user.id, userCode: request.userCode.replace('-', '').toLowerCase() })
    const options = await approvalOptions({ request: new Request(origin), requestId: request.id, userId: admin.user.id })
    const approved = await approveStepUpRequest({ request: new Request(origin), requestId: request.id, userId: admin.user.id, response: await authenticator.authenticate(options) })
    expect({
      asked: asked.status,
      approveUrl: request.approveUrl,
      codeInLink: request.approveUrl.includes(request.userCode),
      beforeApproval,
      strangerFinds: await findStepUpRequest({ userId: stranger.user.id, userCode: request.userCode }),
      found: found && { environments: found.environments.map((e) => e.name) },
      approved,
      afterApproval: { status: await statusOf(cli), read: (await call(cli, reads(protectedEnv)[1]!)).status },
      browserStillNeedsItsOwn: (await call(admin.token, reads(protectedEnv)[1]!)).status,
      othersCannotPoll: await statusOf(admin.token),
      approvedTwice: await approveStepUpRequest({ request: new Request(origin), requestId: request.id, userId: admin.user.id, response: await authenticator.authenticate(options) }),
    }).toEqual({
      asked: 200,
      approveUrl: 'http://e.ly/approve',
      codeInLink: false,
      beforeApproval: { status: 'pending', read: 403 },
      strangerFinds: null,
      found: { environments: ['Prod'] },
      approved: true,
      afterApproval: { status: 'approved', read: 200 },
      browserStillNeedsItsOwn: 403,
      othersCannotPoll: 404,
      approvedTwice: false,
    })
  })

  test('only an admin makes a machine token, for 90 days at most, with an admin approval', async () => {
    // A login without grants from the other tests
    const login = await secondSession()
    const sessionId = await sessionIdOf(login)
    const member = await createTestUser({ name: 'Step-up Member' })
    const { orgId } = (await getDb().query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } }))!
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const outcome = async (args: Partial<Parameters<typeof requireMachineTokenApproval>[0]>) => {
      try {
        await requireMachineTokenApproval({ userId: admin.user.id, sessionId, projectId, expiresInDays: 90, ...args })
        return 'ok'
      } catch (error) {
        return error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message
      }
    }
    const before = {
      member: await outcome({ userId: member.user.id, sessionId: await sessionIdOf(member.token) }),
      year: await outcome({ expiresInDays: 365 }),
      withoutApproval: await outcome({}),
    }
    await grantRead(login, [protectedEnv, otherEnv])
    const accessOnly = await outcome({})
    await grantAdmin(login)
    expect({ ...before, accessOnly, approved: await outcome({}) }).toEqual({
      member: 'Only admins can do this',
      year: 'A machine token expires after 90 days at most',
      withoutApproval: 'step-up:admin',
      accessOnly: 'step-up:admin',
      approved: 'ok',
    })
  })

  test('making a machine token takes a passkey before the organization protects anything too', async () => {
    // A stolen admin session could otherwise leave one behind for later
    const owner = await createTestUser({ name: 'Unprotected Admin' })
    const orgId = assertOk(await authedFetch(owner.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Unprotected Org' } })).id
    const unprotectedProject = assertOk(await authedFetch(owner.token)('/api/v0/projects', { method: 'POST', body: { name: 'Unprotected', orgId } })).id
    const sessionId = await sessionIdOf(owner.token)
    const outcomeOf = (run: () => Promise<unknown>) => run().then(() => 'ok', (error) => error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message)
    const attempt = () => outcomeOf(() => requireMachineTokenApproval({ userId: owner.user.id, sessionId, projectId: unprotectedProject, expiresInDays: 90 }))
    const without = await attempt()
    const deleting = await outcomeOf(() => requireMachineTokenDeletion({ userId: owner.user.id, sessionId, projectId: unprotectedProject }))
    await grantAdmin(owner.token)
    expect({ without, deleting, approved: await attempt() }).toEqual({ without: 'step-up:admin', deleting: 'ok', approved: 'ok' })
  })

  test('a machine token stops working on protected environments when its creator is no longer an admin', async () => {
    const creator = await createTestUser({ name: 'Token Creator' })
    const { orgId } = (await getDb().query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } }))!
    const [membership] = await getDb().insert(schema.orgMember).values({ orgId, userId: creator.user.id, role: 'admin' }).returning({ id: schema.orgMember.id })
    const machine = await insertApiToken({ name: 'demoted', projectId, createdBy: creator.user.id, protectedAccess: true })
    const asAdmin = await statuses(machine.key, protectedEnv)
    await getDb().update(schema.orgMember).set({ role: 'member' }).where(orm.eq(schema.orgMember.id, membership!.id))
    const refused = await call(machine.key, reads(protectedEnv)[1]!)
    expect({ asAdmin, demoted: await statuses(machine.key, protectedEnv), code: (await refused.json() as { code: string }).code })
      .toEqual({ asAdmin: [200, 200, 200], demoted: [403, 403, 403], code: 'MACHINE_TOKEN_REQUIRED' })
  })

  test('turning protection off takes an admin approval, turning it on does not', async () => {
    const token = await secondSession()
    const author = { userId: admin.user.id, apiTokenId: null, sessionId: await sessionIdOf(token) }
    const slug = `unprotect-${Date.now()}`
    const envId = assertOk(await authedFetch(admin.token)('/api/v0/projects/:projectId/environments', { method: 'POST', params: { projectId }, body: { name: slug, slug } })).id
    const toggle = async (protect: boolean) => {
      try {
        await setEnvironmentProtection({ request: new Request(origin), environmentId: envId, protect, author })
        return 'ok'
      } catch (error) {
        return error instanceof StepUpRequiredError ? 'step-up' : (error as Error).message
      }
    }
    const isProtected = async () => (await getDb().query.environment.findFirst({ where: { id: envId }, columns: { protected: true } }))!.protected
    const on = await toggle(true)
    const offWithoutApproval = await toggle(false)
    await grantRead(token, [envId])
    const offWithAccessOnly = await toggle(false)
    const stillProtected = await isProtected()
    await grantAdmin(token)
    const offWithApproval = await toggle(false)
    expect({ on, offWithoutApproval, offWithAccessOnly, stillProtected, offWithApproval, nowProtected: await isProtected() })
      .toEqual({ on: 'ok', offWithoutApproval: 'step-up', offWithAccessOnly: 'step-up', stillProtected: true, offWithApproval: 'ok', nowProtected: false })
  })

  test('API tokens cannot ask for an approval', async () => {
    const machine = await insertApiToken({ name: 'asker', projectId, createdBy: admin.user.id, protectedAccess: true })
    expect((await call(machine.key, '/api/v0/step-up', { body: { environmentIds: [protectedEnv] } })).status).toBe(403)
  })

  test('a first passkey needs a fresh sign-in, and another one an approval with the first', async () => {
    const user = await createTestUser()
    const authenticator = await createSoftAuthenticator({ rpID: 'e.ly', origin })
    const add = async () => {
      const optionsRes = await call(user.token, '/api/auth/passkey/generate-register-options')
      const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
      const second = await createSoftAuthenticator({ rpID: 'e.ly', origin })
      const res = await app.handle(new Request(`${origin}/api/auth/passkey/verify-registration`, {
        method: 'POST',
        headers: { authorization: `Bearer ${user.token}`, origin, 'content-type': 'application/json', cookie },
        body: JSON.stringify({ response: await (authenticator.credentialId && (await getDb().query.passkey.findFirst({ where: { userId: user.user.id } })) ? second : authenticator).register(await optionsRes.json() as { challenge: string }) }),
      }))
      return res.status
    }
    const sessionId = await sessionIdOf(user.token)
    await getDb().update(schema.session).set({ createdAt: Date.now() - 10 * 60 * 1000 }).where(orm.eq(schema.session.id, sessionId))
    const staleFirst = await add()
    await getDb().update(schema.session).set({ createdAt: Date.now() }).where(orm.eq(schema.session.id, sessionId))
    const freshFirst = await add()
    const secondWithout = await add()
    const request = await createStepUpRequest({ request: new Request(origin), userId: user.user.id, sessionId, environmentIds: [], withCode: false, purpose: 'admin' })
    const options = await approvalOptions({ request: new Request(origin), requestId: request.id, userId: user.user.id })
    await approveStepUpRequest({ request: new Request(origin), requestId: request.id, userId: user.user.id, response: await authenticator.authenticate(options) })
    const secondApproved = await add()
    const events = await getDb().query.passkeyEvent.findMany({ where: { userId: user.user.id } })
    expect({ staleFirst, freshFirst, secondWithout, secondApproved, logged: events.map((e) => e.action) })
      .toEqual({ staleFirst: 403, freshFirst: 200, secondWithout: 403, secondApproved: 200, logged: ['added', 'added'] })
  })

  test('values are only decrypted where the gate has run: a new call site fails here', () => {
    const sources = import.meta.glob(['./**/*.ts', './**/*.tsx', '!./**/*.test.ts', '!./soft-authenticator.ts'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>
    const calls: Record<string, number> = {}
    for (const [file, source] of Object.entries(sources)) {
      const code = source.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n')
      const count = code.match(/(?<!function |[\w.])decrypt\(/g)?.length ?? 0
      if (count) calls[file] = count
    }
    // Each one follows recordSecretRead, or keeps the value on the server:
    // the audit digest, and a rename within one environment
    expect(calls).toEqual({ './actions.ts': 2, './api.ts': 4, './audit.ts': 3 })
  })
})

describe('protected writes and admin actions', () => {
  const origin = 'http://e.ly'
  let admin: Awaited<ReturnType<typeof createTestUser>>
  let orgId: string
  let projectId: string
  let prod: string
  let dev: string

  beforeAll(async () => {
    admin = await createTestUser({ name: 'Writes Admin' })
    const af = authedFetch(admin.token)
    orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Writes Org' } })).id
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Writes Project', orgId } })).id
    const envs = assertOk(await af('/api/v0/projects/:projectId/environments', { params: { projectId } })).environments
    prod = envs.find((e) => e.slug === 'prod')!.id
    dev = envs.find((e) => e.slug === 'dev')!.id
    for (const envId of [prod, dev]) {
      assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'PUT', params: { pid: projectId, eid: envId }, body: { secrets: { KEY: 'original' } } }))
    }
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
  })

  const call = (token: string, path: string, method: string, body?: unknown) => app.handle(new Request(`${origin}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, origin, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
  // Every API route that changes secrets
  const writes = (envId: string) => [
    ['POST', `/api/v0/projects/${projectId}/environments/${envId}/secrets`, { name: 'ADDED', value: 'x' }],
    ['PUT', `/api/v0/projects/${projectId}/environments/${envId}/secrets`, { secrets: { KEY: 'changed' } }],
    ['DELETE', `/api/v0/projects/${projectId}/environments/${envId}/secrets/KEY`, undefined],
  ] as const
  const writeStatuses = async (token: string, envId: string) => {
    const statuses: number[] = []
    for (const [method, path, body] of writes(envId)) statuses.push((await call(token, path, method, body)).status)
    return statuses
  }
  const values = async (envId: string) => Object.fromEntries(await Promise.all((await deriveSecrets(envId)).map(async (s) => [s.name, await decrypt(s.valueEncrypted, s.iv, s)] as const)))
  // A second login of the admin, without grants from other tests
  const freshLogin = async () => {
    const auth = await getTestAuth()
    const res = await auth.api.signInEmail({ body: { email: admin.user.email, password: 'test-password-123' } })
    return `${res.token}.${await makeSignature(res.token, (await auth.$context).secret)}`
  }
  const outcome = async (run: () => Promise<unknown>) => {
    try {
      await run()
      return 'ok'
    } catch (error) {
      return error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message
    }
  }

  test('changing a protected environment takes the same approval as reading it', async () => {
    const token = await freshLogin()
    const [method, path, body] = writes(prod)[0]
    const first = await call(token, path, method, body)
    const denied = { status: first.status, body: await first.json() }
    const without = await writeStatuses(token, prod)
    const untouched = await values(prod)
    await grantRead(token, [prod])
    const granted = await writeStatuses(token, prod)
    expect({ denied, without, untouched, granted, after: await values(prod) }).toEqual({
      denied: { status: 403, body: { error: 'this environment is protected: approve with your passkey', code: 'STEP_UP_REQUIRED', purpose: 'access', environmentIds: [prod] } },
      without: [403, 403, 403],
      untouched: { KEY: 'original' },
      granted: [200, 200, 200],
      after: { ADDED: 'x' },
    })
  })

  test('only a machine token changes a protected environment, and unprotected ones need nothing', async () => {
    const plain = await insertApiToken({ name: 'plain-writer', projectId, createdBy: admin.user.id })
    const machine = await insertApiToken({ name: 'machine-writer', projectId, createdBy: admin.user.id, protectedAccess: true })
    const [method, path, body] = writes(prod)[0]
    const refused = await call(plain.key, path, method, body)
    expect({
      plain: await writeStatuses(plain.key, prod),
      code: (await refused.json() as { code: string }).code,
      machine: await writeStatuses(machine.key, prod),
      unprotected: await writeStatuses(plain.key, dev),
    }).toEqual({ plain: [403, 403, 403], code: 'MACHINE_TOKEN_REQUIRED', machine: [200, 200, 200], unprotected: [200, 200, 200] })
  })

  test('the only writer of the history checks it too', async () => {
    const write = (author: { userId: string; apiTokenId: null; sessionId?: string }) => outcome(() => appendSecretEvents({ author, events: [{ environmentId: prod, name: 'DIRECT', operation: 'set', value: 'x' }] }))
    const token = await freshLogin()
    const withoutSession = await write({ userId: admin.user.id, apiTokenId: null })
    const withoutGrant = await write({ userId: admin.user.id, apiTokenId: null, sessionId: await sessionIdOf(token) })
    await grantRead(token, [prod])
    expect({ withoutSession, withoutGrant, granted: await write({ userId: admin.user.id, apiTokenId: null, sessionId: await sessionIdOf(token) }) })
      .toEqual({ withoutSession: 'step-up:access', withoutGrant: 'step-up:access', granted: 'ok' })
  })

  test('deleting a protected environment or its project takes an admin approval', async () => {
    const af = authedFetch(admin.token)
    const token = await freshLogin()
    const slug = `doomed-${Date.now()}`
    const doomed = assertOk(await af('/api/v0/projects/:projectId/environments', { method: 'POST', params: { projectId }, body: { name: slug, slug } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: doomed, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const other = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: `Doomed ${Date.now()}`, orgId } })).id
    const otherProd = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId: other, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: otherProd, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const exists = async () => ({
      env: !!await getDb().query.environment.findFirst({ where: { id: doomed } }),
      project: !!await getDb().query.project.findFirst({ where: { id: other } }),
    })
    const deleteEnv = () => call(token, `/api/v0/projects/${projectId}/environments/${doomed}`, 'DELETE')
    const deleteProject = () => call(token, `/api/v0/projects/${other}`, 'DELETE')
    const without = { env: (await deleteEnv()).status, project: (await deleteProject()).status }
    const kept = await exists()
    // Approving access to the environments isn't enough
    await grantRead(token, [doomed, otherProd])
    const accessOnly = { env: (await deleteEnv()).status, project: (await deleteProject()).status }
    await grantAdmin(token)
    const granted = { env: (await deleteEnv()).status, project: (await deleteProject()).status }
    expect({ without, kept, accessOnly, granted, gone: await exists() }).toEqual({
      without: { env: 403, project: 403 }, kept: { env: true, project: true }, accessOnly: { env: 403, project: 403 }, granted: { env: 200, project: 200 }, gone: { env: false, project: false },
    })
  })

  test('renaming a protected environment, or a project with one, takes an admin approval', async () => {
    const token = await freshLogin()
    const af = authedFetch(admin.token)
    const slug = `renamed-${Date.now()}`
    const guarded = assertOk(await af('/api/v0/projects/:projectId/environments', { method: 'POST', params: { projectId }, body: { name: slug, slug } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: guarded, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const renameEnv = () => call(token, `/api/v0/projects/${projectId}/environments/${guarded}`, 'PATCH', { slug: `${slug}-old` })
    const renameProject = () => call(token, `/api/v0/projects/${projectId}`, 'PATCH', { name: 'Writes Project renamed' })
    const renameUnprotected = () => call(token, `/api/v0/projects/${projectId}/environments/${dev}`, 'PATCH', { name: 'Development' })
    const without = { env: (await renameEnv()).status, project: (await renameProject()).status, unprotected: (await renameUnprotected()).status }
    const names = async () => ({
      slug: (await getDb().query.environment.findFirst({ where: { id: guarded } }))!.slug,
      project: (await getDb().query.project.findFirst({ where: { id: projectId } }))!.name,
    })
    const kept = await names()
    await grantRead(token, [guarded, prod])
    const accessOnly = { env: (await renameEnv()).status, project: (await renameProject()).status }
    await grantAdmin(token)
    const granted = { env: (await renameEnv()).status, project: (await renameProject()).status }
    expect({ without, kept, accessOnly, granted, after: await names() }).toEqual({
      without: { env: 403, project: 403, unprotected: 200 },
      kept: { slug, project: 'Writes Project' },
      accessOnly: { env: 403, project: 403 },
      granted: { env: 200, project: 200 },
      after: { slug: `${slug}-old`, project: 'Writes Project renamed' },
    })
  })

  test('admin actions need an admin approval once the org has a protected environment', async () => {
    const token = await freshLogin()
    const sessionId = await sessionIdOf(token)
    const other = await freshLogin()
    const plainOrg = assertOk(await authedFetch(admin.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Unprotected Org' } })).id
    const member = await createTestUser({ name: 'Writes Member' })
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const check = (org: string, as = { userId: admin.user.id, sessionId }) => outcome(() => requireOrgAdmin({ ...as, orgId: org }))
    const unprotectedOrg = await check(plainOrg)
    const notAdmin = await check(orgId, { userId: member.user.id, sessionId: await sessionIdOf(member.token) })
    const none = await check(orgId)
    await grantRead(token, [prod])
    const accessOnly = await check(orgId)
    await grantAdmin(token, Date.now() - 1)
    const expired = await check(orgId)
    await grantAdmin(other)
    const otherLogin = await check(orgId)
    await grantAdmin(token)
    expect({ unprotectedOrg, notAdmin, none, accessOnly, expired, otherLogin, granted: await check(orgId) }).toEqual({
      unprotectedOrg: 'ok', notAdmin: 'Only admins can do this', none: 'step-up:admin', accessOnly: 'step-up:admin', expired: 'step-up:admin', otherLogin: 'step-up:admin', granted: 'ok',
    })
  })

  test('removing your own passkey needs an approval with one', async () => {
    const token = await freshLogin()
    const sessionId = await sessionIdOf(token)
    const without = await outcome(() => requireAdminApproval({ userId: admin.user.id, sessionId }))
    await grantAdmin(token)
    expect({ without, granted: await outcome(() => requireAdminApproval({ userId: admin.user.id, sessionId })) })
      .toEqual({ without: 'step-up:admin', granted: 'ok' })
  })

  test('every action that can need a passkey answers { stepUp } instead of failing', () => {
    const source = (import.meta.glob('./actions.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['./actions.ts']!
    const gate = /\b(requireOrgAdmin|requireProtectedAccess|requireAdminApproval|requireMachineTokenApproval|requireMachineTokenDeletion|requireOldValuesPurge|appendSecretEvents|recordSecretRead|readSecretValues|readEventValue|setEnvironmentProtection|resetMemberPasskeys|approveEnrollment|declineEnrollment|requirePasskeyOnceEnrolled)\(/
    const functions = source.split(/\n(?=(?:export )?async function )/)
    const nameOf = (fn: string) => fn.match(/async function (\w+)/)?.[1] ?? ''
    const gatedHelpers = functions.filter((fn) => fn.startsWith('async function') && gate.test(fn)).map(nameOf)
    const unwrapped = functions
      .filter((fn) => fn.startsWith('export async function'))
      .filter((fn) => gate.test(fn) || gatedHelpers.some((helper) => fn.includes(`${helper}(`)))
      .filter((fn) => !fn.includes('stepUpOr('))
      .map(nameOf)
    // And admin checks only through requireOrgAdmin
    expect({ unwrapped, ownAdminChecks: source.match(/\{ role \} = await requireOrgMember/g) ?? [] }).toEqual({ unwrapped: [], ownAdminChecks: [] })
  })
})

describe('API errors', () => {
  const call = (token: string, path: string, method: string, body: unknown) => app.handle(new Request(`http://e.ly${path}`, {
    method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body),
  }))

  test('answer with a status and a message, never a stack trace or a query', async () => {
    const user = await createTestUser({ name: 'Error User' })
    const stranger = await createTestUser({ name: 'Error Stranger' })
    const af = authedFetch(user.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Error Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Error Project', orgId } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    // A slug that is taken, and an approval for another org's environment
    const taken = await call(user.token, `/api/v0/projects/${projectId}/environments`, 'POST', { name: 'Dev again', slug: 'dev' })
    const foreign = await call(stranger.token, '/api/v0/step-up', 'POST', { environmentIds: [prod] })
    expect([
      { status: taken.status, body: await taken.json() },
      { status: foreign.status, body: await foreign.json() },
    ]).toEqual([
      { status: 409, body: { error: 'already exists' } },
      { status: 403, body: { error: 'forbidden' } },
    ])
  })
})

describe('deleting', () => {
  test('an organization takes its name typed out, and an environment with secrets its slug', async () => {
    const user = await createTestUser({ name: 'Delete User' })
    const af = authedFetch(user.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Acme Corp' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Website', orgId } })).id
    const env = async (slug: string) => assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: slug } })).id
    const [dev, prod] = [await env('dev'), await env('prod')]
    assertOk(await af('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'PUT', params: { pid: projectId, eid: prod }, body: { secrets: { A: '1', B: '2' } } }))
    const outcome = async (run: () => Promise<unknown>) => run().then(() => 'ok', (error: Error) => error.message)
    expect({
      counts: await countSecrets([dev, prod]),
      orgUntyped: await outcome(() => requireOrgDeletionTyped({ orgId, typed: '' })),
      orgWrongCase: await outcome(() => requireOrgDeletionTyped({ orgId, typed: 'acme corp' })),
      orgTyped: await outcome(() => requireOrgDeletionTyped({ orgId, typed: 'Acme Corp' })),
      emptyEnv: await outcome(() => requireEnvironmentDeletionTyped({ environmentId: dev, typed: undefined })),
      prodUntyped: await outcome(() => requireEnvironmentDeletionTyped({ environmentId: prod, typed: undefined })),
      prodTyped: await outcome(() => requireEnvironmentDeletionTyped({ environmentId: prod, typed: 'prod' })),
      projectUntyped: await outcome(() => requireProjectDeletionTyped({ projectId, typed: 'website' })),
      projectTyped: await outcome(() => requireProjectDeletionTyped({ projectId, typed: 'Website' })),
    }).toEqual({
      counts: { [dev]: 0, [prod]: 2 },
      orgUntyped: "Type the organization's name to delete it",
      orgWrongCase: "Type the organization's name to delete it",
      orgTyped: 'ok',
      emptyEnv: 'ok',
      prodUntyped: "Type the environment's slug to delete it and its 2 secrets",
      prodTyped: 'ok',
      projectUntyped: "Type the project's name to delete it",
      projectTyped: 'ok',
    })
  })
})

describe('moving a protected environment aside', () => {
  const origin = 'http://e.ly'
  const call = (token: string, path: string, method = 'GET', body?: unknown) => app.handle(new Request(`${origin}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, origin, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
  const setup = async (name: string) => {
    const admin = await createTestUser({ name: `${name} Admin` })
    const member = await createTestUser({ name: `${name} Member` })
    const af = authedFetch(admin.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: `${name} Org` } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: `${name} Project`, orgId } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    return { admin, member, orgId, projectId, prod }
  }

  test('only an admin with a passkey approval deletes or renames it, or its project', async () => {
    const { admin, member, projectId, prod } = await setup('Aside')
    // The member may read and change prod with their own approval
    await grantRead(member.token, [prod])
    const env = `/api/v0/projects/${projectId}/environments/${prod}`
    const byMember = {
      renameEnv: (await call(member.token, env, 'PATCH', { slug: 'prod-old' })).status,
      deleteEnv: (await call(member.token, env, 'DELETE')).status,
      renameProject: (await call(member.token, `/api/v0/projects/${projectId}`, 'PATCH', { name: 'Old' })).status,
      deleteProject: (await call(member.token, `/api/v0/projects/${projectId}`, 'DELETE')).status,
    }
    const adminWithoutApproval = await (await call(admin.token, env, 'PATCH', { slug: 'prod-old' })).json() as { code?: string; purpose?: string }
    await grantAdmin(admin.token)
    const adminApproved = (await call(admin.token, env, 'PATCH', { name: 'Production' })).status
    expect({ byMember, adminWithoutApproval: [adminWithoutApproval.code, adminWithoutApproval.purpose], adminApproved }).toEqual({
      byMember: { renameEnv: 403, deleteEnv: 403, renameProject: 403, deleteProject: 403 },
      adminWithoutApproval: ['STEP_UP_REQUIRED', 'admin'],
      adminApproved: 200,
    })
  })

  test('a member can\'t rename a project with an admin-only environment, as they can\'t delete it', async () => {
    const admin = await createTestUser({ name: 'Name Admin' })
    const member = await createTestUser({ name: 'Name Member' })
    const af = authedFetch(admin.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Name Org' } })).id
    const payments = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Payments', orgId } })).id
    await getDb().update(schema.environment).set({ accessRole: 'admin' }).where(orm.and(orm.eq(schema.environment.projectId, payments), orm.eq(schema.environment.slug, 'prod')))
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const rename = await call(member.token, `/api/v0/projects/${payments}`, 'PATCH', { name: 'Payments (old)' })
    expect({ status: rename.status, body: await rename.json() }).toEqual({ status: 403, body: { error: 'admin access required for this environment' } })
  })
})

describe('passkey enrollment', () => {
  const origin = 'http://e.ly'
  const outcomeOf = async (run: () => Promise<unknown>) => {
    try {
      await run()
      return 'ok'
    } catch (error) {
      return error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message
    }
  }
  const send = (path: string, { token, body, cookie }: { token?: string; body?: unknown; cookie?: string } = {}) => app.handle(new Request(`${origin}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(cookie ? { cookie } : {}), origin, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))
  // Registers a new software passkey with this login, as the Passkeys page does
  const register = async (token: string) => {
    const optionsRes = await send('/api/auth/passkey/generate-register-options', { token })
    if (optionsRes.status !== 200) return optionsRes.status
    const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    const authenticator = await createSoftAuthenticator({ rpID: 'e.ly', origin })
    const res = await send('/api/auth/passkey/verify-registration', { token, cookie, body: { response: await authenticator.register(await optionsRes.json() as { challenge: string }) } })
    return res.status
  }
  // A new CLI login, approved on /device by an existing login
  const deviceLogin = async (approver: string) => {
    const code = await (await send('/api/auth/device/code', { body: { client_id: 'sigillo-cli' } })).json() as { device_code: string; user_code: string }
    await send(`/api/auth/device?user_code=${code.user_code}`, { token: approver })
    await send('/api/auth/device/approve', { token: approver, body: { userCode: code.user_code } })
    const issued = await (await send('/api/auth/device/token', {
      body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: code.device_code, client_id: 'sigillo-cli' },
    })).json() as { access_token: string }
    return issued.access_token
  }

  test('an admin resets a member\'s passkeys only as an admin of all their organizations, and signs them out', async () => {
    const admin = await createTestUser({ name: 'Reset Admin' })
    const member = await createTestUser({ name: 'Reset Member' })
    const outsider = await createTestUser({ name: 'Other Org Admin' })
    const af = authedFetch(admin.token)
    const plainOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Plain Org' } })).id
    const guardedOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Guarded Org' } })).id
    const guardedProject = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Guarded', orgId: guardedOrg } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId: guardedProject, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    const outsiderOrg = assertOk(await authedFetch(outsider.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Outsider Org' } })).id
    for (const orgId of [plainOrg, guardedOrg]) await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    await getDb().insert(schema.passkey).values({ name: 'Laptop', publicKey: 'x', userId: member.user.id, credentialID: `c-${Date.now()}`, counter: 0, deviceType: 'singleDevice', backedUp: false })
    const reset = async (actor: typeof admin) => {
      try {
        await resetMemberPasskeys({ request: null, actor: { userId: actor.user.id, sessionId: await sessionIdOf(actor.token) }, userId: member.user.id })
        return 'ok'
      } catch (error) {
        return error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message
      }
    }
    const memberSession = await sessionIdOf(member.token)
    const self = await outcomeOf(() => resetMemberPasskeys({ request: null, actor: { userId: member.user.id, sessionId: memberSession }, userId: member.user.id }))
    // An admin of an org the member isn't in, and one of only some of their orgs
    await getDb().insert(schema.orgMember).values({ orgId: outsiderOrg, userId: member.user.id, role: 'member' })
    const adminOfSome = await reset(admin)
    await getDb().delete(schema.orgMember).where(orm.and(orm.eq(schema.orgMember.orgId, outsiderOrg), orm.eq(schema.orgMember.userId, member.user.id)))
    const withoutApproval = await reset(admin)
    const kept = (await getDb().query.passkey.findMany({ where: { userId: member.user.id } })).length
    await grantAdmin(admin.token)
    const approved = await reset(admin)
    expect({
      self, adminOfSome, withoutApproval, kept, approved,
      passkeys: (await getDb().query.passkey.findMany({ where: { userId: member.user.id } })).length,
      sessions: (await getDb().query.session.findMany({ where: { userId: member.user.id } })).length,
      logged: (await getDb().query.passkeyEvent.findMany({ where: { userId: member.user.id } })).map((e) => [e.action, e.actor]),
    }).toEqual({
      self: 'Remove your own passkeys on the Passkeys page',
      adminOfSome: "They also belong to an organization you're not an admin of: an admin of each of their organizations can reset them",
      withoutApproval: 'step-up:admin',
      kept: 1,
      approved: 'ok',
      passkeys: 0,
      sessions: 0,
      logged: [['removed', `user:${admin.user.id}`]],
    })
  })

  test('a login older than a day signs in again to list sessions or add a passkey, and can still end all others', async () => {
    const user = await createTestUser()
    const sessionId = await sessionIdOf(user.token)
    const authenticator = await createSoftAuthenticator({ rpID: 'e.ly', origin })
    // A first passkey while the sign-in is fresh, and another login elsewhere
    const optionsRes = await send('/api/auth/passkey/generate-register-options', { token: user.token })
    const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    expect((await send('/api/auth/passkey/verify-registration', { token: user.token, cookie, body: { response: await authenticator.register(await optionsRes.json() as { challenge: string }) } })).status).toBe(200)
    const auth = await getTestAuth()
    await auth.api.signInEmail({ body: { email: user.user.email, password: 'test-password-123' } })
    await getDb().update(schema.session).set({ createdAt: Date.now() - 2 * 86_400_000 }).where(orm.eq(schema.session.id, sessionId))
    const asUser = new Request(origin, { headers: { authorization: `Bearer ${user.token}`, origin } })
    const approveAdmin = async (id: string) => {
      const request = await createStepUpRequest({ request: new Request(origin), userId: user.user.id, sessionId: id, environmentIds: [], withCode: false, purpose: 'admin' })
      const options = await approvalOptions({ request: new Request(origin), requestId: request.id, userId: user.user.id })
      await approveStepUpRequest({ request: new Request(origin), requestId: request.id, userId: user.user.id, response: await authenticator.authenticate(options) })
    }
    const listed = await listUserSessions(asUser)
    await approveAdmin(sessionId)
    const secondFromOldLogin = await register(user.token)
    await endOtherUserSessions(asUser)
    const left = (await getDb().query.session.findMany({ where: { userId: user.user.id } })).length
    // Signing in again: a new login, approved with the first passkey
    const again = await auth.api.signInEmail({ body: { email: user.user.email, password: 'test-password-123' } })
    const newLogin = `${again.token}.${await makeSignature(again.token, (await auth.$context).secret)}`
    await approveAdmin(await sessionIdOf(newLogin))
    expect({ listed, secondFromOldLogin, left, afterSignIn: await register(newLogin), listedAfter: (await listUserSessions(new Request(origin, { headers: { authorization: `Bearer ${newLogin}`, origin } })))?.length })
      .toEqual({ listed: null, secondFromOldLogin: 403, left: 1, afterSignIn: 200, listedAfter: 2 })
  })

  test('signing in again comes back to the page it was on', async () => {
    const location = async (path: string) => new URL((await app.handle(new Request(`${origin}${path}`))).headers.get('location')!).searchParams.get('post_logout_redirect_uri')
    expect({ sessions: await location('/logout?redirect=/dash/sessions'), elsewhere: await location('/logout?redirect=https://evil.example'), none: await location('/logout') })
      .toEqual({ sessions: `${origin}/login?redirect=%2Fdash%2Fsessions`, elsewhere: `${origin}/login?redirect=%2Fdash`, none: `${origin}/login` })
  })

  test('another site\'s link to /logout asks before signing out', async () => {
    const user = await createTestUser({ name: 'Logout User' })
    const signedIn = async () => !!await getDb().query.session.findFirst({ where: { token: user.token.split('.')[0]! } })
    const visit = (site: string) => app.handle(new Request(`${origin}/logout?redirect=/dash/sessions`, { headers: { authorization: `Bearer ${user.token}`, 'sec-fetch-site': site } }))
    const fromElsewhere = await visit('cross-site')
    const page = await fromElsewhere.text()
    const stillIn = await signedIn()
    const fromSigillo = await visit('same-origin')
    expect({
      fromElsewhere: [fromElsewhere.status, page.includes('<form method="post" action="/logout?redirect=%2Fdash%2Fsessions">')],
      stillIn,
      fromSigillo: fromSigillo.status,
      signedOut: !await signedIn(),
    }).toEqual({ fromElsewhere: [200, true], stillIn: true, fromSigillo: 302, signedOut: true })
  })

  // A login as the Passkeys page sees it
  const loginOf = async (token: string) => {
    const row = (await getDb().query.session.findFirst({ where: { token: token.split('.')[0]! } }))!
    return { userId: row.userId, sessionId: row.id, signedIn: row.signedIn, sessionCreatedAt: row.createdAt }
  }

  test('once an admin has a passkey, a member\'s first passkey needs an admin\'s approval', async () => {
    const admin = await createTestUser({ name: 'Enroll Admin' })
    const member = await createTestUser({ name: 'Enroll Member' })
    const outsider = await createTestUser({ name: 'Other Org Admin' })
    const af = authedFetch(admin.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Enroll Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Enroll', orgId } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    // The first admin enrolls with a fresh sign-in alone
    const firstAdminPasskey = await register(admin.token)
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    // An admin of an organization of their own, which the member also joined
    const outsiderOrg = assertOk(await authedFetch(outsider.token)('/api/v0/orgs', { method: 'POST', body: { name: 'Outsider Org' } })).id
    await getDb().insert(schema.orgMember).values({ orgId: outsiderOrg, userId: member.user.id, role: 'member' })
    const approverOrgs = await passkeyApproverOrgs(member.user.id)
    const withoutApproval = await register(member.token)
    const asked = await requestEnrollment({ request: new Request(origin), ...await loginOf(member.token), viaCode: false })
    const approve = async (who: typeof admin) => {
      const sessionId = await sessionIdOf(who.token)
      return outcomeOf(() => approveEnrollment({ requestId: asked.id, approver: { userId: who.user.id, sessionId } }))
    }
    const bySelf = await approve(member)
    const byOutsider = await approve(outsider)
    const withoutPasskeyApproval = await approve(admin)
    await grantAdmin(admin.token)
    const approved = await approve(admin)
    const afterApproval = await register(member.token)
    const usedUp = await register(member.token)
    expect({ firstAdminPasskey, approverOrgs, withoutApproval, bySelf, byOutsider, withoutPasskeyApproval, approved, afterApproval, usedUp }).toEqual({
      firstAdminPasskey: 200,
      approverOrgs: [orgId],
      withoutApproval: 403,
      bySelf: 'Another admin approves your own first passkey',
      byOutsider: 'An admin of one of their organizations with protected environments approves it',
      withoutPasskeyApproval: 'step-up:admin',
      approved: 'ok',
      afterApproval: 200,
      usedUp: 403,
    })
  })

  test('leaving an organization doesn\'t get around its approval of a first passkey, nor does its old invite link bring you back', async () => {
    const admin = await createTestUser({ name: 'Leave Admin' })
    const member = await createTestUser({ name: 'Leave Member' })
    const af = authedFetch(admin.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Leave Org' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Leave', orgId } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    expect(await register(admin.token)).toBe(200)
    const invite = async (createdAt: number) => (await getDb().insert(schema.orgInvitation).values({ orgId, createdBy: admin.user.id, createdAt, expiresAt: Date.now() + 60_000 }).returning())[0]!.id
    const oldInvite = await invite(Date.now() - 1000)
    const joined = await outcomeOf(() => joinOrgByInvite({ invitationId: oldInvite, userId: member.user.id }))
    // Someone with the member's Google account leaves, adds a passkey, and comes back
    await deleteOrgMember((await getDb().query.orgMember.findFirst({ where: { orgId, userId: member.user.id } }))!, { userId: member.user.id })
    const approverOrgs = await passkeyApproverOrgs(member.user.id)
    const withoutApproval = await register(member.token)
    const backWithOldInvite = await outcomeOf(() => joinOrgByInvite({ invitationId: oldInvite, userId: member.user.id }))
    // The organization's admins still see the request, from a former member
    const asked = await requestEnrollment({ request: new Request(origin), ...await loginOf(member.token), viaCode: false })
    const shown = (await pendingEnrollments({ userIds: (await listFormerMembers(orgId)).map((user) => user.id), orgId })).map((row) => row.id)
    const backWithNewInvite = await outcomeOf(async () => joinOrgByInvite({ invitationId: await invite(Date.now() + 1), userId: member.user.id }))
    expect({ joined, approverOrgs, withoutApproval, backWithOldInvite, shown, backWithNewInvite, afterRejoining: await passkeyApproverOrgs(member.user.id) }).toEqual({
      joined: 'ok',
      approverOrgs: [orgId],
      withoutApproval: 403,
      backWithOldInvite: 'You left or were removed from this organization after this invitation was made: ask an admin for a new one.',
      shown: [asked.id],
      backWithNewInvite: 'ok',
      afterRejoining: [orgId],
    })
  })

  test('only asking to add a passkey opens an enrollment request, and nobody approves one that needs no admin', async () => {
    const victim = await createTestUser({ name: 'Only Passkey Admin' })
    const stranger = await createTestUser({ name: 'Stranger' })
    const af = authedFetch(victim.token)
    const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Small Team' } })).id
    const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Small', orgId } })).id
    const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: victim.user.id, apiTokenId: null } })
    expect(await register(victim.token)).toBe(200)
    // An hour later, someone has the login
    const login = await loginOf(victim.token)
    await getDb().update(schema.session).set({ createdAt: Date.now() - 60 * 60 * 1000 }).where(orm.eq(schema.session.id, login.sessionId))
    // What the browser's step-up action passes on, with a purpose it picked
    const asked = await outcomeOf(() => createStepUpRequest({ request: new Request(origin), userId: login.userId, sessionId: login.sessionId, environmentIds: [], withCode: false, purpose: 'enroll' as never }))
    // A request like an admin's, from before: nobody else in the org has a passkey
    const [older] = await getDb().insert(schema.stepUpRequest).values({
      userId: login.userId, sessionId: login.sessionId, environmentIds: [], purpose: 'enroll', expiresAt: Date.now() + 60_000,
    }).returning({ id: schema.stepUpRequest.id })
    const byStranger = await outcomeOf(async () => approveEnrollment({ requestId: older!.id, approver: { userId: stranger.user.id, sessionId: await sessionIdOf(stranger.token) } }))
    expect({ asked, byStranger, anotherPasskey: await register(victim.token) }).toEqual({
      asked: 'Unknown approval',
      byStranger: 'This request needs no admin approval',
      anotherPasskey: 403,
    })
  })

  test('one approval to add a passkey is used up as the passkey is added, so two registrations can\'t share it', async () => {
    const user = await createTestUser({ name: 'Racing Enroller' })
    const login = await loginOf(user.token)
    // An old login with an approval to add a passkey, as an admin or another device gives it
    await getDb().update(schema.session).set({ createdAt: Date.now() - 60 * 60 * 1000 }).where(orm.eq(schema.session.id, login.sessionId))
    await getDb().insert(schema.stepUpGrant).values({ userId: user.user.id, sessionId: login.sessionId, purpose: 'enroll', environmentIds: [], createdAt: Date.now(), expiresAt: Date.now() + 60_000 })
    const aged = { ...login, sessionCreatedAt: Date.now() - 60 * 60 * 1000 }
    expect(await canAddPasskey(aged)).toBe(true)
    // Two registrations reach the check at once
    expect((await Promise.all([claimPasskeyAddition(aged), claimPasskeyAddition(aged)])).sort()).toEqual([false, true])
  })

  test('a member of two organizations gets a first passkey once an admin of each has approved', async () => {
    const guardedOrg = async (name: string) => {
      const admin = await createTestUser({ name: `${name} Admin` })
      const af = authedFetch(admin.token)
      const orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name } })).id
      const projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: `${name} Project`, orgId } })).id
      const prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
      await setEnvironmentProtection({ request: new Request(origin), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
      expect(await register(admin.token)).toBe(200)
      await grantAdmin(admin.token)
      return { admin, orgId }
    }
    const first = await guardedOrg('First Guarded')
    const second = await guardedOrg('Second Guarded')
    const member = await createTestUser({ name: 'Two Org Member' })
    for (const { orgId } of [first, second]) await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    const asked = await requestEnrollment({ request: new Request(origin), ...await loginOf(member.token), viaCode: false })
    const approve = async (who: typeof first.admin) => approveEnrollment({ requestId: asked.id, approver: { userId: who.user.id, sessionId: await sessionIdOf(who.token) } })
    const byFirst = await approve(first.admin)
    const accessTab = (await pendingEnrollments({ userIds: [member.user.id], orgId: first.orgId })).map((row) => [row.approvedHere, row.waitingForOthers])
    const beforeSecond = await register(member.token)
    const bySecond = await approve(second.admin)
    expect({ byFirst, accessTab, beforeSecond, bySecond, afterBoth: await register(member.token) }).toEqual({
      byFirst: { waitingFor: 1 },
      accessTab: [[true, 1]],
      beforeSecond: 403,
      bySecond: { waitingFor: 0 },
      afterBoth: 200,
    })
  })

  test('a passkey on another device is approved on /approve with a code, from a fresh sign-in only', async () => {
    const user = await createTestUser()
    const laptop = await createSoftAuthenticator({ rpID: 'e.ly', origin })
    // The first passkey, from the laptop's fresh sign-in
    const optionsRes = await send('/api/auth/passkey/generate-register-options', { token: user.token })
    const cookie = optionsRes.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    expect((await send('/api/auth/passkey/verify-registration', { token: user.token, cookie, body: { response: await laptop.register(await optionsRes.json() as { challenge: string }) } })).status).toBe(200)
    // The phone signs in
    const auth = await getTestAuth()
    const signIn = await auth.api.signInEmail({ body: { email: user.user.email, password: 'test-password-123' } })
    const phone = `${signIn.token}.${await makeSignature(signIn.token, (await auth.$context).secret)}`
    const withoutApproval = await register(phone)
    const asked = await requestEnrollment({ request: new Request(origin), ...await loginOf(phone), viaCode: true })
    // On the laptop: the code typed on /approve, and its passkey
    const found = await findStepUpRequest({ userId: user.user.id, userCode: asked.userCode!.toLowerCase() })
    const options = await approvalOptions({ request: new Request(origin), requestId: asked.id, userId: user.user.id })
    const approved = await approveStepUpRequest({ request: new Request(origin), requestId: asked.id, userId: user.user.id, response: await laptop.authenticate(options) })
    const afterApproval = await register(phone)
    const usedUp = await register(phone)
    // An old login can't even ask
    await getDb().update(schema.session).set({ createdAt: Date.now() - 10 * 60 * 1000 }).where(orm.eq(schema.session.id, await sessionIdOf(phone)))
    const oldLogin = await outcomeOf(async () => requestEnrollment({ request: new Request(origin), ...await loginOf(phone), viaCode: true }))
    expect({ withoutApproval, purpose: found?.purpose, approved, afterApproval, usedUp, oldLogin }).toEqual({
      withoutApproval: 403, purpose: 'enroll', approved: true, afterApproval: 200, usedUp: 403,
      oldLogin: 'Sign in again first: asking to add a passkey takes a sign-in from the last 5 minutes',
    })
  })

  test('approving a CLI login, or making a token, takes your passkey once you have one', async () => {
    const user = await createTestUser()
    const sessionId = await sessionIdOf(user.token)
    const approveLogin = async () => {
      const code = await (await send('/api/auth/device/code', { body: { client_id: 'sigillo-cli' } })).json() as { user_code: string }
      await send(`/api/auth/device?user_code=${code.user_code}`, { token: user.token })
      const res = await send('/api/auth/device/approve', { token: user.token, body: { userCode: code.user_code } })
      return res.status === 403 ? (await res.json() as { code: string }).code : res.status
    }
    const token = () => outcomeOf(() => requirePasskeyOnceEnrolled({ userId: user.user.id, sessionId }))
    const before = { login: await approveLogin(), token: await token() }
    expect(await register(user.token)).toBe(200)
    const withPasskey = { login: await approveLogin(), token: await token() }
    await grantAdmin(user.token)
    expect({ before, withPasskey, approved: { login: await approveLogin(), token: await token() } }).toEqual({
      before: { login: 200, token: 'ok' },
      withPasskey: { login: 'PASSKEY_APPROVAL_REQUIRED', token: 'step-up:admin' },
      approved: { login: 200, token: 'ok' },
    })
  })

  test('signing in from /approve comes back to it', async () => {
    const res = await app.handle(new Request(`${origin}/approve`))
    expect({ status: res.status, location: res.headers.get('location') }).toEqual({ status: 302, location: `${origin}/login?redirect=/approve` })
  })

  test('a CLI login approved by an old session is no fresh sign-in for a first passkey', async () => {
    const user = await createTestUser()
    await getDb().update(schema.session).set({ createdAt: Date.now() - 10 * 60 * 1000 }).where(orm.eq(schema.session.id, await sessionIdOf(user.token)))
    const cli = await deviceLogin(user.token)
    expect({ oldLogin: await register(user.token), newCliLogin: await register(cli) }).toEqual({ oldLogin: 403, newCliLogin: 403 })
  })
})

describe('workload identity', () => {
  const ISSUER = 'https://issuer.test'
  const AUDIENCE = 'https://secrets.test'
  let admin: Awaited<ReturnType<typeof createTestUser>>
  let sessionId: string
  let orgId: string
  let projectId: string
  let dev: string
  let prod: string
  const download = (environmentId: string) => `/api/v0/projects/${projectId}/environments/${environmentId}/secrets/download`

  beforeAll(async () => {
    admin = await createTestUser({ name: 'Workload Admin' })
    const af = authedFetch(admin.token)
    orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Workload Org' } })).id
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Workloads', orgId } })).id
    dev = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'dev' } })).id
    prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    sessionId = await sessionIdOf(admin.token)
    await appendSecretEvents({
      author: { userId: admin.user.id, apiTokenId: null, sessionId },
      events: [
        { environmentId: dev, name: 'DB_URL', operation: 'set', value: 'dev-db' },
        { environmentId: dev, name: 'API_KEY', operation: 'set', value: 'dev-key' },
        { environmentId: prod, name: 'DB_URL', operation: 'set', value: 'prod-db' },
      ],
    })
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    await grantAdmin(admin.token, Date.now() + 10 * 60_000)
  })

  const now = () => Math.floor(Date.now() / 1000)
  const publicOf = ({ d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, key_ops: _ops, ext: _ext, ...key }: JsonWebKey & { kid: string; alg: string }) => key

  // A JWT from the fake issuer (vite.config.ts), valid for five minutes
  async function signed(claims: Record<string, unknown>, key: 'rsa' | 'ec' = 'rsa') {
    const jwk = workerEnv.TEST_ISSUER_KEYS[key]
    return new jose.SignJWT({ iss: ISSUER, aud: AUDIENCE, iat: now(), exp: now() + 300, ...claims })
      .setProtectedHeader({ alg: jwk.alg, kid: jwk.kid })
      .sign(await jose.importJWK(jwk, jwk.alg))
  }

  function rule(overrides: Partial<TrustRuleInput> = {}, by: { userId: string; sessionId: string } = { userId: admin.user.id, sessionId }) {
    return createTrustRule({
      ...by,
      ownHost: 'e.ly',
      rule: { projectId, name: 'GitHub deploy', issuer: ISSUER, audience: AUDIENCE, subject: 'repo:acme/api:environment:dev', claims: {}, environmentIds: [dev], protectedAccess: false, expiresInDays: 30, ...overrides },
    })
  }

  async function exchange(body: Record<string, unknown>) {
    const res = await app.handle(new Request('http://e.ly/api/v0/workload/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }))
    return { status: res.status, body: await res.json() as { token?: string; error?: string; expiresAt?: number; projectId?: string; environmentIds?: string[] } }
  }

  async function call(key: string, path: string) {
    const res = await app.handle(new Request(`http://e.ly${path}`, { headers: { authorization: `Bearer ${key}` } }))
    return { status: res.status, body: await res.json() as Record<string, unknown> }
  }

  const outcome = (run: Promise<unknown>) => run.then(() => 'ok', (error) => error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message)

  test('a job exchanges its JWT for a token of an hour, which reads the rule\'s environments', async () => {
    const { id } = await rule({ name: 'GitHub dev', claims: { repository_id: '74' } })
    const jwt = await signed({ sub: 'repo:acme/api:environment:dev', repository: 'acme/api', repository_id: '74', environment: 'dev', run_id: '8123', run_attempt: '1' })
    const exchanged = await exchange({ token: jwt })
    const key = exchanged.body.token!
    const row = await getDb().query.apiToken.findFirst({ where: { hashedKey: await hashTokenKey(key) } })
    expect({
      status: exchanged.status,
      environmentIds: exchanged.body.environmentIds,
      minutes: Math.round((exchanged.body.expiresAt! - Date.now()) / 60_000),
      dev: await call(key, download(dev)),
      prod: await call(key, download(prod)),
      row: { name: row?.name, trustRuleId: row?.trustRuleId, sub: row?.workload?.claims.sub, kid: row?.workload?.kid, createdBy: row?.createdBy },
    }).toEqual({
      status: 200,
      environmentIds: [dev],
      minutes: 60,
      dev: { status: 200, body: { DB_URL: 'dev-db', API_KEY: 'dev-key' } },
      prod: { status: 403, body: { error: 'token is scoped to a different environment' } },
      row: { name: 'GitHub dev · acme/api environment dev run 8123.1', trustRuleId: id, sub: 'repo:acme/api:environment:dev', kid: 'rsa-1', createdBy: admin.user.id },
    })
  })

  test('refuses a JWT the rule doesn\'t accept, saying only what the JWT says', async () => {
    await rule({ name: 'Refusals', subject: 'refusals', claims: { repository_id: '74' } })
    const base = { sub: 'refusals', repository_id: '74' }
    const statusOf = async (token: string) => {
      const { status, body } = await exchange({ token })
      return status === 200 ? '200' : `${status} ${body.error}`
    }
    const unsigned = `${btoa(JSON.stringify({ alg: 'none' }))}.${btoa(JSON.stringify({ iss: ISSUER, ...base }))}.`.replaceAll('=', '')
    const hmac = await new jose.SignJWT({ iss: ISSUER, aud: AUDIENCE, iat: now(), exp: now() + 300, ...base })
      .setProtectedHeader({ alg: 'HS256', kid: 'rsa-1' })
      .sign(new TextEncoder().encode(JSON.stringify(publicOf(workerEnv.TEST_ISSUER_KEYS.rsa))))
    const stranger = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']) as CryptoKeyPair
    const foreign = await new jose.SignJWT({ iss: ISSUER, aud: AUDIENCE, iat: now(), exp: now() + 300, ...base })
      .setProtectedHeader({ alg: 'RS256', kid: 'rsa-1' })
      .sign(stranger.privateKey)
    const refused = `403 No trust rule accepts this JWT (issuer ${ISSUER}, subject refusals, audience "https://other.test")`
    expect({
      accepted: await statusOf(await signed(base)),
      thirtySecondsLate: await statusOf(await signed({ ...base, exp: now() - 30 })),
      ninetySecondsLate: await statusOf(await signed({ ...base, exp: now() - 90 })),
      noExpiry: await statusOf(await signed({ ...base, exp: undefined })),
      issuedYesterday: await statusOf(await signed({ ...base, iat: now() - 25 * 3600 })),
      notYetValid: (await statusOf(await signed({ ...base, nbf: now() + 600 }))).slice(0, 3),
      otherAudience: await statusOf(await signed({ ...base, aud: 'https://other.test' })),
      otherSubject: (await statusOf(await signed({ ...base, sub: 'refusals-2' }))).slice(0, 3),
      otherRepository: (await statusOf(await signed({ ...base, repository_id: '75' }))).slice(0, 3),
      otherIssuer: (await statusOf(await signed({ ...base, iss: 'https://elsewhere.test' }))).slice(0, 3),
      unsigned: await statusOf(unsigned),
      hmac: await statusOf(hmac),
      foreignKey: (await statusOf(foreign)).slice(0, 3),
      notAJwt: await statusOf('hello'),
    }).toEqual({
      accepted: '200',
      thirtySecondsLate: '200',
      ninetySecondsLate: '401 The JWT has expired, or never does',
      noExpiry: '401 The JWT has expired, or never does',
      issuedYesterday: '401 The JWT is older than 24 hours, or doesn\'t say when it was issued',
      notYetValid: '403',
      otherAudience: refused,
      otherSubject: '403',
      otherRepository: '403',
      otherIssuer: '403',
      unsigned: '400 JWTs signed with none aren\'t accepted, only RS256 and ES256',
      hmac: '400 JWTs signed with HS256 aren\'t accepted, only RS256 and ES256',
      foreignKey: '403',
      notAJwt: '400 Not a JWT',
    })
  })

  test('pasted keys, ES256, an audience list and nested claims, as a Kubernetes pod sends them', async () => {
    const fetches = async () => (await (await fetch('https://issuer.test/fetches')).json() as { fetches: number }).fetches
    const before = await fetches()
    const cluster = 'https://kubernetes.default.svc.cluster.local'
    const { id } = await rule({
      name: 'Pods',
      issuer: cluster,
      jwks: JSON.stringify({ keys: [publicOf(workerEnv.TEST_ISSUER_KEYS.ec)] }),
      subject: 'system:serviceaccount:payments:api',
      claims: { '/kubernetes.io/namespace': 'payments', '/kubernetes.io/serviceaccount/uid': 'uid-1' },
    })
    const pod = (uid: string, key: 'rsa' | 'ec' = 'ec') => signed({
      iss: cluster,
      sub: 'system:serviceaccount:payments:api',
      aud: [AUDIENCE, 'https://kubernetes.default.svc'],
      'kubernetes.io': { namespace: 'payments', serviceaccount: { name: 'api', uid }, pod: { name: 'api-7d9f5b-x2k9q', uid: 'pod-1' } },
    }, key)
    const accepted = await exchange({ token: await pod('uid-1') })
    const recreated = (await exchange({ token: await pod('uid-2') })).status
    // The cluster rotates to its RSA key, and the admin pastes the new set
    const beforePaste = (await exchange({ token: await pod('uid-1', 'rsa') })).status
    await replaceTrustRuleKeys({ userId: admin.user.id, sessionId, ruleId: id, jwks: JSON.stringify({ keys: [publicOf(workerEnv.TEST_ISSUER_KEYS.rsa)] }) })
    const afterPaste = (await exchange({ token: await pod('uid-1', 'rsa') })).status
    const discovered = await rule({ name: 'Discovered', subject: 'discovered' })
    const row = await getDb().query.apiToken.findFirst({ where: { hashedKey: await hashTokenKey(accepted.body.token!) }, columns: { name: true } })
    expect({
      accepted: accepted.status,
      name: row?.name,
      recreated,
      beforePaste,
      afterPaste,
      pastingOverDiscovered: await outcome(replaceTrustRuleKeys({ userId: admin.user.id, sessionId, ruleId: discovered.id, jwks: '{}' })),
      // One fetch: the discovered rule's keys. Pasted keys never fetch.
      fetched: await fetches() - before,
    }).toEqual({
      accepted: 200,
      name: 'Pods · payments/api pod api-7d9f5b-x2k9q',
      recreated: 403,
      beforePaste: 403,
      afterPaste: 200,
      pastingOverDiscovered: 'This rule gets its keys from its issuer',
      fetched: 1,
    })
  })

  test('requests that arrive together fetch the issuer\'s keys once, and keys a day old are fetched again', async () => {
    const fetches = async () => (await (await fetch('https://issuer.test/fetches')).json() as { fetches: number }).fetches
    const insertRule = (subject: string, jwks: { keys: Array<Record<string, unknown>> }, jwksFetchedAt: number) => getDb().insert(schema.trustRule).values({
      projectId, name: 'Keys', issuer: ISSUER, jwksUri: 'https://issuer.test/jwks', jwks, jwksFetchedAt,
      audience: AUDIENCE, subject, claims: {}, environmentIds: [dev], createdBy: admin.user.id, expiresAt: Date.now() + 86_400_000,
    })
    const ec = publicOf(workerEnv.TEST_ISSUER_KEYS.ec)
    const rsa = publicOf(workerEnv.TEST_ISSUER_KEYS.rsa)
    await insertRule('together', { keys: [ec] }, Date.now() - 10 * 60_000)
    const before = await fetches()
    // The one that claims the fetch gets through; the others try again later
    const together = await Promise.all([1, 2, 3, 4].map(async () => (await exchange({ token: await signed({ sub: 'together' }), project: projectId })).status))
    const afterTogether = await fetches()
    // A key set that would still verify, but was fetched more than a day ago
    await insertRule('yesterday', { keys: [ec, rsa] }, Date.now() - 25 * 3600_000)
    const yesterday = (await exchange({ token: await signed({ sub: 'yesterday' }), project: projectId })).status
    const [fetchedAt] = await getDb().select({ at: schema.trustRule.jwksFetchedAt }).from(schema.trustRule).where(orm.eq(schema.trustRule.subject, 'yesterday'))
    expect({ fetchedTogether: afterTogether - before, oneGotThrough: together.includes(200), yesterday, fetchedForYesterday: await fetches() - afterTogether, refreshedToday: Date.now() - fetchedAt!.at! < 60_000 })
      .toEqual({ fetchedTogether: 1, oneGotThrough: true, yesterday: 200, fetchedForYesterday: 1, refreshedToday: true })
  })

  test('an unknown key id fetches the issuer\'s keys again, at most every five minutes', async () => {
    const fetches = async () => (await (await fetch('https://issuer.test/fetches')).json() as { fetches: number }).fetches
    // Rules that know only the issuer's EC key, fetched long ago and just now
    const staleRule = (subject: string, jwksFetchedAt: number) => getDb().insert(schema.trustRule).values({
      projectId, name: 'Stale keys', issuer: ISSUER, jwksUri: 'https://issuer.test/jwks', jwks: { keys: [publicOf(workerEnv.TEST_ISSUER_KEYS.ec)] },
      jwksFetchedAt, audience: AUDIENCE, subject, claims: {}, environmentIds: [dev], createdBy: admin.user.id, expiresAt: Date.now() + 86_400_000,
    })
    await staleRule('keys-long-ago', Date.now() - 10 * 60_000)
    await staleRule('keys-just-now', Date.now())
    const before = await fetches()
    const longAgo = (await exchange({ token: await signed({ sub: 'keys-long-ago' }) })).status
    const afterLongAgo = await fetches()
    const justNow = (await exchange({ token: await signed({ sub: 'keys-just-now' }) })).status
    const again = (await exchange({ token: await signed({ sub: 'keys-just-now' }) })).status
    expect({ longAgo, fetchedForIt: afterLongAgo - before, justNow, again, fetchedSince: await fetches() - afterLongAgo })
      .toEqual({ longAgo: 200, fetchedForIt: 1, justNow: 403, again: 403, fetchedSince: 0 })
  })

  test('keys come only from an https issuer that names itself, in a small answer', async () => {
    expect({
      liar: await outcome(rule({ issuer: 'https://liar.test' })),
      redirect: await outcome(rule({ issuer: 'https://redirect.test' })),
      plainJwks: await outcome(rule({ issuer: 'https://plain.test' })),
      huge: await outcome(rule({ issuer: 'https://huge.test' })),
      http: await outcome(rule({ issuer: 'http://issuer.test' })),
      address: await outcome(rule({ issuer: 'https://10.0.0.1' })),
      itself: await outcome(rule({ issuer: 'https://e.ly' })),
      privateKey: await outcome(rule({ issuer: 'https://k8s.test', jwks: JSON.stringify({ keys: [workerEnv.TEST_ISSUER_KEYS.rsa] }) })),
      // jose never picks an RSA key named for another algorithm for RS256
      otherAlgorithm: await outcome(rule({ issuer: 'https://k8s.test', jwks: JSON.stringify({ keys: [{ ...publicOf(workerEnv.TEST_ISSUER_KEYS.rsa), alg: 'PS256' }] }) })),
      notJson: await outcome(rule({ issuer: 'https://k8s.test', jwks: 'keys please' })),
    }).toEqual({
      liar: 'The discovery document of https://liar.test names another issuer: https://issuer.test',
      redirect: 'https://redirect.test/.well-known/openid-configuration answered 302',
      plainJwks: 'http://plain.test/jwks must be an https URL without a port, query or credentials',
      huge: 'https://huge.test/.well-known/openid-configuration answered with more than 64 KiB',
      http: 'http://issuer.test must be an https URL without a port, query or credentials',
      address: '10.0.0.1 can\'t be fetched: it must be another host\'s name',
      itself: 'e.ly can\'t be fetched: it must be another host\'s name',
      privateKey: 'That key set holds a private key: paste only the public keys',
      otherAlgorithm: 'The key set has no RSA or P-256 signing key',
      notJson: 'Paste the keys as JSON, as `kubectl get --raw /openid/v1/jwks` prints them',
    })
  })

  test('only an org admin with their passkey makes or deletes a rule, and protected ones last 90 days at most', async () => {
    const member = await createTestUser({ name: 'Workload Member' })
    const newAdmin = await createTestUser({ name: 'Workload Admin Too' })
    await getDb().insert(schema.orgMember).values([{ orgId, userId: member.user.id, role: 'member' }, { orgId, userId: newAdmin.user.id, role: 'admin' }])
    const asMember = { userId: member.user.id, sessionId: await sessionIdOf(member.token) }
    const asNewAdmin = { userId: newAdmin.user.id, sessionId: await sessionIdOf(newAdmin.token) }
    const { id } = await rule({ subject: 'authorization' })
    expect({
      member: await outcome(rule({ subject: 'authorization-1' }, asMember)),
      adminWithoutPasskey: await outcome(rule({ subject: 'authorization-2' }, asNewAdmin)),
      protectedForAYear: await outcome(rule({ subject: 'authorization-3', protectedAccess: true, expiresInDays: 365 })),
      protectedFor90Days: await outcome(rule({ subject: 'authorization-4', protectedAccess: true, expiresInDays: 90 })),
      otherProjectsEnvironment: await outcome(rule({ subject: 'authorization-5', environmentIds: ['01NOTANENVIRONMENT'] })),
      memberDeletes: await outcome(deleteTrustRule({ ...asMember, ruleId: id })),
      adminWithoutPasskeyDeletes: await outcome(deleteTrustRule({ ...asNewAdmin, ruleId: id })),
    }).toEqual({
      member: 'Only admins can do this',
      adminWithoutPasskey: 'step-up:admin',
      protectedForAYear: 'A rule for protected environments expires after 90 days at most',
      protectedFor90Days: 'ok',
      otherProjectsEnvironment: 'Environment not found in this project',
      memberDeletes: 'Only admins can do this',
      adminWithoutPasskeyDeletes: 'step-up:admin',
    })
  })

  test('a workload\'s token stops with its creator\'s admin role, and removing them removes their rules', async () => {
    const creator = await createTestUser({ name: 'Leaving Admin' })
    const [membership] = await getDb().insert(schema.orgMember).values({ orgId, userId: creator.user.id, role: 'admin' }).returning({ id: schema.orgMember.id })
    await grantAdmin(creator.token, Date.now() + 10 * 60_000)
    const { id } = await rule({ name: 'Leaving', subject: 'leaving' }, { userId: creator.user.id, sessionId: await sessionIdOf(creator.token) })
    const key = (await exchange({ token: await signed({ sub: 'leaving' }) })).body.token!
    const before = (await call(key, download(dev))).status
    await getDb().update(schema.orgMember).set({ role: 'member' }).where(orm.eq(schema.orgMember.id, membership!.id))
    const demoted = await call(key, download(dev))
    await deleteOrgMember({ id: membership!.id, orgId, userId: creator.user.id, role: 'member' }, { userId: admin.user.id })
    const row = await getDb().query.apiToken.findFirst({ where: { hashedKey: await hashTokenKey(key) }, columns: { expiresAt: true, trustRuleId: true } })
    expect({
      before,
      demoted,
      ruleLeft: await getDb().query.trustRule.findFirst({ where: { id }, columns: { id: true } }) ?? null,
      token: row && { expired: row.expiresAt! <= Date.now(), trustRuleId: row.trustRuleId },
    }).toEqual({
      before: 200,
      demoted: { status: 403, body: { error: 'the admin who made this trust rule no longer is one' } },
      ruleLeft: null,
      token: { expired: true, trustRuleId: null },
    })
  })

  test('deleting a rule ends its tokens at once, and keeps them for the read log', async () => {
    const { id } = await rule({ name: 'Short-lived', subject: 'short-lived' })
    const key = (await exchange({ token: await signed({ sub: 'short-lived' }) })).body.token!
    const before = (await call(key, download(dev))).status
    await deleteTrustRule({ userId: admin.user.id, sessionId, ruleId: id })
    const row = await getDb().query.apiToken.findFirst({ where: { hashedKey: await hashTokenKey(key) }, columns: { trustRuleId: true, workload: true } })
    expect({
      before,
      after: await call(key, download(dev)),
      row: { trustRuleId: row?.trustRuleId, sub: row?.workload?.claims.sub },
      exchangedAgain: (await exchange({ token: await signed({ sub: 'short-lived' }) })).status,
    }).toEqual({
      before: 200,
      after: { status: 401, body: { error: 'API token expired' } },
      row: { trustRuleId: null, sub: 'short-lived' },
      exchangedAgain: 403,
    })
  })

  test('a rule reads a protected environment only when it says so, and only while its creator is an admin', async () => {
    const creator = await createTestUser({ name: 'Rule Creator' })
    await getDb().insert(schema.orgMember).values({ orgId, userId: creator.user.id, role: 'admin' })
    await grantAdmin(creator.token, Date.now() + 10 * 60_000)
    const by = { userId: creator.user.id, sessionId: await sessionIdOf(creator.token) }
    await rule({ name: 'Deploy prod', subject: 'deploy-prod', environmentIds: [prod], protectedAccess: true, expiresInDays: 90 }, by)
    await rule({ name: 'Read prod', subject: 'read-prod', environmentIds: [prod] }, by)
    const keyFor = async (sub: string) => (await exchange({ token: await signed({ sub }) })).body.token!
    const deploy = await keyFor('deploy-prod')
    const allowed = await call(deploy, download(prod))
    const refused = await call(await keyFor('read-prod'), download(prod))
    const token = await getDb().query.apiToken.findFirst({ where: { hashedKey: await hashTokenKey(deploy) }, columns: { id: true } })
    const lastRead = await getDb().query.secretRead.findFirst({ where: { environmentId: prod }, orderBy: { seq: 'desc' }, columns: { actor: true, kind: true } })
    await getDb().update(schema.orgMember).set({ role: 'member' })
      .where(orm.and(orm.eq(schema.orgMember.orgId, orgId), orm.eq(schema.orgMember.userId, creator.user.id)))
    expect({
      allowed,
      refused: refused.body.code,
      lastRead,
      afterDemotion: { read: (await call(deploy, download(prod))).status, exchange: (await exchange({ token: await signed({ sub: 'deploy-prod' }) })).body.error },
    }).toEqual({
      allowed: { status: 200, body: { DB_URL: 'prod-db' } },
      refused: 'MACHINE_TOKEN_REQUIRED',
      lastRead: { actor: `token:${token!.id}`, kind: 'download' },
      afterDemotion: { read: 403, exchange: 'The admin who owns this trust rule no longer is one: another admin has to renew it on the project\'s Machines tab' },
    })
  })

  test('a workload two projects trust names its project by ID, or its rule', async () => {
    const af = authedFetch(admin.token)
    const other = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Workloads Too', orgId } })).id
    const otherDev = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId: other, id: 'dev' } })).id
    await rule({ name: 'Here', subject: 'shared' })
    const { id } = await rule({ name: 'There', subject: 'shared', projectId: other, environmentIds: [otherDev] })
    const token = await signed({ sub: 'shared' })
    const neither = await exchange({ token })
    expect({
      neither: `${neither.status} ${neither.body.error}`,
      // Names repeat across organizations, so one never picks a rule
      byName: (await exchange({ token, project: 'Workloads Too' })).status,
      byId: (await exchange({ token, project: projectId })).body.projectId,
      byRule: (await exchange({ token, rule: id })).body.projectId,
    }).toEqual({
      neither: '409 Several trust rules accept this JWT: name the project or the rule',
      byName: 403,
      byId: projectId,
      byRule: other,
    })
  })

  test('External Secrets Operator\'s Doppler provider logs in with its service account and downloads an environment', async () => {
    const { id } = await rule({ name: 'ESO', subject: 'system:serviceaccount:external-secrets:sigillo' })
    // As ESO's Doppler client sends them: the token as Basic auth user name
    const doppler = async (path: string, { token, ...init }: RequestInit & { token?: string } = {}) => {
      const headers = new Headers(init.headers)
      if (token !== undefined) headers.set('authorization', `Basic ${btoa(`${token}:`)}`)
      const res = await app.handle(new Request(`http://e.ly${path}`, { ...init, headers }))
      const text = await res.text()
      return { status: res.status, body: res.headers.get('content-type')?.includes('json') ? JSON.parse(text) as Record<string, unknown> : text }
    }
    const login = (identity: string, token: string) => doppler('/v3/auth/oidc', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identity, token }),
    })
    const serviceAccountToken = await signed({ sub: 'system:serviceaccount:external-secrets:sigillo', aud: [AUDIENCE, 'secretStore:payments:sigillo'] })
    const loggedIn = await login(id, serviceAccountToken)
    const token = (loggedIn.body as { token: string }).token
    const secrets = '/v3/configs/config/secrets/download'
    expect({
      loggedIn: { ...loggedIn, body: { ...loggedIn.body as object, token: token.startsWith('sig_'), expires_at: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test((loggedIn.body as { expires_at: string }).expires_at) } },
      otherIdentity: await login('01NOTARULE', serviceAccountToken),
      projects: await doppler('/v3/projects', { token }),
      all: await doppler(`${secrets}?project=${projectId}&config=dev`, { token }),
      // Without a config, the rule's only environment
      one: await doppler(`${secrets}?project=Workloads&secrets=DB_URL`, { token }),
      env: await doppler(`${secrets}?config=dev&format=env`, { token, headers: { accept: 'text/plain' } }),
      nameTransformer: await doppler(`${secrets}?config=dev&name_transformer=camel`, { token }),
      otherProject: await doppler(`${secrets}?project=Elsewhere&config=dev`, { token }),
      noToken: await doppler('/v3/projects'),
    }).toEqual({
      loggedIn: { status: 200, body: { success: true, token: true, expires_at: true } },
      otherIdentity: { status: 403, body: { success: false, messages: [`No trust rule accepts this JWT (issuer ${ISSUER}, subject system:serviceaccount:external-secrets:sigillo, audience ["${AUDIENCE}","secretStore:payments:sigillo"])`] } },
      projects: { status: 200, body: { success: true, projects: [{ id: projectId, slug: projectId, name: 'Workloads', created_at: expect.any(String) }] } },
      all: { status: 200, body: { DB_URL: 'dev-db', API_KEY: 'dev-key' } },
      one: { status: 200, body: { DB_URL: 'dev-db' } },
      env: { status: 200, body: "DB_URL='dev-db'\nAPI_KEY='dev-key'\n" },
      nameTransformer: { status: 400, body: { success: false, messages: ['Sigillo keeps secret names as they are: remove nameTransformer'] } },
      otherProject: { status: 403, body: { success: false, messages: ['This token belongs to another project'] } },
      noToken: { status: 401, body: { success: false, messages: ['Pass a Sigillo API token'] } },
    })
  })
})

// ── Renewals ────────────────────────────────────────────────────────
// Tokens regenerated and trust rules renewed in place (tokens.ts,
// workload.ts), the API's expiry headers, the dashboard banner's data and
// the security log

describe('renewals', () => {
  const ISSUER = 'https://issuer.test'
  const AUDIENCE = 'https://secrets.test'
  const DAY = 86_400_000
  type Login = { userId: string; sessionId: string }
  let admin: Awaited<ReturnType<typeof createTestUser>>
  let member: Awaited<ReturnType<typeof createTestUser>>
  let adminLogin: Login
  let memberLogin: Login
  let orgId: string
  let projectId: string
  let dev: string
  let prod: string

  beforeAll(async () => {
    admin = await createTestUser({ name: 'Renewal Admin' })
    member = await createTestUser({ name: 'Renewal Member' })
    const af = authedFetch(admin.token)
    orgId = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Renewal Org' } })).id
    projectId = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Renewals', orgId } })).id
    dev = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'dev' } })).id
    prod = assertOk(await af('/api/v0/projects/:projectId/environments/:id', { params: { projectId, id: 'prod' } })).id
    await getDb().insert(schema.orgMember).values({ orgId, userId: member.user.id, role: 'member' })
    adminLogin = { userId: admin.user.id, sessionId: await sessionIdOf(admin.token) }
    memberLogin = { userId: member.user.id, sessionId: await sessionIdOf(member.token) }
    await appendSecretEvents({
      author: { ...adminLogin, apiTokenId: null },
      events: [
        { environmentId: dev, name: 'DB_URL', operation: 'set', value: 'dev-db' },
        { environmentId: prod, name: 'DB_URL', operation: 'set', value: 'prod-db' },
      ],
    })
    await setEnvironmentProtection({ request: new Request('http://e.ly'), environmentId: prod, protect: true, author: { userId: admin.user.id, apiTokenId: null } })
    await grantAdmin(admin.token, Date.now() + 10 * 60_000)
  })

  const rfc3339 = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z')
  const download = (environmentId: string) => `/api/v0/projects/${projectId}/environments/${environmentId}/secrets/download`
  async function read(key: string, { environmentId = dev, ip }: { environmentId?: string; ip?: string } = {}) {
    const res = await app.handle(new Request(`http://e.ly${download(environmentId)}`, { headers: { authorization: `Bearer ${key}`, ...(ip ? { 'cf-connecting-ip': ip } : {}) } }))
    return { status: res.status, body: await res.json() as Record<string, unknown>, expires: res.headers.get('sigillo-token-expires'), warning: res.headers.get('sigillo-warning') }
  }
  const tokenRow = async (id: string) => (await getDb().query.apiToken.findFirst({ where: { id } }))!
  const eventsOf = (subjectId: string) => getDb().query.securityEvent.findMany({ where: { subjectId }, orderBy: { createdAt: 'asc' } })
  async function regenerate(tokenId: string, { by = adminLogin, expiresInDays = 90, graceDays = 7 }: { by?: Login; expiresInDays?: number; graceDays?: number } = {}) {
    return regenerateToken({ ...by, tokenId, prefix: (await tokenRow(tokenId)).prefix, expiresInDays, graceDays })
  }
  // A token made daysAgo days ago that expires in daysLeft days
  async function tokenAged({ name, createdBy = admin.user.id, daysAgo, daysLeft, environmentIds }: { name: string; createdBy?: string; daysAgo: number; daysLeft: number; environmentIds?: string[] }) {
    const now = Date.now()
    const token = await insertApiToken({ name, projectId, createdBy, expiresAt: now + daysLeft * DAY, environmentIds })
    await getDb().update(schema.apiToken).set({ createdAt: now - daysAgo * DAY }).where(orm.eq(schema.apiToken.id, token.tokenId))
    return { ...token, expiresAt: now + daysLeft * DAY }
  }
  const outcome = (run: Promise<unknown>) => run.then(() => 'ok', (error) => error instanceof StepUpRequiredError ? `step-up:${error.purpose}` : (error as Error).message)

  const now = () => Math.floor(Date.now() / 1000)
  const publicOf = ({ d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, key_ops: _ops, ext: _ext, ...key }: JsonWebKey & { kid: string; alg: string }) => key
  async function signed(claims: Record<string, unknown>) {
    const jwk = workerEnv.TEST_ISSUER_KEYS.rsa
    return new jose.SignJWT({ iss: ISSUER, aud: AUDIENCE, iat: now(), exp: now() + 300, ...claims })
      .setProtectedHeader({ alg: jwk.alg, kid: jwk.kid })
      .sign(await jose.importJWK(jwk, jwk.alg))
  }
  function rule(overrides: Partial<TrustRuleInput> = {}, by: Login = adminLogin) {
    return createTrustRule({
      ...by,
      ownHost: 'e.ly',
      rule: { projectId, name: 'Renewal deploy', issuer: ISSUER, audience: AUDIENCE, subject: 'renewal', claims: {}, environmentIds: [dev], protectedAccess: false, expiresInDays: 30, ...overrides },
    })
  }
  async function exchange(body: Record<string, unknown>) {
    const res = await app.handle(new Request('http://e.ly/api/v0/workload/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }))
    return { status: res.status, warning: res.headers.get('sigillo-warning'), body: await res.json() as { token?: string; error?: string; expiresAt?: number; ruleId?: string; ruleExpiresAt?: number } }
  }
  const fetches = async () => (await (await fetch('https://issuer.test/fetches')).json() as { fetches: number }).fetches

  test('a regenerated token\'s previous value works until its grace ends, each value with its own last use', async () => {
    const { key: old, tokenId } = await insertApiToken({ name: 'Member CI', projectId, createdBy: member.user.id, expiresAt: Date.now() + 90 * DAY })
    const { key: fresh, id, previousExpiresAt } = await regenerate(tokenId, { by: memberLogin })
    const both = { old: (await read(old, { ip: '203.0.113.1' })).status, fresh: (await read(fresh, { ip: '203.0.113.2' })).status }
    const row = await tokenRow(tokenId)
    await getDb().update(schema.apiToken).set({ previousExpiresAt: Date.now() - 1000 }).where(orm.eq(schema.apiToken.id, tokenId))
    const afterGrace = await read(old)
    expect({
      sameToken: id === tokenId,
      both,
      graceDays: Math.round((previousExpiresAt! - Date.now()) / DAY),
      lastUse: { current: row.lastUsedIp, previous: row.previousLastUsedIp },
      regeneratedBy: row.regeneratedBy === member.user.id && row.createdBy === member.user.id,
      afterGrace: { old: { status: afterGrace.status, body: afterGrace.body }, fresh: (await read(fresh)).status },
    }).toEqual({
      sameToken: true,
      both: { old: 200, fresh: 200 },
      graceDays: 7,
      lastUse: { current: '203.0.113.2', previous: '203.0.113.1' },
      regeneratedBy: true,
      afterGrace: { old: { status: 401, body: { error: 'API token expired: it was regenerated, use the new value' } }, fresh: 200 },
    })
  })

  test('the grace never outlasts the old value\'s own expiry, and a token that never expired gets an expiry', async () => {
    const soon = await insertApiToken({ name: 'Soon', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 2 * DAY })
    const soonExpiresAt = (await tokenRow(soon.tokenId)).expiresAt
    const soonRegenerated = await regenerate(soon.tokenId)
    const never = await insertApiToken({ name: 'Never', projectId, createdBy: admin.user.id })
    const neverRegenerated = await regenerate(never.tokenId, { expiresInDays: 30 })
    const expired = await insertApiToken({ name: 'Gone', projectId, createdBy: admin.user.id, expiresAt: Date.now() - 1000 })
    const expiredRegenerated = await regenerate(expired.tokenId)
    const noGrace = await insertApiToken({ name: 'No grace', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 30 * DAY })
    await regenerate(noGrace.tokenId, { graceDays: 0 })
    expect({
      soon: soonRegenerated.previousExpiresAt === soonExpiresAt,
      never: {
        grace: Math.round((neverRegenerated.previousExpiresAt! - Date.now()) / DAY),
        expiresIn: Math.round(((await tokenRow(never.tokenId)).expiresAt! - Date.now()) / DAY),
        old: (await read(never.key)).status,
      },
      expired: { previousExpiresAt: expiredRegenerated.previousExpiresAt, previousHashedKey: (await tokenRow(expired.tokenId)).previousHashedKey, old: (await read(expired.key)).body },
      noGrace: (await read(noGrace.key)).body,
      oneOfThree: await outcome(regenerate(noGrace.tokenId, { graceDays: 3 })),
    }).toEqual({
      soon: true,
      never: { grace: 7, expiresIn: 30, old: 200 },
      expired: { previousExpiresAt: null, previousHashedKey: null, old: { error: 'invalid or revoked API token' } },
      noGrace: { error: 'API token expired: it was regenerated, use the new value' },
      oneOfThree: 'The previous value keeps working for 0, 1 or 7 days',
    })
  })

  test('regenerating again stops the value that was previous, and a page showing an older value is refused', async () => {
    const first = await insertApiToken({ name: 'Twice', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 90 * DAY })
    const firstPrefix = (await tokenRow(first.tokenId)).prefix
    const second = await regenerate(first.tokenId)
    const third = await regenerate(first.tokenId)
    const stale = await outcome(regenerateToken({ ...adminLogin, tokenId: first.tokenId, prefix: firstPrefix, expiresInDays: 90, graceDays: 7 }))
    // Another admin's regeneration lands between reading the token and writing it
    const race = await insertApiToken({ name: 'Race', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 90 * DAY })
    const prefix = (await tokenRow(race.tokenId)).prefix
    const theirs = await hashTokenKey('sig_regenerated_meanwhile')
    const [raced] = await Promise.all([
      outcome(regenerateToken({ ...adminLogin, tokenId: race.tokenId, prefix, expiresInDays: 90, graceDays: 7 })),
      getDb().update(schema.apiToken).set({ hashedKey: theirs }).where(orm.eq(schema.apiToken.id, race.tokenId)),
    ])
    expect({
      first: (await read(first.key)).status,
      second: (await read(second.key)).status,
      third: (await read(third.key)).status,
      stale,
      raced,
      theirsKept: (await tokenRow(race.tokenId)).hashedKey === theirs,
      logged: (await eventsOf(race.tokenId)).length,
    }).toEqual({
      first: 401,
      second: 200,
      third: 200,
      stale: 'Someone regenerated this token meanwhile: reload the page to see its new value\'s expiry',
      raced: 'Someone regenerated this token meanwhile: reload the page to see its new value\'s expiry',
      theirsKept: true,
      logged: 0,
    })
  })

  test('stopping the previous value ends it at once, into the security log', async () => {
    const token = await insertApiToken({ name: 'Stop CI', projectId, createdBy: member.user.id, expiresAt: Date.now() + 90 * DAY })
    const regenerated = await regenerate(token.tokenId, { by: memberLogin })
    await stopPreviousValue({ ...memberLogin, tokenId: token.tokenId })
    const row = await tokenRow(token.tokenId)
    expect({
      row: { previousHashedKey: row.previousHashedKey, previousExpiresAt: row.previousExpiresAt },
      old: (await read(token.key)).status,
      fresh: (await read(regenerated.key)).status,
      again: await outcome(stopPreviousValue({ ...memberLogin, tokenId: token.tokenId })),
      kinds: (await eventsOf(token.tokenId)).map((event) => event.kind).sort(),
    }).toEqual({
      row: { previousHashedKey: null, previousExpiresAt: null },
      old: 401,
      fresh: 200,
      again: 'Its previous value has already stopped working',
      kinds: ['token.previous_stopped', 'token.regenerated'],
    })
  })

  test('its creator or an org admin regenerates a token, a machine token an admin with a passkey for 90 days at most, and only while its creator can use it', async () => {
    const colleague = await createTestUser({ name: 'Renewal Colleague' })
    const otherAdmin = await createTestUser({ name: 'Renewal Admin Without Passkey' })
    const leaving = await createTestUser({ name: 'Renewal Restricted' })
    const demoted = await createTestUser({ name: 'Renewal Demoted' })
    await getDb().insert(schema.orgMember).values([
      { orgId, userId: colleague.user.id, role: 'member' },
      { orgId, userId: otherAdmin.user.id, role: 'admin' },
      { orgId, userId: leaving.user.id, role: 'member' },
      { orgId, userId: demoted.user.id, role: 'admin' },
    ])
    const plain = await insertApiToken({ name: 'Plain', projectId, createdBy: member.user.id, expiresAt: Date.now() + 90 * DAY })
    const machine = await insertApiToken({ name: 'Deploy', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 90 * DAY, protectedAccess: true })
    const restricted = await insertApiToken({ name: 'Restricted', projectId, createdBy: leaving.user.id, expiresAt: Date.now() + 90 * DAY })
    const demotedMachine = await insertApiToken({ name: 'Demoted deploy', projectId, createdBy: demoted.user.id, expiresAt: Date.now() + 90 * DAY, protectedAccess: true })
    // An admin limits one member to no projects, and demotes the other admin
    await getDb().update(schema.orgMember).set({ projectAccess: 'selected' })
      .where(orm.and(orm.eq(schema.orgMember.orgId, orgId), orm.eq(schema.orgMember.userId, leaving.user.id)))
    await getDb().update(schema.orgMember).set({ role: 'member' })
      .where(orm.and(orm.eq(schema.orgMember.orgId, orgId), orm.eq(schema.orgMember.userId, demoted.user.id)))
    const asColleague = { userId: colleague.user.id, sessionId: await sessionIdOf(colleague.token) }
    const asOtherAdmin = { userId: otherAdmin.user.id, sessionId: await sessionIdOf(otherAdmin.token) }
    const before = {
      colleague: await outcome(regenerate(plain.tokenId, { by: asColleague })),
      adminWithoutPasskey: await outcome(regenerate(machine.tokenId, { by: asOtherAdmin })),
      machineForAYear: await outcome(regenerate(machine.tokenId, { expiresInDays: 365 })),
      creatorLostTheProject: await outcome(regenerate(restricted.tokenId)),
      creatorNoLongerAdmin: await outcome(regenerate(demotedMachine.tokenId)),
      plainForAYear: await outcome(regenerate(plain.tokenId, { expiresInDays: 365 })),
    }
    const regenerated = await regenerate(machine.tokenId, { expiresInDays: 90 })
    const [event] = (await eventsOf(machine.tokenId)).filter((row) => row.kind === 'token.regenerated')
    expect({
      ...before,
      machineReadsProtected: (await read(regenerated.key, { environmentId: prod })).status,
      event: event && { ...event, id: typeof event.id, createdAt: typeof event.createdAt, details: { ...event.details, expiresAt: typeof event.details.expiresAt, previousExpiresAt: typeof event.details.previousExpiresAt } },
    }).toEqual({
      colleague: 'Only its creator or an org admin deletes or regenerates a token',
      adminWithoutPasskey: 'step-up:admin',
      machineForAYear: 'A machine token expires after 90 days at most',
      creatorLostTheProject: 'Its creator can no longer use this token: make a new one',
      creatorNoLongerAdmin: 'Its creator can no longer use this token: make a new one',
      plainForAYear: 'ok',
      machineReadsProtected: 200,
      event: {
        id: 'string', orgId, projectId, projectName: 'Renewals', kind: 'token.regenerated', subjectId: machine.tokenId, subjectName: 'Deploy',
        actor: `user:${admin.user.id}`, actorName: 'Renewal Admin', ipAddress: null, createdAt: 'number',
        details: { machine: true, expiresAt: 'number', previousExpiresAt: 'number', graceDays: 7 },
      },
    })
  })

  test('a regenerated token keeps its place in the history', async () => {
    const token = await insertApiToken({ name: 'History CI', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 90 * DAY })
    const set = (key: string, name: string) => authedFetch(key)('/api/v0/projects/:pid/environments/:eid/secrets', { method: 'POST', params: { pid: projectId, eid: dev }, body: { name, value: 'v' } })
    assertOk(await set(token.key, 'SET_BY_OLD_VALUE'))
    const { key } = await regenerate(token.tokenId)
    assertOk(await set(key, 'SET_BY_NEW_VALUE'))
    assertOk(await set(token.key, 'SET_BY_OLD_VALUE_AGAIN'))
    const rows = await getDb().query.secretEvent.findMany({ where: { environmentId: dev, name: { like: 'SET_BY_%' } }, columns: { name: true, actor: true, apiTokenId: true }, orderBy: { createdAt: 'asc' } })
    const chains = await getAuditChains(dev)
    expect({ rows, chain: (await verifyChain(chains.publicKey, chains.events.rows)).ok }).toEqual({
      rows: ['SET_BY_OLD_VALUE', 'SET_BY_NEW_VALUE', 'SET_BY_OLD_VALUE_AGAIN'].map((name) => ({ name, actor: `token:${token.tokenId}`, apiTokenId: token.tokenId })),
      chain: true,
    })
  })

  test('renewing a rule keeps its id, moves its expiry, fetches its keys again and makes it the renewing admin\'s', async () => {
    const owner = await createTestUser({ name: 'Rule Owner' })
    const [membership] = await getDb().insert(schema.orgMember).values({ orgId, userId: owner.user.id, role: 'admin' }).returning({ id: schema.orgMember.id })
    await grantAdmin(owner.token, Date.now() + 10 * 60_000)
    const { id } = await rule({ name: 'Renewed', subject: 'renewed' }, { userId: owner.user.id, sessionId: await sessionIdOf(owner.token) })
    await getDb().update(schema.trustRule).set({ expiresAt: Date.now() + DAY }).where(orm.eq(schema.trustRule.id, id))
    await getDb().update(schema.orgMember).set({ role: 'member' }).where(orm.eq(schema.orgMember.id, membership!.id))
    const ownerDemoted = await exchange({ token: await signed({ sub: 'renewed' }) })
    const beforeRenewal = await fetches()
    await renewTrustRule({ ...adminLogin, ownHost: 'e.ly', ruleId: id, expiresInDays: 30 })
    const fetched = await fetches() - beforeRenewal
    const renewed = await exchange({ token: await signed({ sub: 'renewed' }) })
    const afterFirst = (await getDb().query.trustRule.findFirst({ where: { id } }))!
    // Expired: renewed all the same, and the log says so
    await getDb().update(schema.trustRule).set({ expiresAt: Date.now() - 1000 }).where(orm.eq(schema.trustRule.id, id))
    const whileExpired = (await exchange({ token: await signed({ sub: 'renewed' }) })).status
    await renewTrustRule({ ...adminLogin, ownHost: 'e.ly', ruleId: id, expiresInDays: 90 })
    const events = (await eventsOf(id)).filter((event) => event.kind === 'rule.renewed')
    expect({
      ownerDemoted: ownerDemoted.body.error,
      fetched,
      renewed: { status: renewed.status, minutes: Math.round((renewed.body.expiresAt! - Date.now()) / 60_000), ruleId: renewed.body.ruleId },
      afterFirst: { createdBy: afterFirst.createdBy, renewals: afterFirst.renewals, days: Math.round((afterFirst.expiresAt - Date.now()) / DAY), renewedAt: afterFirst.renewedAt !== null },
      whileExpired,
      afterExpired: (await exchange({ token: await signed({ sub: 'renewed' }) })).status,
      renewals: (await getDb().query.trustRule.findFirst({ where: { id }, columns: { renewals: true } }))!.renewals,
      details: events.map((event) => ({ wasExpired: event.details.wasExpired, previousOwner: event.details.previousOwner, actor: event.actor })),
    }).toEqual({
      ownerDemoted: 'The admin who owns this trust rule no longer is one: another admin has to renew it on the project\'s Machines tab',
      fetched: 1,
      renewed: { status: 200, minutes: 60, ruleId: id },
      afterFirst: { createdBy: admin.user.id, renewals: 1, days: 30, renewedAt: true },
      whileExpired: 403,
      afterExpired: 200,
      renewals: 2,
      details: [
        { wasExpired: false, previousOwner: { id: owner.user.id, name: 'Rule Owner' }, actor: `user:${admin.user.id}` },
        { wasExpired: true, previousOwner: { id: admin.user.id, name: 'Renewal Admin' }, actor: `user:${admin.user.id}` },
      ],
    })
  })

  test('only an org admin with their passkey renews a rule, a protected one for 90 days at most, and not while its issuer names another', async () => {
    const newAdmin = await createTestUser({ name: 'Renewal Admin Too' })
    await getDb().insert(schema.orgMember).values({ orgId, userId: newAdmin.user.id, role: 'admin' })
    const { id } = await rule({ name: 'Protected deploy', subject: 'protected-renewal', environmentIds: [prod], protectedAccess: true, expiresInDays: 90 })
    const expiresAt = Date.now() + 5 * DAY
    const [liar] = await getDb().insert(schema.trustRule).values({
      projectId, name: 'Liar', issuer: 'https://liar.test', jwksUri: 'https://issuer.test/jwks', jwks: { keys: [] }, audience: AUDIENCE,
      subject: 'liar', claims: {}, environmentIds: [dev], createdBy: admin.user.id, expiresAt,
    }).returning({ id: schema.trustRule.id })
    const renew = (ruleId: string, expiresInDays: number, by: Login = adminLogin) => outcome(renewTrustRule({ ...by, ownHost: 'e.ly', ruleId, expiresInDays }))
    expect({
      member: await renew(id, 30, memberLogin),
      adminWithoutPasskey: await renew(id, 30, { userId: newAdmin.user.id, sessionId: await sessionIdOf(newAdmin.token) }),
      protectedForAYear: await renew(id, 365),
      protectedFor90Days: await renew(id, 90),
      liar: await renew(liar!.id, 30),
      liarUnchanged: await getDb().query.trustRule.findFirst({ where: { id: liar!.id }, columns: { expiresAt: true, renewals: true } }),
      deleted: await renew('01NOTARULE', 30),
    }).toEqual({
      member: 'Only admins can do this',
      adminWithoutPasskey: 'step-up:admin',
      protectedForAYear: 'A rule for protected environments expires after 90 days at most',
      protectedFor90Days: 'ok',
      liar: 'The discovery document of https://liar.test names another issuer: https://issuer.test',
      liarUnchanged: { expiresAt, renewals: 0 },
      deleted: 'Trust rule not found',
    })
  })

  test('the renewal dialog shows how a rule was used, which workloads used it, and what looks stale', async () => {
    const { id } = await rule({ name: 'Evidence', subject: 'evidence' })
    for (const [actor, ref] of [['alice', 'refs/heads/main'], ['bob', 'refs/heads/main'], ['alice', 'refs/tags/v1']]) {
      expect((await exchange({ token: await signed({ sub: 'evidence', repository: 'acme/api', actor, ref, event_name: 'push', runner_environment: 'github-hosted', run_id: '1', run_attempt: '1' }) })).status).toBe(200)
    }
    const insertRule = (values: Partial<typeof schema.trustRule.$inferInsert>) => getDb().insert(schema.trustRule).values({
      projectId, name: 'Stale', issuer: ISSUER, jwks: { keys: [{ kid: 'k1' }] }, audience: AUDIENCE, subject: 'stale', claims: {}, environmentIds: [dev],
      createdBy: admin.user.id, expiresAt: Date.now() + DAY, ...values,
    }).returning({ id: schema.trustRule.id })
    const [old] = await insertRule({ createdAt: Date.now() - 400 * DAY })
    const [idle] = await insertRule({ lastUsedAt: Date.now() - 90 * DAY })
    const [github] = await insertRule({ issuer: GITHUB_ISSUER, subject: 'repo:acme/api:ref:refs/heads/main', protectedAccess: true, lastUsedAt: Date.now() })
    const evidence = await trustRuleEvidence({ userId: admin.user.id, ruleId: id })
    const warnings = async (ruleId: string) => (await trustRuleEvidence({ userId: admin.user.id, ruleId })).warnings
    expect({
      exchanges: { ...evidence.exchanges, last: evidence.exchanges.last.map((token) => token.name) },
      seen: evidence.seen,
      keys: evidence.keys.discovered,
      warnings: evidence.warnings,
      old: await warnings(old!.id),
      idle: await warnings(idle!.id),
      github: await warnings(github!.id),
      member: await outcome(trustRuleEvidence({ userId: member.user.id, ruleId: id })),
    }).toEqual({
      exchanges: { total: 3, lastMonth: 3, last: ['acme/api refs/tags/v1 run 1.1', 'acme/api refs/heads/main run 1.1', 'acme/api refs/heads/main run 1.1'] },
      seen: [
        { label: 'actors', values: ['alice', 'bob'] },
        { label: 'refs', values: ['refs/heads/main', 'refs/tags/v1'] },
        { label: 'events', values: ['push'] },
        { label: 'runners', values: ['github-hosted'] },
        { label: 'repositories', values: ['acme/api'] },
      ],
      keys: true,
      warnings: [],
      old: ['Never used: no workload has got a token under it. Delete it instead?', 'Made over a year ago: consider making it again with today\'s IDs.'],
      idle: ['Not used in 60 days. Delete it instead?'],
      github: [
        'Its subject names the repository, not its ID: a repository that takes over the name after a rename would match.',
        'Without a GitHub environment, anyone who can push to the branch reads these environments. Name an environment with required reviewers.',
      ],
      member: 'Only admins can do this',
    })
  })

  test('the API says when a token stops working, and warns in the last quarter of its life, 14 days at most', async () => {
    const fresh = await tokenAged({ name: 'Fresh', daysAgo: 0, daysLeft: 90 })
    const threeDays = await tokenAged({ name: 'Three days', daysAgo: 87, daysLeft: 3 })
    const halfDays = await tokenAged({ name: 'Half days', daysAgo: 87.5, daysLeft: 2.5 })
    const weekly = await tokenAged({ name: 'Weekly', daysAgo: 4, daysLeft: 3 })
    const scoped = await tokenAged({ name: 'Scoped', daysAgo: 87, daysLeft: 3, environmentIds: [dev] })
    const regenerated = await insertApiToken({ name: 'Regenerated', projectId, createdBy: admin.user.id, expiresAt: Date.now() + 90 * DAY })
    const { previousExpiresAt } = await regenerate(regenerated.tokenId)
    const expired = await insertApiToken({ name: 'Expired', projectId, createdBy: admin.user.id, expiresAt: Date.now() - 1000 })
    // A workload's token under a 30-day rule with 5 days left
    const { id } = await rule({ name: 'Header rule', subject: 'header-rule' })
    const ruleExpiresAt = Date.now() + 5 * DAY
    await getDb().update(schema.trustRule).set({ createdAt: Date.now() - 25 * DAY, expiresAt: ruleExpiresAt }).where(orm.eq(schema.trustRule.id, id))
    const exchanged = await exchange({ token: await signed({ sub: 'header-rule' }) })
    const headers = async (key: string, environmentId = dev) => {
      const { status, expires, warning } = await read(key, { environmentId })
      return { status, expires, warning }
    }
    // ESO's routes, with the token as Basic auth user name
    const doppler = await app.handle(new Request('http://e.ly/v3/projects', { headers: { authorization: `Basic ${btoa(`${threeDays.key}:`)}` } }))
    expect({
      fresh: await headers(fresh.key),
      threeDays: await headers(threeDays.key),
      halfDays: (await headers(halfDays.key)).warning,
      weekly: (await headers(weekly.key)).warning,
      workload: await headers(exchanged.body.token!),
      exchange: exchanged.warning,
      previous: await headers(regenerated.key),
      refused: await headers(scoped.key, prod),
      expired: await headers(expired.key),
      invalid: await headers('sig_nothing'),
      doppler: { status: doppler.status, warning: doppler.headers.get('sigillo-warning') },
    }).toEqual({
      fresh: { status: 200, expires: rfc3339(fresh.expiresAt), warning: null },
      threeDays: { status: 200, expires: rfc3339(threeDays.expiresAt), warning: `token-expiry; expires=${rfc3339(threeDays.expiresAt)}; days=3` },
      halfDays: `token-expiry; expires=${rfc3339(halfDays.expiresAt)}; days=3`,
      // 7 days warn for their last 42 hours
      weekly: null,
      workload: { status: 200, expires: rfc3339(ruleExpiresAt), warning: `rule-expiry; rule=${id}; expires=${rfc3339(ruleExpiresAt)}; days=5` },
      exchange: `rule-expiry; rule=${id}; expires=${rfc3339(ruleExpiresAt)}; days=5`,
      previous: { status: 200, expires: rfc3339(previousExpiresAt!), warning: `token-regenerated; expires=${rfc3339(previousExpiresAt!)}; days=7` },
      refused: { status: 403, expires: rfc3339(scoped.expiresAt), warning: `token-expiry; expires=${rfc3339(scoped.expiresAt)}; days=3` },
      expired: { status: 401, expires: null, warning: null },
      invalid: { status: 401, expires: null, warning: null },
      doppler: { status: 200, warning: `token-expiry; expires=${rfc3339(threeDays.expiresAt)}; days=3` },
    })
  })

  test('the exchange answers with its rule\'s id and expiry, and ESO\'s login stays as it was', async () => {
    const { id } = await rule({ name: 'Exchange fields', subject: 'exchange-fields' })
    const { expiresAt } = (await getDb().query.trustRule.findFirst({ where: { id }, columns: { expiresAt: true } }))!
    const exchanged = await exchange({ token: await signed({ sub: 'exchange-fields' }) })
    const oidc = await app.handle(new Request('http://e.ly/v3/auth/oidc', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ identity: id, token: await signed({ sub: 'exchange-fields' }) }),
    }))
    expect({
      exchange: { ruleId: exchanged.body.ruleId, ruleExpiresAt: exchanged.body.ruleExpiresAt, keys: Object.keys(exchanged.body).sort(), warning: exchanged.warning },
      oidc: Object.keys(await oidc.json() as object).sort(),
    }).toEqual({
      exchange: { ruleId: id, ruleExpiresAt: expiresAt, keys: ['environmentIds', 'expiresAt', 'projectId', 'ruleExpiresAt', 'ruleId', 'token'], warning: null },
      oidc: ['expires_at', 'success', 'token'],
    })
  })

  test('the dashboard banner shows admins what expires in their organization, members the tokens they made', async () => {
    const bannerAdmin = await createTestUser({ name: 'Banner Admin' })
    const bannerMember = await createTestUser({ name: 'Banner Member' })
    const af = authedFetch(bannerAdmin.token)
    const bannerOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Banner Org' } })).id
    const bannerProject = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Banner', orgId: bannerOrg } })).id
    await getDb().insert(schema.orgMember).values({ orgId: bannerOrg, userId: bannerMember.user.id, role: 'member' })
    const now = Date.now()
    const insert = async (name: string, createdBy: string, createdAt: number, expiresAt: number | undefined, workload?: boolean) => {
      const { tokenId } = await insertApiToken({ name, projectId: bannerProject, createdBy, expiresAt })
      await getDb().update(schema.apiToken).set({ createdAt, ...(workload ? { workload: { kid: null, claims: {} } } : {}) }).where(orm.eq(schema.apiToken.id, tokenId))
    }
    await insert('Member CI', bannerMember.user.id, now - 87 * DAY, now + 3 * DAY)
    await insert('Not yet', bannerAdmin.user.id, now - 30 * DAY, now + 60 * DAY)
    await insert('Old laptop', bannerAdmin.user.id, now - 400 * DAY, undefined)
    await insert('Gone', bannerAdmin.user.id, now - 90 * DAY, now - DAY)
    await insert('Workload', bannerAdmin.user.id, now - 30 * 60_000, now + 30 * 60_000, true)
    await getDb().insert(schema.trustRule).values({
      projectId: bannerProject, name: 'k3s pods', issuer: ISSUER, jwks: { keys: [] }, audience: AUDIENCE, subject: 'pods', claims: {}, environmentIds: [],
      createdBy: bannerAdmin.user.id, createdAt: now - 28 * DAY, expiresAt: now + 2 * DAY,
    })
    const orgs = (role: 'admin' | 'member') => [{ id: bannerOrg, role }]
    const list = async (userId: string, role: 'admin' | 'member') => (await expiringCredentials({ userId, orgs: orgs(role), now }))
      .map(({ kind, name, projectName, when }) => `${kind} ${name} (${projectName}, ${when})`)
    const banner = (dismissed: string | null) => expiryBanner({ userId: bannerAdmin.user.id, orgs: orgs('admin'), dismissed, now })
    const admin = await list(bannerAdmin.user.id, 'admin')
    const member = await list(bannerMember.user.id, 'member')
    const shown = (await banner(null))!
    const dismissedForIt = await banner(shown.dismissKey)
    // Something expiring sooner brings it back
    await insert('Sooner', bannerAdmin.user.id, now - 89 * DAY, now + DAY)
    const afterSooner = await banner(shown.dismissKey)
    expect({
      admin,
      member,
      shown: { count: shown.items.length, more: shown.more, dismissKey: shown.dismissKey },
      dismissedForIt,
      afterSooner: afterSooner?.items.map((item) => item.name),
    }).toEqual({
      admin: ['trust rule k3s pods (Banner, in 2 days)', 'token Member CI (Banner, in 3 days)', 'token Old laptop (Banner, never expires)'],
      member: ['token Member CI (Banner, in 3 days)'],
      shown: { count: 3, more: 0, dismissKey: String(now + 2 * DAY) },
      dismissedForIt: null,
      afterSooner: ['Sooner', 'k3s pods', 'Member CI', 'Old laptop'],
    })
  })

  test('a token\'s expiry reads the same everywhere: a quarter of its lifetime, 14 days at most', () => {
    const at = Date.UTC(2026, 9, 1)
    const expiry = (lifetimeDays: number, leftHours: number) => describeExpiry({ expiresAt: at + leftHours * 3_600_000, lifetimeStart: at + leftHours * 3_600_000 - lifetimeDays * DAY, now: at })
    expect({
      weekOutside: expiry(7, 43),
      weekInside: expiry(7, 41),
      monthInside: expiry(30, 7 * 24),
      yearOutside: expiry(365, 15 * 24),
      yearInside: expiry(365, 13 * 24),
      lastMinutes: expiry(90, 0.5),
      expired: expiry(90, -1),
      never: describeExpiry({ expiresAt: null, lifetimeStart: at, now: at }),
    }).toEqual({
      weekOutside: { text: 'in 43 hours', level: 'ok' },
      weekInside: { text: 'in 41 hours', level: 'warning' },
      monthInside: { text: 'in 7 days', level: 'warning' },
      yearOutside: { text: 'in 15 days', level: 'ok' },
      yearInside: { text: 'in 13 days', level: 'warning' },
      lastMinutes: { text: 'in 30 minutes', level: 'warning' },
      expired: { text: 'expired', level: 'expired' },
      never: { text: 'never expires', level: 'warning' },
    })
  })

  test('a token\'s name can\'t carry terminal control characters', async () => {
    expect(await outcome(createToken({ ...adminLogin, name: 'CI\u001b[2J', projectId, expiresInDays: 30 }))).toBe('Names can\'t contain control characters')
  })

  test('every change to what reaches secrets writes its security log row, never a value or a token', async () => {
    const logAdmin = await createTestUser({ name: 'Log Admin' })
    const logMember = await createTestUser({ name: 'Log Member' })
    const af = authedFetch(logAdmin.token)
    const logOrg = assertOk(await af('/api/v0/orgs', { method: 'POST', body: { name: 'Log Org' } })).id
    const logProject = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Logged', orgId: logOrg } })).id
    const doomedProject = assertOk(await af('/api/v0/projects', { method: 'POST', body: { name: 'Doomed', orgId: logOrg } })).id
    const env = (id: string) => af('/api/v0/projects/:projectId/environments/:id', { params: { projectId: logProject, id } }).then(assertOk)
    const [logDev, logPreview] = [(await env('dev')).id, (await env('preview')).id]
    const [membership] = await getDb().insert(schema.orgMember).values({ orgId: logOrg, userId: logMember.user.id, role: 'member' }).returning()
    await grantAdmin(logAdmin.token, Date.now() + 10 * 60_000)
    const by = { userId: logAdmin.user.id, sessionId: await sessionIdOf(logAdmin.token), request: new Request('http://e.ly', { headers: { 'cf-connecting-ip': '203.0.113.9' } }) }

    const made = await createToken({ ...by, name: 'Logged CI', projectId: logProject, expiresInDays: 30 })
    await regenerateToken({ ...by, tokenId: made.id, prefix: (await tokenRow(made.id)).prefix, expiresInDays: 30, graceDays: 1 })
    await stopPreviousValue({ ...by, tokenId: made.id })
    await deleteToken({ ...by, tokenId: made.id })
    const { id: ruleId } = await createTrustRule({ ...by, ownHost: 'e.ly', rule: {
      projectId: logProject, name: 'Logged rule', issuer: 'https://k8s.test', jwks: JSON.stringify({ keys: [publicOf(workerEnv.TEST_ISSUER_KEYS.ec)] }),
      audience: AUDIENCE, subject: 'logged', claims: {}, environmentIds: [], protectedAccess: false, expiresInDays: 30,
    } })
    await replaceTrustRuleKeys({ ...by, ruleId, jwks: JSON.stringify({ keys: [publicOf(workerEnv.TEST_ISSUER_KEYS.rsa)] }) })
    await renewTrustRule({ ...by, ownHost: 'e.ly', ruleId, expiresInDays: 90 })
    // Refused: nothing is logged
    const refused = await outcome(deleteTrustRule({ userId: logMember.user.id, sessionId: await sessionIdOf(logMember.token), ruleId }))
    await deleteTrustRule({ ...by, ruleId })
    await appendSecretEvents({ author: { ...by, apiTokenId: null }, events: [{ environmentId: logDev, name: 'PASSWORD', operation: 'set', value: 'first-value' }] })
    await appendSecretEvents({ author: { ...by, apiTokenId: null }, events: [{ environmentId: logDev, name: 'PASSWORD', operation: 'set', value: 'second-value' }] })
    await purgeOldValues({ environmentId: logDev, author: { ...by, apiTokenId: null }, request: by.request })
    await setEnvironmentProtection({ request: by.request, environmentId: logDev, protect: true, author: { ...by, apiTokenId: null } })
    await setEnvironmentProtection({ request: by.request, environmentId: logDev, protect: false, author: { ...by, apiTokenId: null } })
    const call = (path: string) => app.handle(new Request(`http://e.ly${path}`, { method: 'DELETE', headers: { authorization: `Bearer ${logAdmin.token}`, 'cf-connecting-ip': '203.0.113.9' } }))
    expect((await call(`/api/v0/projects/${logProject}/environments/${logPreview}`)).status).toBe(200)
    expect((await call(`/api/v0/projects/${doomedProject}`)).status).toBe(200)
    await setOrgMemberRole({ member: membership!, role: 'admin', by })
    await resetMemberPasskeys({ request: by.request, actor: by, userId: logMember.user.id })
    await deleteOrgMember({ ...membership!, role: 'admin' }, by)

    const rows = await getDb().query.securityEvent.findMany({ where: { orgId: logOrg } })
    const text = JSON.stringify(rows)
    expect({
      refused,
      kinds: rows.map((row) => row.kind).sort(),
      subjects: [...new Set(rows.map((row) => `${row.kind} ${row.projectName ?? '-'} ${row.subjectName}`))].sort(),
      everyRow: [...new Set(rows.map((row) => `${row.actor} ${row.actorName} ${row.ipAddress}`))],
      details: Object.fromEntries(rows.filter((row) => ['environment.deleted', 'member.removed', 'member.role_changed', 'values.purged', 'passkeys.reset', 'rule.keys_replaced'].includes(row.kind))
        .map((row) => [`${row.kind} ${row.projectName ?? '-'} ${row.subjectName}`, row.details])),
      noSecrets: ['first-value', 'second-value', 'sig_', 'eyJ'].filter((secret) => text.includes(secret)),
    }).toEqual({
      refused: 'Only admins can do this',
      kinds: [
        'environment.deleted', 'environment.deleted', 'environment.deleted', 'environment.deleted',
        'environment.protected', 'environment.unprotected',
        'member.removed', 'member.role_changed', 'passkeys.reset',
        'rule.created', 'rule.deleted', 'rule.keys_replaced', 'rule.renewed',
        'token.created', 'token.deleted', 'token.previous_stopped', 'token.regenerated',
        'values.purged',
      ],
      subjects: [
        'environment.deleted Doomed Dev', 'environment.deleted Doomed Preview', 'environment.deleted Doomed Prod', 'environment.deleted Logged Preview',
        'environment.protected Logged Dev', 'environment.unprotected Logged Dev',
        'member.removed - Log Member', 'member.role_changed - Log Member', 'passkeys.reset - Log Member',
        'rule.created Logged Logged rule', 'rule.deleted Logged Logged rule', 'rule.keys_replaced Logged Logged rule', 'rule.renewed Logged Logged rule',
        'token.created Logged Logged CI', 'token.deleted Logged Logged CI', 'token.previous_stopped Logged Logged CI', 'token.regenerated Logged Logged CI',
        'values.purged Logged Dev',
      ],
      everyRow: [`user:${logAdmin.user.id} Log Admin 203.0.113.9`],
      details: {
        'environment.deleted Doomed Dev': { protected: false, withProject: true },
        'environment.deleted Doomed Preview': { protected: false, withProject: true },
        'environment.deleted Doomed Prod': { protected: false, withProject: true },
        'environment.deleted Logged Preview': { protected: false, withProject: false },
        'member.removed - Log Member': { role: 'admin', left: false },
        'member.role_changed - Log Member': { role: 'admin', previousRole: 'member' },
        'passkeys.reset - Log Member': { passkeys: 0 },
        'rule.keys_replaced Logged Logged rule': { keyIds: ['rsa-1'] },
        'values.purged Logged Dev': { values: 1, names: 1 },
      },
      noSecrets: [],
    })
  })
})
