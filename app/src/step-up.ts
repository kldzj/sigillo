// Step-up: a person approves with a passkey. An access approval lets one
// session read and change protected environments; an admin approval lets it
// run admin actions in an organization with protected environments, and
// manage its own passkeys.
// better-auth's passkey plugin adds and manages passkeys; its own passkey
// sign-in would create a new session and accepts a passkey without user
// verification, so approvals are verified here, on the same passkey table,
// with user verification required and no session created.

import * as orm from 'drizzle-orm'
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server'
import { getDb, schema } from 'db'
import { getRequestOrigin, getUserEnvironmentAccess, getProjectMemberAccess, requireOrgMember } from './db.ts'
import { MACHINE_TOKEN_MAX_DAYS } from './lib/utils.ts'

// How long an approval lasts for the session, and how long a request waits
const GRANT_MS = { access: 15 * 60 * 1000, admin: 5 * 60 * 1000 }
const REQUEST_MS = 10 * 60 * 1000
// The first passkey needs a sign-in this recent instead of an approval
const FRESH_SIGN_IN_MS = 5 * 60 * 1000

export type Purpose = 'access' | 'admin'

// Where passkeys belong: the hostname and origin of this request
export function relyingParty(request: Request) {
  const origin = getRequestOrigin(request)
  return { origin, rpID: new URL(origin).hostname }
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// A challenge for the user's own passkeys
export async function passkeyChallenge({ userId, rpID }: { userId: string; rpID: string }): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const passkeys = await getDb().query.passkey.findMany({ where: { userId }, columns: { credentialID: true, transports: true } })
  return generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.credentialID,
      transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransport[] : undefined,
    })),
  })
}

// Whether the response is a user-verified signature of the challenge by one
// of the user's passkeys. Advances the passkey's counter when it is.
export async function verifyPasskey({ userId, response, expectedChallenge, origin, rpID }: {
  userId: string
  response: AuthenticationResponseJSON
  expectedChallenge: string
  origin: string
  rpID: string
}): Promise<boolean> {
  const db = getDb()
  const passkey = await db.query.passkey.findFirst({ where: { credentialID: response.id, userId } })
  if (!passkey) return false
  let verified = false
  let newCounter = passkey.counter
  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.credentialID,
        publicKey: fromBase64(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransport[] : undefined,
      },
      requireUserVerification: true,
    })
    verified = verification.verified
    newCounter = verification.authenticationInfo.newCounter
  } catch {
    return false
  }
  if (!verified) return false
  await db.update(schema.passkey).set({ counter: newCounter }).where(orm.eq(schema.passkey.id, passkey.id))
  return true
}

// ── The gate ────────────────────────────────────────────────────────

export class StepUpRequiredError extends Error {
  constructor(readonly purpose: Purpose, readonly environmentIds: string[] = [], readonly machineTokenRequired = false) {
    super(machineTokenRequired
      ? 'this environment is protected: only a machine token can use it'
      : purpose === 'access'
        ? 'this environment is protected: approve with your passkey'
        : 'this needs an approval with your passkey')
    this.name = 'StepUpRequiredError'
  }

  get code() {
    return this.machineTokenRequired ? 'MACHINE_TOKEN_REQUIRED' : 'STEP_UP_REQUIRED'
  }
}

export type Reader = { userId: string | null; apiTokenId: string | null; sessionId?: string | null }

// Reading or changing a protected environment needs an access grant for the
// session, or a machine token. recordSecretRead and appendSecretEvents call
// this, and every read and write of values goes through them. It only ever
// denies on top of the usual access rules.
export async function requireStepUp({ environmentId, reader }: { environmentId: string; reader: Reader }) {
  await requireProtectedAccess({ environmentIds: [environmentId], reader, known: true })
}

// The same for several environments at once; only the protected ones need
// it. One error lists every environment still missing an approval, so the
// browser asks for the passkey once.
export async function requireProtectedAccess({ environmentIds, reader, known = false }: {
  environmentIds: string[]
  reader: Reader
  // The environments are known to be protected
  known?: boolean
}) {
  const db = getDb()
  const ids = [...new Set(environmentIds)]
  const protectedIds = known || ids.length === 0
    ? ids
    : (await db.query.environment.findMany({ where: { id: { in: ids }, protected: true }, columns: { id: true } })).map((env) => env.id)
  if (protectedIds.length === 0) return
  if (reader.apiTokenId) {
    // A machine token acts for its creator, who must still be an org admin
    const token = await db.query.apiToken.findFirst({ where: { id: reader.apiTokenId }, columns: { protectedAccess: true, projectId: true, createdBy: true } })
    const creator = token?.protectedAccess && token.createdBy ? await getProjectMemberAccess(token.createdBy, token.projectId) : null
    if (creator?.role !== 'admin') throw new StepUpRequiredError('access', protectedIds, true)
    return
  }
  if (!reader.userId || !reader.sessionId) throw new StepUpRequiredError('access', protectedIds)
  const grants = await db.query.stepUpGrant.findMany({
    where: { sessionId: reader.sessionId, userId: reader.userId, purpose: 'access', expiresAt: { gt: Date.now() } },
    columns: { environmentIds: true },
  })
  const missing = protectedIds.filter((id) => !grants.some((grant) => grant.environmentIds.includes(id)))
  if (missing.length) throw new StepUpRequiredError('access', missing)
}

async function hasAdminGrant({ userId, sessionId }: { userId: string; sessionId: string }) {
  const grant = await getDb().query.stepUpGrant.findFirst({
    where: { sessionId, userId, purpose: 'admin', expiresAt: { gt: Date.now() } },
    columns: { id: true },
  })
  return !!grant
}

// An org admin, with an admin approval for the session when the org has a
// protected environment, so a stolen admin session can't invite someone,
// change roles or access, or delete. Orgs without protection keep today's rules.
export async function requireOrgAdmin({ userId, sessionId, orgId }: { userId: string; sessionId: string; orgId: string }) {
  const { role } = await requireOrgMember(userId, orgId)
  if (role !== 'admin') throw new Error('Only admins can do this')
  const [protectedEnv] = await getDb()
    .select({ id: schema.environment.id })
    .from(schema.environment)
    .innerJoin(schema.project, orm.eq(schema.project.id, schema.environment.projectId))
    .where(orm.and(orm.eq(schema.project.orgId, orgId), orm.eq(schema.environment.protected, true)))
    .limit(1)
  if (protectedEnv && !await hasAdminGrant({ userId, sessionId })) throw new StepUpRequiredError('admin')
}

// A machine token reads and changes protected environments without a
// passkey, so making or deleting one is an admin action (with an admin
// approval once the org has a protected environment), and it expires after
// 90 days at most. It stops working when its creator is no longer an admin.
export async function requireMachineTokenApproval({ userId, sessionId, projectId, expiresInDays }: {
  userId: string
  sessionId: string
  projectId: string
  expiresInDays: number
}) {
  if (expiresInDays > MACHINE_TOKEN_MAX_DAYS) throw new Error(`A machine token expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  const project = await getDb().query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } })
  if (!project) throw new Error('Project not found')
  await requireOrgAdmin({ userId, sessionId, orgId: project.orgId })
}

// ── Requests and approvals ──────────────────────────────────────────

// Eight letters without vowels, so a code never spells a word, as XXXX-XXXX
function newUserCode(): string {
  const letters = 'BCDFGHJKLMNPQRSTVWXZ'
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  const code = [...bytes].map((b) => letters[b % letters.length]).join('')
  return `${code.slice(0, 4)}-${code.slice(4)}`
}

export class NoPasskeyError extends Error {
  constructor() {
    super('Add a passkey first: user menu → Passkeys')
    this.name = 'NoPasskeyError'
  }
}

// Opens a request for the session: access to the environments, or admin
// actions. The CLI gets a code that its user types on /approve; the browser
// approves its own.
export async function createStepUpRequest({ request, userId, sessionId, environmentIds, withCode, purpose = 'access' }: {
  request: Request
  userId: string
  sessionId: string
  environmentIds: string[]
  withCode: boolean
  purpose?: Purpose
}) {
  const ids = [...new Set(environmentIds)]
  if (purpose === 'access' && ids.length === 0) throw new Error('No environments to approve')
  // Only environments the user may read at all
  for (const id of ids) {
    if (!await getUserEnvironmentAccess({ userId, environmentRef: id })) throw new Error('Environment not found')
  }
  const [row] = await getDb().insert(schema.stepUpRequest).values({
    userId,
    sessionId,
    environmentIds: ids,
    purpose,
    userCode: withCode ? newUserCode() : null,
    ipAddress: request.headers.get('cf-connecting-ip'),
    country: request.headers.get('cf-ipcountry'),
    userAgent: request.headers.get('user-agent'),
    expiresAt: Date.now() + REQUEST_MS,
  }).returning({ id: schema.stepUpRequest.id, userCode: schema.stepUpRequest.userCode, expiresAt: schema.stepUpRequest.expiresAt })
  return row!
}

async function pendingRequest(where: { id?: string; userCode?: string; userId: string }) {
  const row = await getDb().query.stepUpRequest.findFirst({ where: { ...where, status: 'pending', expiresAt: { gt: Date.now() } } })
  return row ?? null
}

// A pending access request of this user by the code typed on /approve, with
// what the page shows before anyone approves it
export async function findStepUpRequest({ userId, userCode }: { userId: string; userCode: string }) {
  const row = await pendingRequest({ userId, userCode: userCode.trim().toUpperCase() })
  if (!row || row.purpose !== 'access') return null
  const environments = await getDb().query.environment.findMany({
    where: { id: { in: row.environmentIds } },
    columns: { id: true, name: true },
    with: { project: { columns: { name: true } } },
  })
  return {
    id: row.id,
    environments: environments.map((env) => ({ id: env.id, name: env.name, project: env.project?.name ?? '' })),
    ipAddress: row.ipAddress,
    country: row.country,
    userAgent: row.userAgent,
    createdAt: row.createdAt,
  }
}

// The passkey challenge for approving a request of this user
export async function approvalOptions({ request, requestId, userId }: { request: Request; requestId: string; userId: string }) {
  const row = await pendingRequest({ id: requestId, userId })
  if (!row) throw new Error('This request expired or was already approved')
  if (!await getDb().query.passkey.findFirst({ where: { userId }, columns: { id: true } })) throw new NoPasskeyError()
  const options = await passkeyChallenge({ userId, rpID: relyingParty(request).rpID })
  await getDb().update(schema.stepUpRequest).set({ challenge: options.challenge }).where(orm.eq(schema.stepUpRequest.id, row.id))
  return options
}

// Approves the request with the passkey's answer to its challenge: the
// session that asked gets its grant
export async function approveStepUpRequest({ request, requestId, userId, response }: {
  request: Request
  requestId: string
  userId: string
  response: AuthenticationResponseJSON
}): Promise<boolean> {
  const row = await pendingRequest({ id: requestId, userId })
  if (!row?.challenge) return false
  const { origin, rpID } = relyingParty(request)
  if (!await verifyPasskey({ userId, response, expectedChallenge: row.challenge, origin, rpID })) return false
  const db = getDb()
  const now = Date.now()
  await db.batch([
    db.update(schema.stepUpRequest).set({ status: 'approved', challenge: null }).where(orm.eq(schema.stepUpRequest.id, row.id)),
    db.insert(schema.stepUpGrant).values({
      userId, sessionId: row.sessionId, purpose: row.purpose, environmentIds: row.environmentIds, createdAt: now, expiresAt: now + GRANT_MS[row.purpose],
    }),
  ])
  return true
}

// For the CLI polling its own request
export async function stepUpRequestStatus({ requestId, sessionId }: { requestId: string; sessionId: string }) {
  const row = await getDb().query.stepUpRequest.findFirst({ where: { id: requestId, sessionId }, columns: { status: true, expiresAt: true } })
  if (!row) return null
  return row.status === 'approved' ? 'approved' : row.expiresAt > Date.now() ? 'pending' : 'expired'
}

// ── Adding passkeys ─────────────────────────────────────────────────

// The first passkey needs a session made by a Google sign-in in the last 5
// minutes, so an old stolen session can't add one, not even through a CLI
// login it approves; every further one an admin approval with an existing
// passkey.
export function isFreshSignIn({ signedIn, sessionCreatedAt }: { signedIn: boolean; sessionCreatedAt: number }) {
  return signedIn && Date.now() - sessionCreatedAt < FRESH_SIGN_IN_MS
}

export async function canAddPasskey({ userId, sessionId, signedIn, sessionCreatedAt }: { userId: string; sessionId: string; signedIn: boolean; sessionCreatedAt: number }) {
  const existing = await getDb().query.passkey.findFirst({ where: { userId }, columns: { id: true } })
  if (!existing) return isFreshSignIn({ signedIn, sessionCreatedAt })
  return hasAdminGrant({ userId, sessionId })
}

// An admin approval for the session, whatever the organization: removing one
// of your passkeys (so a stolen session can't clear them and add its own after
// a fresh sign-in), and turning protection off
export async function requireAdminApproval({ userId, sessionId }: { userId: string; sessionId: string }) {
  if (!await hasAdminGrant({ userId, sessionId })) throw new StepUpRequiredError('admin')
}

// An admin removes a member's passkeys, for a member who lost them. Passkeys
// belong to the person, not to one organization, so the admin must be an admin
// of every organization the member belongs to, with an admin approval where
// one has protected environments. The member is signed out everywhere, and
// adds new passkeys after a fresh Google sign-in.
export async function resetMemberPasskeys({ request, actor, userId }: {
  request: Request | null
  actor: { userId: string; sessionId: string }
  userId: string
}) {
  if (userId === actor.userId) throw new Error('Remove your own passkeys on the Passkeys page')
  const db = getDb()
  const memberships = await db.query.orgMember.findMany({ where: { userId }, columns: { orgId: true } })
  for (const { orgId } of memberships) {
    const admin = await db.query.orgMember.findFirst({ where: { orgId, userId: actor.userId }, columns: { role: true } })
    if (admin?.role !== 'admin') {
      throw new Error("They also belong to an organization you're not an admin of: an admin of each of their organizations can reset them")
    }
  }
  for (const { orgId } of memberships) await requireOrgAdmin({ ...actor, orgId })
  const passkeys = await db.query.passkey.findMany({ where: { userId }, columns: { name: true } })
  await db.batch([
    db.delete(schema.passkey).where(orm.eq(schema.passkey.userId, userId)),
    db.delete(schema.session).where(orm.eq(schema.session.userId, userId)),
  ])
  for (const passkey of passkeys) {
    await logPasskeyEvent({ request, userId, actor: `user:${actor.userId}`, action: 'removed', passkeyName: passkey.name })
  }
}

export async function logPasskeyEvent({ request, userId, actor, action, passkeyName }: {
  request: Request | null
  userId: string
  actor: string
  action: 'added' | 'removed'
  passkeyName: string | null
}) {
  await getDb().insert(schema.passkeyEvent).values({
    userId, actor, action, passkeyName, ipAddress: request?.headers.get('cf-connecting-ip') ?? null,
  })
}
