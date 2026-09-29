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
import { ForbiddenError, getOrgIdForProject, getRequestOrigin, getUserEnvironmentAccess, getProjectMemberAccess, requireOrgMember } from './db.ts'
import { MACHINE_TOKEN_MAX_DAYS, formatUserCode } from './lib/utils.ts'

// How long an approval lasts for the session, and how long a request waits
const GRANT_MS = { access: 15 * 60 * 1000, admin: 5 * 60 * 1000, enroll: 15 * 60 * 1000 }
const REQUEST_MS = 10 * 60 * 1000
// An admin may take longer to approve a member's first passkey
const ADMIN_REQUEST_MS = 24 * 60 * 60 * 1000
// The first passkey needs a sign-in this recent instead of an approval
const FRESH_SIGN_IN_MS = 5 * 60 * 1000

export type Purpose = 'access' | 'admin' | 'enroll'

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
  constructor(readonly purpose: 'access' | 'admin', readonly environmentIds: string[] = [], readonly machineTokenRequired = false) {
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

async function hasGrant({ userId, sessionId, purpose }: { userId: string; sessionId: string; purpose: Purpose }) {
  const grant = await getDb().query.stepUpGrant.findFirst({
    where: { sessionId, userId, purpose, expiresAt: { gt: Date.now() } },
    columns: { id: true },
  })
  return !!grant
}

async function hasAdminGrant({ userId, sessionId }: { userId: string; sessionId: string }) {
  return hasGrant({ userId, sessionId, purpose: 'admin' })
}

// An org admin, with an admin approval for the session when the org has a
// protected environment, so a stolen admin session can't invite someone,
// change roles or access, or delete. Orgs without protection keep today's rules.
export async function requireOrgAdmin({ userId, sessionId, orgId }: { userId: string; sessionId: string; orgId: string }) {
  const { role } = await requireOrgMember(userId, orgId)
  if (role !== 'admin') throw new ForbiddenError('Only admins can do this')
  const [protectedEnv] = await getDb()
    .select({ id: schema.environment.id })
    .from(schema.environment)
    .innerJoin(schema.project, orm.eq(schema.project.id, schema.environment.projectId))
    .where(orm.and(orm.eq(schema.project.orgId, orgId), orm.eq(schema.environment.protected, true)))
    .limit(1)
  if (protectedEnv && !await hasAdminGrant({ userId, sessionId })) throw new StepUpRequiredError('admin')
}

// Deleting or renaming a protected environment, or the project it is in, is
// an admin action: someone who may only change its secrets could otherwise
// delete it along with its read log, or move it aside so that an
// unprotected one takes over its slug or name
export async function requireAdminForProtected({ userId, sessionId, environmentIds }: { userId: string; sessionId: string; environmentIds: string[] }) {
  if (environmentIds.length === 0) return
  const rows = await getDb()
    .select({ orgId: schema.project.orgId })
    .from(schema.environment)
    .innerJoin(schema.project, orm.eq(schema.project.id, schema.environment.projectId))
    .where(orm.and(orm.inArray(schema.environment.id, environmentIds), orm.eq(schema.environment.protected, true)))
  for (const orgId of new Set(rows.map((row) => row.orgId))) await requireOrgAdmin({ userId, sessionId, orgId })
}

// Renaming or deleting a project: someone who can open it, an admin when it
// has an admin-only environment, and one with a passkey when a protected one
export async function requireProjectChange({ userId, sessionId, projectId }: { userId: string; sessionId: string; projectId: string }) {
  const access = await getProjectMemberAccess(userId, projectId)
  if (!access || (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(projectId))) throw new ForbiddenError()
  const environments = await getDb().query.environment.findMany({ where: { projectId }, columns: { id: true, accessRole: true } })
  if (access.role !== 'admin' && environments.some((env) => env.accessRole === 'admin')) throw new ForbiddenError('admin access required for this environment')
  await requireAdminForProtected({ userId, sessionId, environmentIds: environments.map((env) => env.id) })
}

// Deleting a token stops whatever uses it: up to its creator, or an org admin
// (an admin action, with an admin approval once the org has a protected
// environment)
export async function requireTokenDeletion({ userId, sessionId, token }: { userId: string; sessionId: string; token: { createdBy: string; projectId: string } }) {
  if (token.createdBy === userId) return
  const access = await getProjectMemberAccess(userId, token.projectId)
  if (access?.role !== 'admin') throw new ForbiddenError('Only its creator or an org admin deletes a token')
  const orgId = await getOrgIdForProject(token.projectId)
  if (orgId) await requireOrgAdmin({ userId, sessionId, orgId })
}

// A machine token reads and changes protected environments without a
// passkey. Making one is an org admin's, approved with their passkey even
// while the organization has no protected environment: otherwise a stolen
// admin session could leave one behind that reads environments once they are
// protected. It expires after 90 days at most, and stops working when its
// creator is no longer an admin.
export async function requireMachineTokenApproval({ userId, sessionId, projectId, expiresInDays }: {
  userId: string
  sessionId: string
  projectId: string
  expiresInDays: number
}) {
  if (expiresInDays > MACHINE_TOKEN_MAX_DAYS) throw new Error(`A machine token expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  await requireMachineTokenDeletion({ userId, sessionId, projectId })
  if (!await hasAdminGrant({ userId, sessionId })) throw new StepUpRequiredError('admin')
}

// Deleting one stops whatever uses it: an admin action like any other
export async function requireMachineTokenDeletion({ userId, sessionId, projectId }: { userId: string; sessionId: string; projectId: string }) {
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
  return formatUserCode(code)
}

export class NoPasskeyError extends Error {
  constructor() {
    super('Add a passkey first: user menu → Passkeys')
    this.name = 'NoPasskeyError'
  }
}

// Opens a request for the session: access to the environments, or admin
// actions. The CLI gets a code that its user types on /approve; the browser
// approves its own. Only requestEnrollment asks to add a passkey, after its
// own checks: the purpose comes from the caller here.
export async function createStepUpRequest({ request, userId, sessionId, environmentIds, withCode, purpose = 'access' }: {
  request: Request
  userId: string
  sessionId: string
  environmentIds: string[]
  withCode: boolean
  purpose?: 'access' | 'admin'
}) {
  if (purpose !== 'access' && purpose !== 'admin') throw new Error('Unknown approval')
  const ids = [...new Set(environmentIds)]
  if (purpose === 'access' && ids.length === 0) throw new Error('No environments to approve')
  // Only environments the user may read at all
  for (const id of ids) {
    if (!await getUserEnvironmentAccess({ userId, environmentRef: id })) throw new ForbiddenError('Environment not found')
  }
  return insertRequest({ request, userId, sessionId, environmentIds: ids, withCode, purpose, lifetimeMs: REQUEST_MS })
}

async function insertRequest({ request, userId, sessionId, environmentIds, withCode, purpose, lifetimeMs }: {
  request: Request
  userId: string
  sessionId: string
  environmentIds: string[]
  withCode: boolean
  purpose: Purpose
  lifetimeMs: number
}) {
  const [row] = await getDb().insert(schema.stepUpRequest).values({
    userId,
    sessionId,
    environmentIds,
    purpose,
    userCode: withCode ? newUserCode() : null,
    ipAddress: request.headers.get('cf-connecting-ip'),
    country: request.headers.get('cf-ipcountry'),
    userAgent: request.headers.get('user-agent'),
    expiresAt: Date.now() + lifetimeMs,
  }).returning({ id: schema.stepUpRequest.id, userCode: schema.stepUpRequest.userCode, expiresAt: schema.stepUpRequest.expiresAt })
  return row!
}

async function pendingRequest(where: { id?: string; userCode?: string; userId: string }) {
  const row = await getDb().query.stepUpRequest.findFirst({ where: { ...where, status: 'pending', expiresAt: { gt: Date.now() } } })
  return row ?? null
}

// A pending request of this user by the code typed on /approve, access for
// the CLI or a passkey for another device, with what the page shows before
// anyone approves it
export async function findStepUpRequest({ userId, userCode }: { userId: string; userCode: string }) {
  const row = await pendingRequest({ userId, userCode: formatUserCode(userCode) })
  if (!row || row.purpose === 'admin') return null
  const environments = await getDb().query.environment.findMany({
    where: { id: { in: row.environmentIds } },
    columns: { id: true, name: true },
    with: { project: { columns: { name: true } } },
  })
  return {
    id: row.id,
    purpose: row.purpose,
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

// A session made by a Google sign-in in the last 5 minutes. An old stolen
// session is none, and neither is a CLI login it approves.
export function isFreshSignIn({ signedIn, sessionCreatedAt }: { signedIn: boolean; sessionCreatedAt: number }) {
  return signedIn && Date.now() - sessionCreatedAt < FRESH_SIGN_IN_MS
}

// Organizations whose admins approve this person's first passkey: those with
// a protected environment where another admin already has a passkey. None on
// a fresh instance, whose first admin enrolls with a fresh sign-in alone.
// Organizations they left or were removed from count too, so leaving one,
// adding a passkey and coming back doesn't get around its admins.
export async function passkeyApproverOrgs(userId: string): Promise<string[]> {
  const db = getDb()
  const [memberships, removals] = await Promise.all([
    db.query.orgMember.findMany({ where: { userId }, columns: { orgId: true } }),
    db.select({ orgId: schema.orgRemoval.orgId }).from(schema.orgRemoval).where(orm.eq(schema.orgRemoval.userId, userId)),
  ])
  const candidates = [...new Set([...memberships, ...removals].map((row) => row.orgId))]
  if (candidates.length === 0) return []
  const guarded = await db.selectDistinct({ orgId: schema.project.orgId })
    .from(schema.environment)
    .innerJoin(schema.project, orm.eq(schema.project.id, schema.environment.projectId))
    .where(orm.and(orm.inArray(schema.project.orgId, candidates), orm.eq(schema.environment.protected, true)))
  const orgIds: string[] = []
  for (const { orgId } of guarded) {
    const [admin] = await db.select({ id: schema.orgMember.id })
      .from(schema.orgMember)
      .innerJoin(schema.passkey, orm.eq(schema.passkey.userId, schema.orgMember.userId))
      .where(orm.and(orm.eq(schema.orgMember.orgId, orgId), orm.eq(schema.orgMember.role, 'admin'), orm.ne(schema.orgMember.userId, userId)))
      .limit(1)
    if (admin) orgIds.push(orgId)
  }
  return orgIds
}

// Adding a passkey: with an enroll grant for this session (approved on another
// device, or by an admin, and used up by the passkey it adds); a further one
// with an admin approval with an existing passkey; the first one with a fresh
// Google sign-in, unless an admin has to approve it.
export async function canAddPasskey(login: { userId: string; sessionId: string; signedIn: boolean; sessionCreatedAt: number }) {
  if (await hasGrant({ userId: login.userId, sessionId: login.sessionId, purpose: 'enroll' })) return true
  return canAddWithoutApproval(login)
}

// The same, as a passkey is being added: an approval to add one is used up
// right here, before the passkey is stored, so two registrations racing on
// one approval add one passkey
export async function claimPasskeyAddition(login: { userId: string; sessionId: string; signedIn: boolean; sessionCreatedAt: number }) {
  const [claimed] = await getDb().delete(schema.stepUpGrant).where(orm.and(
    orm.eq(schema.stepUpGrant.userId, login.userId), orm.eq(schema.stepUpGrant.sessionId, login.sessionId),
    orm.eq(schema.stepUpGrant.purpose, 'enroll'), orm.gt(schema.stepUpGrant.expiresAt, Date.now()),
  )).returning({ id: schema.stepUpGrant.id })
  return !!claimed || canAddWithoutApproval(login)
}

async function canAddWithoutApproval({ userId, sessionId, signedIn, sessionCreatedAt }: { userId: string; sessionId: string; signedIn: boolean; sessionCreatedAt: number }) {
  const existing = await getDb().query.passkey.findFirst({ where: { userId }, columns: { id: true } })
  if (existing) return hasAdminGrant({ userId, sessionId })
  return isFreshSignIn({ signedIn, sessionCreatedAt }) && (await passkeyApproverOrgs(userId)).length === 0
}

// Asks for an approval to add a passkey: with a code the person types on
// /approve on a device that has one of their passkeys, or, for a first
// passkey, for an admin to approve. Only from a Google sign-in of the last 5
// minutes, so an old stolen session can't ask for one.
export async function requestEnrollment({ request, userId, sessionId, signedIn, sessionCreatedAt, viaCode }: {
  request: Request
  userId: string
  sessionId: string
  signedIn: boolean
  sessionCreatedAt: number
  viaCode: boolean
}) {
  if (!isFreshSignIn({ signedIn, sessionCreatedAt })) throw new Error('Sign in again first: asking to add a passkey takes a sign-in from the last 5 minutes')
  const hasPasskey = !!await getDb().query.passkey.findFirst({ where: { userId }, columns: { id: true } })
  if (viaCode && !hasPasskey) throw new Error('Approving on another device takes a passkey there: you have none yet')
  if (!viaCode && (hasPasskey || (await passkeyApproverOrgs(userId)).length === 0)) throw new Error('Your passkey needs no admin approval')
  return insertRequest({ request, userId, sessionId, environmentIds: [], withCode: viaCode, purpose: 'enroll', lifetimeMs: viaCode ? REQUEST_MS : ADMIN_REQUEST_MS })
}

// A member's request for a first passkey. Each of their organizations that
// needs it approves it through one of its admins, never the member: an admin
// of one organization, maybe one made for the purpose, can't approve it for
// the others. Returns the organizations this approver answers for.
async function enrollmentForAdmin({ requestId, approver }: { requestId: string; approver: { userId: string; sessionId: string } }) {
  const db = getDb()
  const row = await db.query.stepUpRequest.findFirst({
    where: { id: requestId, purpose: 'enroll', userCode: { isNull: true }, status: 'pending', expiresAt: { gt: Date.now() } },
  })
  if (!row) throw new Error('This request expired or was already answered')
  if (row.userId === approver.userId) throw new Error('Another admin approves your own first passkey')
  const orgIds = await passkeyApproverOrgs(row.userId)
  // Only a first passkey that an admin has to approve: otherwise anyone
  // would pass the checks below
  const hasPasskey = !!await db.query.passkey.findFirst({ where: { userId: row.userId }, columns: { id: true } })
  if (orgIds.length === 0 || hasPasskey) throw new Error('This request needs no admin approval')
  const answering = (await db.query.orgMember.findMany({
    where: { userId: approver.userId, orgId: { in: orgIds }, role: 'admin' },
    columns: { orgId: true },
  })).map((member) => member.orgId)
  if (answering.length === 0) throw new Error('An admin of one of their organizations with protected environments approves it')
  // An admin action, with the admin approval these organizations need
  for (const orgId of answering) await requireOrgAdmin({ ...approver, orgId })
  return { row, orgIds, answering }
}

// Approves for the organizations this admin answers for. Once every one of
// them has, the member's session may add one passkey.
export async function approveEnrollment({ requestId, approver }: { requestId: string; approver: { userId: string; sessionId: string } }): Promise<{ waitingFor: number }> {
  const { row, orgIds, answering } = await enrollmentForAdmin({ requestId, approver })
  const db = getDb()
  const [first, ...rest] = answering.map((orgId) => db.insert(schema.enrollmentApproval).values({ requestId: row.id, orgId, approverId: approver.userId }).onConflictDoNothing())
  await db.batch([first!, ...rest])
  const approved = new Set((await db.select({ orgId: schema.enrollmentApproval.orgId }).from(schema.enrollmentApproval)
    .where(orm.eq(schema.enrollmentApproval.requestId, row.id))).map((approval) => approval.orgId))
  const waitingFor = orgIds.filter((orgId) => !approved.has(orgId)).length
  if (waitingFor > 0) return { waitingFor }
  // The approval that completes it answers the request, once
  const [answered] = await db.update(schema.stepUpRequest).set({ status: 'approved' })
    .where(orm.and(orm.eq(schema.stepUpRequest.id, row.id), orm.eq(schema.stepUpRequest.status, 'pending')))
    .returning({ id: schema.stepUpRequest.id })
  if (answered) {
    const now = Date.now()
    await db.insert(schema.stepUpGrant).values({ userId: row.userId, sessionId: row.sessionId, purpose: 'enroll', environmentIds: [], createdAt: now, expiresAt: now + GRANT_MS.enroll })
  }
  return { waitingFor: 0 }
}

export async function declineEnrollment({ requestId, approver }: { requestId: string; approver: { userId: string; sessionId: string } }) {
  const { row } = await enrollmentForAdmin({ requestId, approver })
  await getDb().delete(schema.stepUpRequest).where(orm.eq(schema.stepUpRequest.id, row.id))
}

// What the Passkeys page shows about approvals to add one: a request of this
// session still waiting, an approval ready to use, and whether a first
// passkey needs an admin
export async function enrollmentState({ userId, sessionId }: { userId: string; sessionId: string }) {
  const db = getDb()
  const [pending, approved, passkey] = await Promise.all([
    db.query.stepUpRequest.findFirst({
      where: { userId, sessionId, purpose: 'enroll', status: 'pending', expiresAt: { gt: Date.now() } },
      columns: { id: true, userCode: true, expiresAt: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    }),
    hasGrant({ userId, sessionId, purpose: 'enroll' }),
    db.query.passkey.findFirst({ where: { userId }, columns: { id: true } }),
  ])
  const approverOrgs = passkey ? [] : await passkeyApproverOrgs(userId)
  // For a request to admins: how many of the organizations have approved
  const approvedBy = pending && !pending.userCode
    ? (await db.select({ orgId: schema.enrollmentApproval.orgId }).from(schema.enrollmentApproval)
      .where(orm.eq(schema.enrollmentApproval.requestId, pending.id))).filter((row) => approverOrgs.includes(row.orgId)).length
    : 0
  return {
    pending: pending ? { ...pending, approvedBy, approversNeeded: approverOrgs.length } : null,
    approved,
    needsAdmin: approverOrgs.length > 0,
  }
}

// Members' requests for a first passkey that this organization approves:
// whether it has, and how many of their other organizations still have to
export async function pendingEnrollments({ userIds, orgId }: { userIds: string[]; orgId: string }) {
  if (userIds.length === 0) return []
  const db = getDb()
  const rows = await db.query.stepUpRequest.findMany({
    where: { userId: { in: userIds }, purpose: 'enroll', userCode: { isNull: true }, status: 'pending', expiresAt: { gt: Date.now() } },
    columns: { id: true, userId: true, ipAddress: true, country: true, userAgent: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
  })
  if (rows.length === 0) return []
  const approvals = await db.select({ requestId: schema.enrollmentApproval.requestId, orgId: schema.enrollmentApproval.orgId })
    .from(schema.enrollmentApproval).where(orm.inArray(schema.enrollmentApproval.requestId, rows.map((row) => row.id)))
  const requests = await Promise.all(rows.map(async (row) => {
    const orgIds = await passkeyApproverOrgs(row.userId)
    const approved = new Set(approvals.filter((approval) => approval.requestId === row.id).map((approval) => approval.orgId))
    return { ...row, approves: orgIds.includes(orgId), approvedHere: approved.has(orgId), waitingForOthers: orgIds.filter((id) => id !== orgId && !approved.has(id)).length }
  }))
  return requests.filter((request) => request.approves)
}

// What gives lasting access to your account: approving a CLI login, making an
// API token. Once you have a passkey, these take an approval with it, so a
// stolen session can't turn itself into a login or a token that outlives it.
export async function requirePasskeyOnceEnrolled({ userId, sessionId }: { userId: string; sessionId: string }) {
  const passkey = await getDb().query.passkey.findFirst({ where: { userId }, columns: { id: true } })
  if (passkey && !await hasAdminGrant({ userId, sessionId })) throw new StepUpRequiredError('admin')
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
