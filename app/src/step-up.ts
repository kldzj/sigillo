// Step-up: a person approves reads of protected environments with a passkey.
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
import { getRequestOrigin, getUserEnvironmentAccess, getProjectMemberAccess } from './db.ts'
import { MACHINE_TOKEN_MAX_DAYS } from './lib/utils.ts'

// How long an approval lets a session read, or add passkeys, and how long a
// request waits
const GRANT_MS = { read: 15 * 60 * 1000, passkeys: 5 * 60 * 1000 }
const REQUEST_MS = 10 * 60 * 1000
// The first passkey needs a sign-in this recent instead of an approval
const FRESH_SIGN_IN_MS = 5 * 60 * 1000

type Purpose = 'read' | 'passkeys'

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
  constructor(readonly environmentIds: string[], readonly machineTokenRequired = false) {
    super(machineTokenRequired
      ? 'this environment is protected: only a machine token can read it'
      : 'this environment is protected: approve the read with your passkey')
    this.name = 'StepUpRequiredError'
  }

  get code() {
    return this.machineTokenRequired ? 'MACHINE_TOKEN_REQUIRED' : 'STEP_UP_REQUIRED'
  }
}

export type Reader = { userId: string | null; apiTokenId: string | null; sessionId?: string | null }

// Reads of a protected environment need a grant for the reading session, or
// a machine token. recordSecretRead calls this, and every read of values goes
// through recordSecretRead. It only ever denies on top of the usual access rules.
export async function requireStepUp({ environmentId, reader }: { environmentId: string; reader: Reader }) {
  const db = getDb()
  if (reader.apiTokenId) {
    const token = await db.query.apiToken.findFirst({ where: { id: reader.apiTokenId }, columns: { protectedAccess: true } })
    if (!token?.protectedAccess) throw new StepUpRequiredError([environmentId], true)
    return
  }
  if (!reader.userId || !reader.sessionId) throw new StepUpRequiredError([environmentId])
  const grants = await db.query.stepUpGrant.findMany({
    where: { sessionId: reader.sessionId, userId: reader.userId, purpose: 'read', expiresAt: { gt: Date.now() } },
    columns: { environmentIds: true },
  })
  if (!grants.some((grant) => grant.environmentIds.includes(environmentId))) throw new StepUpRequiredError([environmentId])
}

// A machine token reads protected environments without a passkey, so only
// an admin makes one, with an approval of their own for every protected
// environment it covers right now, and it expires after 90 days at most
export async function requireMachineTokenApproval({ userId, sessionId, projectId, environmentIds, expiresInDays }: {
  userId: string
  sessionId: string
  projectId: string
  // [] covers every environment of the project
  environmentIds: string[]
  expiresInDays: number
}) {
  if (expiresInDays > MACHINE_TOKEN_MAX_DAYS) throw new Error(`A machine token expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  if ((await getProjectMemberAccess(userId, projectId))?.role !== 'admin') throw new Error('Only admins can make a machine token')
  const environments = await getDb().query.environment.findMany({ where: { projectId, protected: true }, columns: { id: true } })
  const missing: string[] = []
  for (const env of environments) {
    if (environmentIds.length && !environmentIds.includes(env.id)) continue
    try {
      await requireStepUp({ environmentId: env.id, reader: { userId, apiTokenId: null, sessionId } })
    } catch (error) {
      if (!(error instanceof StepUpRequiredError)) throw error
      missing.push(env.id)
    }
  }
  if (missing.length) throw new StepUpRequiredError(missing)
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

// Opens a request for the session to read the environments, or to add
// passkeys. The CLI gets a code that its user types on /approve; the browser
// approves its own.
export async function createStepUpRequest({ request, userId, sessionId, environmentIds, withCode, purpose = 'read' }: {
  request: Request
  userId: string
  sessionId: string
  environmentIds: string[]
  withCode: boolean
  purpose?: Purpose
}) {
  const ids = [...new Set(environmentIds)]
  if (purpose === 'read' && ids.length === 0) throw new Error('No environments to approve')
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

// A pending read request of this user by the code typed on /approve, with
// what the page shows before anyone approves it
export async function findStepUpRequest({ userId, userCode }: { userId: string; userCode: string }) {
  const row = await pendingRequest({ userId, userCode: userCode.trim().toUpperCase() })
  if (!row || row.purpose !== 'read') return null
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
// session that asked may read its environments for 15 minutes
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

// The first passkey needs a Google sign-in from the last 5 minutes, so an old
// stolen session can't add one; every further one an approval with an
// existing passkey from the last 5 minutes.
export async function canAddPasskey({ userId, sessionId, sessionCreatedAt }: { userId: string; sessionId: string; sessionCreatedAt: number }) {
  const db = getDb()
  const existing = await db.query.passkey.findFirst({ where: { userId }, columns: { id: true } })
  if (!existing) return Date.now() - sessionCreatedAt < FRESH_SIGN_IN_MS
  const grant = await db.query.stepUpGrant.findFirst({
    where: { sessionId, userId, purpose: 'passkeys', expiresAt: { gt: Date.now() } },
    columns: { id: true },
  })
  return !!grant
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
