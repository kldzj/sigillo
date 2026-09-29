// Shared server actions for the Sigillo app UI.
// Client components import these directly instead of receiving action props.
//
// Every action authenticates via getActionRequest() → getSession() and
// verifies org membership before mutating data. No action accepts a raw
// userId — it always comes from the session cookie.
//
// Actions throw on error (caught by ErrorBoundary in the UI) and return
// objects on success. Never return strings or scalar values.

'use server'

import { ulid } from 'ulid'
import { getEnvSlugError, getSecretNameError, TOKEN_EXPIRY_DAYS } from './lib/utils.ts'
import * as orm from 'drizzle-orm'
import { schema } from 'db'
import { getActionRequest, redirect } from 'spiceflow'
import { router } from 'spiceflow/react'
import {
  getDb, getSession,
  requireOrgMember,
  getOrgIdForProject, getOrgIdForEnvironment,
  decrypt,
  generateApiToken,
  deriveSecrets,
  getMemberProjectAccess,
  getMemberAccess,
  getUserEnvironmentAccess,
  getEnvironmentAccessError,
  getClaimableAutoJoinDomain,
  deleteOrgMember, joinOrgByInvite, setOrgMemberRole, requireValidName, requireOrgDeletionTyped, requireEnvironmentDeletionTyped, requireProjectDeletionTyped,
  endUserSession,
  endOtherUserSessions,
} from './db.ts'
import { appendSecretEvents, recordSecretRead, setEnvironmentProtection, readSecretValues, readEventValue, purgeOldValues, type NewSecretEvent } from './audit.ts'
import {
  StepUpRequiredError, NoPasskeyError, createStepUpRequest, approvalOptions, approveStepUpRequest, findStepUpRequest, logPasskeyEvent,
  requireMachineTokenApproval, requireMachineTokenDeletion, requireOldValuesPurge, requireOrgAdmin, requireAdminApproval, requireAdminForProtected, requireProjectChange, requireProtectedAccess, requireTokenDeletion, resetMemberPasskeys, type Purpose,
  requestEnrollment, approveEnrollment, declineEnrollment, stepUpRequestStatus, requirePasskeyOnceEnrolled,
} from './step-up.ts'
import { createTrustRule, deleteTrustRule, replaceTrustRuleKeys, type TrustRuleInput } from './workload.ts'
import type { AuthenticationResponseJSON } from '@simplewebauthn/server'

async function requireSession() {
  const request = getActionRequest()
  const session = await getSession(request)
  if (!session) throw new Error('Unauthorized')
  return session
}

// The signed-in person as the author of a change or a read
function authorOf(session: { userId: string; sessionId: string }) {
  return { userId: session.userId, apiTokenId: null, sessionId: session.sessionId }
}

// Org member + project access + admin role for admin-only envs.
async function requireEnvironmentAccess(userId: string, environmentId: string) {
  const env = await getUserEnvironmentAccess({ userId, environmentRef: environmentId })
  if (!env) throw new Error('Environment not found')
  return env
}

async function requireProjectAccess(userId: string, projectId: string) {
  const orgId = await getOrgIdForProject(projectId)
  if (!orgId) throw new Error('Project not found')
  if (!await getMemberProjectAccess({ userId, orgId, projectId })) {
    throw new Error('You do not have access to this project')
  }
  return orgId
}

// A token reads every secret in its scope, so creating or revoking one needs
// access to that whole scope: the listed envs, or every env of the project
// for a project-wide token (no env ids). Admin-only envs added later stay
// safe: token use re-checks that the creator is still an admin.
async function requireTokenScopeAccess({ userId, projectId, environmentIds }: {
  userId: string
  projectId: string
  environmentIds: string[]
}) {
  const orgId = await requireProjectAccess(userId, projectId)
  const [access, envs] = await Promise.all([
    getMemberAccess({ userId, orgId }),
    getDb().query.environment.findMany({
      where: environmentIds.length > 0 ? { projectId, id: { in: environmentIds } } : { projectId },
      columns: { projectId: true, accessRole: true },
    }),
  ])
  if (envs.length < environmentIds.length) throw new Error('Environment not found in this project')
  for (const env of envs) {
    const error = getEnvironmentAccessError(access, env)
    if (error) throw new Error(error)
  }
}

async function ensureAnotherAdminExists(orgId: string, userId: string) {
  const db = getDb()
  const admins = await db.query.orgMember.findMany({
    where: { orgId, role: 'admin' },
    columns: { userId: true },
  })
  if (admins.length === 1 && admins[0]?.userId === userId) {
    throw new Error('This organization needs at least one admin')
  }
}

export async function createProjectAction({ name, orgId }: { name: string; orgId: string }) {
  requireValidName(name)
  if (!orgId) throw new Error('No org selected')
  const session = await requireSession()
  await requireOrgMember(session.userId, orgId)
  const db = getDb()
  const projectId = ulid()
  const [[proj]] = await db.batch([
    db.insert(schema.project).values({ id: projectId, name, orgId })
      .returning({ id: schema.project.id, name: schema.project.name }),
    ...schema.DEFAULT_ENVIRONMENTS.map((e) =>
      db.insert(schema.environment).values({ projectId, name: e.name, slug: e.slug }),
    ),
  ] as const)
  throw redirect(router.href('/dash/projects/:projectId', { projectId: proj!.id }))
}

// All secret mutations append to the secretEvent log. Never update or delete events.

export async function deleteSecretAction({ name, environmentIds }: {
  name: string
  environmentIds: string[]
}) {
  return stepUpOr(async () => {
    const unique = Array.from(new Set(environmentIds))
    if (!unique.length) throw new Error('No environments selected')
    const session = await requireSession()
    const envs = await Promise.all(unique.map((id) => requireEnvironmentAccess(session.userId, id)))
    if (envs.some((env) => env.projectId !== envs[0]!.projectId)) {
      throw new Error('All environments must belong to the same project')
    }
    await appendSecretEvents({
      author: authorOf(session),
      events: unique.map((environmentId) => ({ environmentId, name, operation: 'delete' as const })),
    })
    return { ok: true }
  })
}

// An action that needs a passkey approval first: the browser asks for one
// (startStepUpAction) and runs the action again
type StepUp = { stepUp: { purpose: 'access' | 'admin'; environmentIds: string[] } }

async function stepUpOr<T>(action: () => Promise<T>): Promise<T | StepUp> {
  try {
    return await action()
  } catch (error) {
    if (error instanceof StepUpRequiredError) return { stepUp: { purpose: error.purpose, environmentIds: error.environmentIds } }
    throw error
  }
}

// Values the web UI reveals, downloads or copies. Recorded as reads.
export async function revealSecretsAction({ environmentId, names, download }: {
  environmentId: string
  names: string[] | null
  download?: boolean
}) {
  if (names !== null && !(Array.isArray(names) && names.every((name) => typeof name === 'string'))) throw new Error('Secret names must be a list')
  const session = await requireSession()
  return stepUpOr(async () => ({
    values: await readSecretValues({
      request: getActionRequest(), userId: session.userId, sessionId: session.sessionId,
      environmentId, names, kind: download ? 'download' : 'value',
    }),
  }))
}

// An admin removes an environment's old values, all but each secret's
// current one (audit.ts)
export async function purgeOldValuesAction({ environmentId }: { environmentId: string }) {
  const session = await requireSession()
  return stepUpOr(async () => {
    await requireOldValuesPurge({ ...session, environmentId })
    return purgeOldValues({ environmentId, author: authorOf(session) })
  })
}

export async function revealEventValueAction({ eventId }: { eventId: string }) {
  const session = await requireSession()
  return stepUpOr(async () => ({
    value: await readEventValue({ request: getActionRequest(), userId: session.userId, sessionId: session.sessionId, eventId }),
  }))
}

// ── Step-up in the browser ──────────────────────────────────────────

// Asks this browser session's own approval: the passkey challenge to sign
export async function startStepUpAction({ purpose, environmentIds }: { purpose: 'access' | 'admin'; environmentIds: string[] }) {
  const session = await requireSession()
  const request = getActionRequest()
  const row = await createStepUpRequest({ request, userId: session.userId, sessionId: session.sessionId, environmentIds, withCode: false, purpose })
  try {
    return { requestId: row.id, options: await approvalOptions({ request, requestId: row.id, userId: session.userId }) }
  } catch (error) {
    if (error instanceof NoPasskeyError) return { noPasskey: true as const }
    throw error
  }
}

export async function finishStepUpAction({ requestId, response }: { requestId: string; response: AuthenticationResponseJSON }) {
  const session = await requireSession()
  return { approved: await approveStepUpRequest({ request: getActionRequest(), requestId, userId: session.userId, response }) }
}

// ── Passkeys ────────────────────────────────────────────────────────

export async function removePasskeyAction({ passkeyId }: { passkeyId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    const db = getDb()
    const passkey = await db.query.passkey.findFirst({ where: { id: passkeyId, userId: session.userId }, columns: { id: true, name: true } })
    if (!passkey) throw new Error('Passkey not found')
    await requireAdminApproval({ userId: session.userId, sessionId: session.sessionId })
    await db.delete(schema.passkey).where(orm.eq(schema.passkey.id, passkey.id))
    await logPasskeyEvent({ request: getActionRequest(), userId: session.userId, actor: `user:${session.userId}`, action: 'removed', passkeyName: passkey.name })
    return { ok: true }
  })
}

// An org admin removes a member's passkeys, for a member who lost them: the
// member then adds new ones after a fresh sign-in
export async function removeMemberPasskeysAction({ memberId }: { memberId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    const db = getDb()
    const member = await db.query.orgMember.findFirst({ where: { id: memberId }, columns: { orgId: true, userId: true } })
    if (!member) throw new Error('Member not found')
    await resetMemberPasskeys({ request: getActionRequest(), actor: session, userId: member.userId })
    return { ok: true }
  })
}

// Adding a passkey that someone approves first: on another device of yours
// with a code, or, for a first passkey, by an admin
export async function requestEnrollmentAction({ viaCode }: { viaCode: boolean }) {
  const session = await requireSession()
  const request = getActionRequest()
  const row = await requestEnrollment({ request, ...session, viaCode })
  return { requestId: row.id, userCode: row.userCode, expiresAt: row.expiresAt }
}

export async function enrollmentStatusAction({ requestId }: { requestId: string }) {
  const session = await requireSession()
  return { status: await stepUpRequestStatus({ requestId, sessionId: session.sessionId }) }
}

// An admin answers a member's request for their first passkey
export async function approveEnrollmentAction({ requestId }: { requestId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    return approveEnrollment({ requestId, approver: session })
  })
}

export async function declineEnrollmentAction({ requestId }: { requestId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    await declineEnrollment({ requestId, approver: session })
    return { ok: true }
  })
}

// /approve: a CLI request of the signed-in user, found by the code typed there
export async function findApprovalAction({ userCode }: { userCode: string }) {
  const session = await requireSession()
  return findStepUpRequest({ userId: session.userId, userCode })
}

export async function approvalOptionsAction({ requestId }: { requestId: string }) {
  const session = await requireSession()
  try {
    return { options: await approvalOptions({ request: getActionRequest(), requestId, userId: session.userId }) }
  } catch (error) {
    if (error instanceof NoPasskeyError) return { noPasskey: true as const }
    throw error
  }
}

// Save edited secrets to the current environment and optionally apply
// the same changes to additional environments. Each edit appends a "set"
// event to the log. Renames are handled as delete old name + set new name.
// A rename without a value keeps the current one, which the browser may never
// have loaded; copying it to other environments is recorded as a read.
export async function saveSecretsAction(args: {
  edits: { name: string; originalName?: string; value?: string }[]
  environmentIds: string[]
}) {
  return stepUpOr(() => saveSecrets(args))
}

async function saveSecrets({ edits: requested, environmentIds }: {
  edits: { name: string; originalName?: string; value?: string }[]
  environmentIds: string[]
}) {
  if (requested.length === 0 || environmentIds.length === 0) return
  const session = await requireSession()
  const currentEnvId = environmentIds[0]!
  const envs = await Promise.all(
    Array.from(new Set(environmentIds)).map((id) => requireEnvironmentAccess(session.userId, id)),
  )
  if (envs.some((env) => env.projectId !== envs[0]!.projectId)) {
    throw new Error('All environments must belong to the same project')
  }

  // New and renamed names must be valid. An invalid name is accepted only
  // when it is unchanged AND already exists here (legacy secrets stay editable).
  if (requested.some((edit) => getSecretNameError(edit.name))) {
    const existingNames = new Set((await deriveSecrets(currentEnvId)).map((s) => s.name))
    for (const edit of requested) {
      const nameError = getSecretNameError(edit.name)
      if (!nameError) continue
      if (edit.name === edit.originalName && existingNames.has(edit.name)) continue
      throw new Error(nameError)
    }
  }

  // Every environment written, protected ones asked for at once
  const author = authorOf(session)
  await requireProtectedAccess({ environmentIds, reader: author })

  const kept = requested.filter((edit) => edit.value === undefined)
  const current = kept.length ? await deriveSecrets(currentEnvId) : []
  const edits = await Promise.all(requested.map(async (edit) => {
    if (edit.value !== undefined) return { ...edit, value: edit.value }
    const secret = current.find((s) => s.name === (edit.originalName ?? edit.name))
    if (!secret) throw new Error(`${edit.originalName ?? edit.name} no longer exists`)
    return { ...edit, value: await decrypt(secret.valueEncrypted, secret.iv, secret) }
  }))
  if (kept.length && environmentIds.some((id) => id !== currentEnvId)) {
    await recordSecretRead({
      request: getActionRequest(), environment: envs.find((env) => env.id === currentEnvId)!,
      author, kind: 'copy', names: kept.map((edit) => edit.originalName ?? edit.name),
    })
  }

  const events: NewSecretEvent[] = []
  for (const edit of edits) {
    const originalName = edit.originalName
    if (originalName && edit.name !== originalName) {
      events.push({ environmentId: currentEnvId, name: originalName, operation: 'delete' })
    }
    events.push({ environmentId: currentEnvId, name: edit.name, operation: 'set', value: edit.value })
  }

  // Apply value changes to other environments
  const otherEnvIds = Array.from(new Set(environmentIds.slice(1))).filter((id) => id !== currentEnvId)
  for (const environmentId of otherEnvIds) {
    for (const edit of edits) {
      events.push({ environmentId, name: edit.name, operation: 'set', value: edit.value })
    }
  }

  await appendSecretEvents({ author, events })
}

export async function deleteEnvAction({ id, typedSlug }: { id: string; typedSlug?: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    await requireEnvironmentAccess(session.userId, id)
    await requireEnvironmentDeletionTyped({ environmentId: id, typed: typedSlug })
    await requireAdminForProtected({ ...session, environmentIds: [id] })
    const db = getDb()
    await db.delete(schema.environment).where(orm.eq(schema.environment.id, id))
    return { ok: true }
  })
}

export async function createEnvAction({ name, slug, projectId }: {
  name: string
  slug: string
  projectId: string
}) {
  if (!name || !slug) throw new Error('Name and slug are required')
  requireValidName(name)
  const slugError = getEnvSlugError(slug)
  if (slugError) throw new Error(slugError)
  const session = await requireSession()
  await requireProjectAccess(session.userId, projectId)
  const db = getDb()
  await db.insert(schema.environment).values({ projectId, name, slug })
  return { name }
}

export async function renameEnvAction({ id, name, slug }: {
  id: string
  name?: string
  slug?: string
}) {
  return stepUpOr(async () => {
    if (!name && !slug) throw new Error('At least one of name or slug is required')
    if (name) requireValidName(name)
    const slugError = slug ? getEnvSlugError(slug) : null
    if (slugError) throw new Error(slugError)
    const session = await requireSession()
    await requireEnvironmentAccess(session.userId, id)
    await requireAdminForProtected({ ...session, environmentIds: [id] })
    const db = getDb()
    const updates: Partial<{ name: string; slug: string; updatedAt: number }> = { updatedAt: Date.now() }
    if (name) updates.name = name
    if (slug) updates.slug = slug
    await db.update(schema.environment).set(updates).where(orm.eq(schema.environment.id, id))
    return { id }
  })
}

const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

export async function createInviteAction({ orgId, projectIds }: { orgId: string; projectIds?: string[] }) {
  return stepUpOr(async () => {
    if (!orgId) throw new Error('No org selected')
    const session = await requireSession()
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId })

    // Validate project IDs belong to this org if provided
    if (projectIds && projectIds.length > 0) {
      const db = getDb()
      const orgProjects = await db.query.project.findMany({
        where: { orgId },
        columns: { id: true },
      })
      const validIds = new Set(orgProjects.map((p) => p.id))
      for (const pid of projectIds) {
        if (!validIds.has(pid)) throw new Error(`Project ${pid} does not belong to this organization`)
      }
    }

    const db = getDb()
    const [invite] = await db.insert(schema.orgInvitation).values({
      orgId,
      createdBy: session.userId,
      projectIds: projectIds && projectIds.length > 0 ? JSON.stringify(projectIds) : null,
      expiresAt: Date.now() + INVITE_EXPIRY_MS,
    }).returning({ id: schema.orgInvitation.id })
    return { id: invite!.id }
  })
}

export async function acceptInviteAction({ invitationId }: { invitationId: string }) {
  if (!invitationId) throw new Error('Invitation ID is required')
  const session = await requireSession()
  const orgId = await joinOrgByInvite({ invitationId, userId: session.userId })
  throw redirect(router.href('/dash/orgs/:orgId', { orgId }))
}

export async function updateOrgMemberRoleAction({ memberId, role }: {
  memberId: string
  role: 'admin' | 'member'
}) {
  if (role !== 'admin' && role !== 'member') throw new Error('Unknown role')
  return stepUpOr(async () => {
    const session = await requireSession()
    const db = getDb()
    const member = await db.query.orgMember.findFirst({
      where: { id: memberId },
      columns: { id: true, orgId: true, userId: true, role: true },
    })
    if (!member) throw new Error('Member not found')

    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: member.orgId })

    if (member.role === role) {
      return { id: member.id, role: member.role }
    }

    if (member.role === 'admin' && role !== 'admin') {
      await ensureAnotherAdminExists(member.orgId, member.userId)
    }

    await setOrgMemberRole({ member, role })

    return { id: member.id, role }
  })
}

export async function removeOrgMemberAction({ memberId }: { memberId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    const db = getDb()
    const member = await db.query.orgMember.findFirst({
      where: { id: memberId },
      columns: { id: true, orgId: true, userId: true, role: true },
    })
    if (!member) throw new Error('Member not found')

    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: member.orgId })

    if (member.role === 'admin') {
      await ensureAnotherAdminExists(member.orgId, member.userId)
    }

    await deleteOrgMember(member)
    return { id: member.id }
  })
}

// ── Session actions ─────────────────────────────────────────────────

export async function endSessionAction({ sessionId }: { sessionId: string }) {
  if (!sessionId) throw new Error('Session ID is required')
  await requireSession()
  await endUserSession(getActionRequest(), sessionId)
}

export async function endOtherSessionsAction() {
  await requireSession()
  await endOtherUserSessions(getActionRequest())
}

// ── API Token actions ───────────────────────────────────────────────

export async function createTokenAction(args: {
  name: string
  projectId: string
  environmentIds?: string[]
  expiresInDays: number
  // A machine token, which reads protected environments without a passkey
  protectedAccess?: boolean
}) {
  return stepUpOr(() => createToken(args))
}

async function createToken({ name, projectId, environmentIds, expiresInDays, protectedAccess = false }: {
  name: string
  projectId: string
  environmentIds?: string[]
  expiresInDays: number
  protectedAccess?: boolean
}) {
  if (!name) throw new Error('Name is required')
  if (!projectId) throw new Error('Project is required')
  if (!TOKEN_EXPIRY_DAYS.some((days) => days === expiresInDays)) {
    throw new Error(`Expiry must be one of ${TOKEN_EXPIRY_DAYS.join(', ')} days`)
  }
  const session = await requireSession()
  const uniqueEnvIds = Array.from(new Set(environmentIds ?? []))
  await requireTokenScopeAccess({ userId: session.userId, projectId, environmentIds: uniqueEnvIds })
  const db = getDb()

  // A token outlives the session that makes it
  await requirePasskeyOnceEnrolled({ userId: session.userId, sessionId: session.sessionId })
  if (protectedAccess) {
    await requireMachineTokenApproval({ userId: session.userId, sessionId: session.sessionId, projectId, expiresInDays })
  }

  const { key, hashedKey, prefix } = await generateApiToken()
  const tokenId = ulid()
  await db.batch([
    db.insert(schema.apiToken).values({
      id: tokenId,
      name,
      projectId,
      prefix,
      hashedKey,
      createdBy: session.userId,
      expiresAt: Date.now() + expiresInDays * 86_400_000,
      protectedAccess,
    }),
    ...uniqueEnvIds.map((environmentId) =>
      db.insert(schema.apiTokenEnvironment).values({ tokenId, environmentId }),
    ),
  ] as [any, ...any[]])

  // Return the full key — this is the only time it's ever available
  return { id: tokenId, key }
}

export async function deleteTokenAction({ tokenId }: { tokenId: string }) {
  return stepUpOr(async () => {
    if (!tokenId) throw new Error('Token ID is required')
    const session = await requireSession()
    const db = getDb()
    const token = await db.query.apiToken.findFirst({
      where: { id: tokenId },
      columns: { projectId: true, protectedAccess: true, createdBy: true },
      with: { environments: { columns: { environmentId: true } } },
    })
    if (!token) throw new Error('Token not found')
    await requireTokenDeletion({ ...session, token })
    await requireTokenScopeAccess({
      userId: session.userId,
      projectId: token.projectId,
      environmentIds: token.environments.map((row) => row.environmentId),
    })
    // Deleting a machine token stops CI: an admin action, like making one
    if (token.protectedAccess) await requireMachineTokenDeletion({ userId: session.userId, sessionId: session.sessionId, projectId: token.projectId })
    await db.delete(schema.apiToken).where(orm.eq(schema.apiToken.id, tokenId))
    return { ok: true }
  })
}

// ── Workload identities ─────────────────────────────────────────────
// Trust rules (workload.ts), each change an org admin's with their passkey

export async function createTrustRuleAction(rule: TrustRuleInput) {
  return stepUpOr(async () => {
    const session = await requireSession()
    return createTrustRule({ userId: session.userId, sessionId: session.sessionId, ownHost: new URL(getActionRequest().url).hostname, rule })
  })
}

export async function deleteTrustRuleAction({ ruleId }: { ruleId: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    await deleteTrustRule({ userId: session.userId, sessionId: session.sessionId, ruleId })
    return { ok: true }
  })
}

export async function replaceTrustRuleKeysAction({ ruleId, jwks }: { ruleId: string; jwks: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    await replaceTrustRuleKeys({ userId: session.userId, sessionId: session.sessionId, ruleId, jwks })
    return { ok: true }
  })
}

export async function syncMissingSecretsAction(args: {
  sourceEnvironmentId: string
  targetEnvironmentId: string
  names: string[]
}) {
  return stepUpOr(() => syncMissingSecrets(args))
}

async function syncMissingSecrets({
  sourceEnvironmentId,
  targetEnvironmentId,
  names,
}: {
  sourceEnvironmentId: string
  targetEnvironmentId: string
  names: string[]
}) {
  if (!sourceEnvironmentId || !targetEnvironmentId) throw new Error('Both environment IDs are required')
  if (sourceEnvironmentId === targetEnvironmentId) throw new Error('Source and target environments must be different')
  if (!names.length) throw new Error('No secret names provided')
  const session = await requireSession()

  const [source, target] = await Promise.all([
    requireEnvironmentAccess(session.userId, sourceEnvironmentId),
    requireEnvironmentAccess(session.userId, targetEnvironmentId),
  ])
  if (source.projectId !== target.projectId) throw new Error('Environments must belong to the same project')

  // Re-derive both sides server-side so we never overwrite a key that was
  // added to the target after the client loaded (stale tab race condition).
  const [sourceSecrets, targetSecrets] = await Promise.all([
    deriveSecrets(sourceEnvironmentId),
    deriveSecrets(targetEnvironmentId),
  ])
  const targetNames = new Set(targetSecrets.map((s) => s.name))
  const stillMissing = new Set(names.filter((name) => !targetNames.has(name)))
  // Legacy names that fail validation are not copied to new environments.
  const toSync = sourceSecrets.filter((s) => stillMissing.has(s.name) && !getSecretNameError(s.name))

  if (toSync.length === 0) return { count: 0 }

  // Copying values out of a protected environment is a read of them, and
  // into one a change: both asked for at once
  const author = authorOf(session)
  await requireProtectedAccess({ environmentIds: [sourceEnvironmentId, targetEnvironmentId], reader: author })
  await recordSecretRead({ request: getActionRequest(), environment: source, author, kind: 'copy', names: toSync.map((s) => s.name) })
  const values = await Promise.all(toSync.map((s) => decrypt(s.valueEncrypted, s.iv, s)))
  await appendSecretEvents({
    author,
    events: toSync.map((s, i) => ({ environmentId: targetEnvironmentId, name: s.name, operation: 'set' as const, value: values[i]! })),
  })
  return { count: toSync.length }
}

export async function createOrgAction({ name, enableAutoJoin }: { name: string; enableAutoJoin?: boolean }) {
  requireValidName(name)
  const session = await requireSession()

  let autoJoinDomain: string | null = null
  if (enableAutoJoin) {
    const domain = await getClaimableAutoJoinDomain({ session })
    if (domain instanceof Error) throw domain
    autoJoinDomain = domain
  }

  const db = getDb()
  const orgId = ulid()
  const [[org]] = await db.batch([
    db.insert(schema.org).values({ id: orgId, name, autoJoinDomain }).returning({ id: schema.org.id, name: schema.org.name }),
    db.insert(schema.orgMember).values({ orgId, userId: session.userId, role: 'admin' }),
  ] as const)
  throw redirect(router.href('/dash/orgs/:orgId', { orgId: org!.id }))
}

export async function updateAutoJoinDomainAction({ orgId, enabled }: { orgId: string; enabled: boolean }) {
  return stepUpOr(async () => {
    if (!orgId) throw new Error('Org ID is required')
    const session = await requireSession()
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: orgId })

    let autoJoinDomain: string | null = null
    if (enabled) {
      const domain = await getClaimableAutoJoinDomain({ session, orgId })
      if (domain instanceof Error) throw domain
      autoJoinDomain = domain
    }

    const db = getDb()
    await db.update(schema.org)
      .set({ autoJoinDomain, updatedAt: Date.now() })
      .where(orm.eq(schema.org.id, orgId))
      .limit(1)

    return { autoJoinDomain }
  })
}

// ── Member access (granular project permissions) ────────────────────
// Admin-only. Sets which projects a member can access and which secrets
// are restricted. Passing an empty projects array reverts to "all access".

// projectIds null = all projects; [] = no projects.
export async function updateMemberAccessAction({ memberId, projectIds }: {
  memberId: string
  projectIds: string[] | null
}) {
  return stepUpOr(async () => {
    const session = await requireSession()
    const db = getDb()
    const member = await db.query.orgMember.findFirst({
      where: { id: memberId },
      columns: { id: true, orgId: true, role: true },
    })
    if (!member) throw new Error('Member not found')
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: member.orgId })

    // Cannot restrict admins
    if (member.role === 'admin') throw new Error('Admins always have full access')

    const selected = projectIds ?? []
    const orgProjects = await db.query.project.findMany({
      where: { orgId: member.orgId },
      columns: { id: true },
    })
    const orgProjectIdsSet = new Set(orgProjects.map((p) => p.id))
    for (const pid of selected) {
      if (!orgProjectIdsSet.has(pid)) {
        throw new Error(`Project ${pid} does not belong to this organization`)
      }
    }

    // Mode and rules in one batch, so a failure keeps the old access.
    await db.batch([
      db.update(schema.orgMember)
        .set({ projectAccess: projectIds === null ? 'all' : 'selected' })
        .where(orm.eq(schema.orgMember.id, member.id)),
      db.delete(schema.memberAccess).where(orm.eq(schema.memberAccess.orgMemberId, member.id)),
      ...selected.map((projectId) => db.insert(schema.memberAccess).values({ orgMemberId: member.id, projectId })),
    ])

    return { ok: true }
  })
}

// ── Environment access role ─────────────────────────────────────────
// Admins can restrict an environment (e.g. production) so only admins
// can read/write secrets in it. Members get 403 on all secret operations.

export async function updateEnvironmentAccessRoleAction({ environmentId, accessRole }: {
  environmentId: string
  accessRole: 'admin' | 'member'
}) {
  if (accessRole !== 'admin' && accessRole !== 'member') throw new Error('Unknown role')
  return stepUpOr(async () => {
    const session = await requireSession()
    const orgId = await getOrgIdForEnvironment(environmentId)
    if (!orgId) throw new Error('Environment not found')
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: orgId })
    const db = getDb()
    await db.update(schema.environment)
      .set({ accessRole, updatedAt: Date.now() })
      .where(orm.eq(schema.environment.id, environmentId))
      .limit(1)
    return { ok: true, environmentId, accessRole }
  })
}

export async function updateEnvironmentProtectionAction({ environmentId, protect }: {
  environmentId: string
  protect: boolean
}) {
  return stepUpOr(async () => {
    const session = await requireSession()
    const orgId = await getOrgIdForEnvironment(environmentId)
    if (!orgId) throw new Error('Environment not found')
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: orgId })
    await setEnvironmentProtection({
      request: getActionRequest(), environmentId, protect, author: { userId: session.userId, apiTokenId: null, sessionId: session.sessionId },
    })
    return { ok: true, environmentId, protect }
  })
}

export async function renameProjectAction({ projectId, name }: { projectId: string; name: string }) {
  return stepUpOr(async () => {
    requireValidName(name)
    const session = await requireSession()
    await requireProjectChange({ ...session, projectId })
    await getDb().update(schema.project).set({ name: name.trim(), updatedAt: Date.now() }).where(orm.eq(schema.project.id, projectId))
    return { ok: true }
  })
}

// Deleting a project deletes its environments and secrets: it takes its
// name, typed out
export async function deleteProjectAction({ projectId, typedName }: { projectId: string; typedName: string }) {
  return stepUpOr(async () => {
    const session = await requireSession()
    await requireProjectChange({ ...session, projectId })
    await requireProjectDeletionTyped({ projectId, typed: typedName })
    const project = await getDb().query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } })
    await getDb().delete(schema.project).where(orm.eq(schema.project.id, projectId))
    throw redirect(project ? router.href('/dash/orgs/:orgId', { orgId: project.orgId }) : router.href('/dash'))
  })
}

// A member leaves an organization, as if an admin removed them: auto-join
// doesn't add them back. The last admin can't leave.
export async function leaveOrgAction({ orgId }: { orgId: string }) {
  const session = await requireSession()
  const member = await getDb().query.orgMember.findFirst({
    where: { orgId, userId: session.userId },
    columns: { id: true, orgId: true, userId: true, role: true },
  })
  if (!member) return { error: 'You are not a member of this organization' }
  if (member.role === 'admin') {
    const admins = await getDb().query.orgMember.findMany({ where: { orgId, role: 'admin' }, columns: { userId: true } })
    if (admins.length === 1) return { error: 'This organization needs at least one admin: make someone else an admin first' }
  }
  await deleteOrgMember(member)
  throw redirect(router.href('/dash'))
}

export async function deleteOrgAction({ orgId, typedName }: { orgId: string; typedName: string }) {
  return stepUpOr(async () => {
    if (!orgId) throw new Error('Org ID is required')
    const session = await requireSession()
    await requireOrgAdmin({ userId: session.userId, sessionId: session.sessionId, orgId: orgId })
    await requireOrgDeletionTyped({ orgId, typed: typedName })
    const db = getDb()
    // Cascade deletes handle orgMembers, invitations, projects, environments,
    // secretEvents, and apiTokens automatically via foreign key constraints.
    await db.delete(schema.org).where(orm.eq(schema.org.id, orgId))
    // /dash re-resolves the user's remaining orgs (or shows the create-org flow)
    throw redirect(router.href('/dash'))
  })
}
