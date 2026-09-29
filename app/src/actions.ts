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
import { getEnvSlugError, getSecretNameError, TOKEN_EXPIRY_DAYS, GRACE_DAYS } from './lib/utils.ts'
import { asId, asString, asText, asBool, asOneOf, asList, asObject, asStringRecord, optional, nullable } from './lib/input.ts'
import * as orm from 'drizzle-orm'
import { schema } from 'db'
import { getActionRequest, redirect } from 'spiceflow'
import { router } from 'spiceflow/react'
import {
  getDb, getSession,
  requireOrgMember,
  getOrgIdForProject, getOrgIdForEnvironment,
  decrypt,
  deriveSecrets,
  getMemberProjectAccess,
  getUserEnvironmentAccess,
  getClaimableAutoJoinDomain,
  deleteOrgMember, joinOrgByInvite, setOrgMemberRole, requireValidName, requireOrgDeletionTyped, requireEnvironmentDeletionTyped, requireProjectDeletionTyped,
  deleteEnvironment, deleteProject,
  endUserSession,
  endOtherUserSessions,
} from './db.ts'
import { appendSecretEvents, recordSecretRead, setEnvironmentProtection, readSecretValues, readEventValue, purgeOldValues, type NewSecretEvent } from './audit.ts'
import {
  StepUpRequiredError, NoPasskeyError, createStepUpRequest, approvalOptions, approveStepUpRequest, findStepUpRequest, logPasskeyEvent,
  requireOldValuesPurge, requireOrgAdmin, requireAdminApproval, requireAdminForProtected, requireProjectChange, requireProtectedAccess, resetMemberPasskeys, type Purpose,
  requestEnrollment, approveEnrollment, declineEnrollment, stepUpRequestStatus,
} from './step-up.ts'
import { createTrustRule, deleteTrustRule, renewTrustRule, replaceTrustRuleKeys, trustRuleEvidence, type TrustRuleInput } from './workload.ts'
import { createToken, deleteToken, regenerateToken, stopPreviousValue } from './tokens.ts'
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
  asText(name)
  asId(orgId)
  requireValidName(name)
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
  asText(name)
  asList(environmentIds, asId)
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
  asId(environmentId)
  nullable(names, (value) => asList(value, asText))
  optional(download, asBool)
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
  asId(environmentId)
  const session = await requireSession()
  return stepUpOr(async () => {
    await requireOldValuesPurge({ ...session, environmentId })
    return purgeOldValues({ environmentId, author: authorOf(session), request: getActionRequest() })
  })
}

export async function revealEventValueAction({ eventId }: { eventId: string }) {
  asId(eventId)
  const session = await requireSession()
  return stepUpOr(async () => ({
    value: await readEventValue({ request: getActionRequest(), userId: session.userId, sessionId: session.sessionId, eventId }),
  }))
}

// ── Step-up in the browser ──────────────────────────────────────────

// Asks this browser session's own approval: the passkey challenge to sign
export async function startStepUpAction({ purpose, environmentIds }: { purpose: 'access' | 'admin'; environmentIds: string[] }) {
  asOneOf(purpose, ['access', 'admin'] as const)
  asList(environmentIds, asId)
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
  asId(requestId)
  asObject(response)
  const session = await requireSession()
  return { approved: await approveStepUpRequest({ request: getActionRequest(), requestId, userId: session.userId, response }) }
}

// ── Passkeys ────────────────────────────────────────────────────────

export async function removePasskeyAction({ passkeyId }: { passkeyId: string }) {
  asId(passkeyId)
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
  asId(memberId)
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
  asBool(viaCode)
  const session = await requireSession()
  const request = getActionRequest()
  const row = await requestEnrollment({ request, ...session, viaCode })
  return { requestId: row.id, userCode: row.userCode, expiresAt: row.expiresAt }
}

export async function enrollmentStatusAction({ requestId }: { requestId: string }) {
  asId(requestId)
  const session = await requireSession()
  return { status: await stepUpRequestStatus({ requestId, sessionId: session.sessionId }) }
}

// An admin answers a member's request for their first passkey
export async function approveEnrollmentAction({ requestId }: { requestId: string }) {
  asId(requestId)
  return stepUpOr(async () => {
    const session = await requireSession()
    return approveEnrollment({ requestId, approver: session })
  })
}

export async function declineEnrollmentAction({ requestId }: { requestId: string }) {
  asId(requestId)
  return stepUpOr(async () => {
    const session = await requireSession()
    await declineEnrollment({ requestId, approver: session })
    return { ok: true }
  })
}

// /approve: a CLI request of the signed-in user, found by the code typed there
export async function findApprovalAction({ userCode }: { userCode: string }) {
  asString(userCode)
  const session = await requireSession()
  return findStepUpRequest({ userId: session.userId, userCode })
}

export async function approvalOptionsAction({ requestId }: { requestId: string }) {
  asId(requestId)
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
  asList(args.edits, (edit) => {
    const fields = asObject(edit)
    asText(fields.name)
    optional(fields.originalName, asText)
    optional(fields.value, asText)
  })
  asList(args.environmentIds, asId)
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
  asId(id)
  optional(typedSlug, asText)
  return stepUpOr(async () => {
    const session = await requireSession()
    await requireEnvironmentAccess(session.userId, id)
    await requireEnvironmentDeletionTyped({ environmentId: id, typed: typedSlug })
    await requireAdminForProtected({ ...session, environmentIds: [id] })
    await deleteEnvironment({ environmentId: id, by: { userId: session.userId, request: getActionRequest() } })
    return { ok: true }
  })
}

export async function createEnvAction({ name, slug, projectId }: {
  name: string
  slug: string
  projectId: string
}) {
  asText(name)
  asText(slug)
  asId(projectId)
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
  asId(id)
  optional(name, asText)
  optional(slug, asText)
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
  asId(orgId)
  optional(projectIds, (value) => asList(value, asId))
  return stepUpOr(async () => {
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
  asId(invitationId)
  const session = await requireSession()
  const orgId = await joinOrgByInvite({ invitationId, userId: session.userId })
  throw redirect(router.href('/dash/orgs/:orgId', { orgId }))
}

export async function updateOrgMemberRoleAction({ memberId, role }: {
  memberId: string
  role: 'admin' | 'member'
}) {
  asId(memberId)
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

    await setOrgMemberRole({ member, role, by: { userId: session.userId, request: getActionRequest() } })

    return { id: member.id, role }
  })
}

export async function removeOrgMemberAction({ memberId }: { memberId: string }) {
  asId(memberId)
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

    await deleteOrgMember(member, { userId: session.userId, request: getActionRequest() })
    return { id: member.id }
  })
}

// ── Session actions ─────────────────────────────────────────────────

export async function endSessionAction({ sessionId }: { sessionId: string }) {
  asId(sessionId)
  await requireSession()
  await endUserSession(getActionRequest(), sessionId)
}

export async function endOtherSessionsAction() {
  await requireSession()
  await endOtherUserSessions(getActionRequest())
}

// ── API Token actions ───────────────────────────────────────────────
// Through tokens.ts, which checks who may

// The signed-in person changing a token, and their request
async function tokenLogin() {
  const { userId, sessionId } = await requireSession()
  return { userId, sessionId, request: getActionRequest() }
}

export async function createTokenAction({ name, projectId, environmentIds, expiresInDays, protectedAccess }: {
  name: string
  projectId: string
  environmentIds?: string[]
  expiresInDays: number
  // A machine token, which reads protected environments without a passkey
  protectedAccess?: boolean
}) {
  asText(name)
  asId(projectId)
  optional(environmentIds, (value) => asList(value, asId))
  asOneOf(expiresInDays, TOKEN_EXPIRY_DAYS)
  optional(protectedAccess, asBool)
  return stepUpOr(async () => createToken({ ...await tokenLogin(), name, projectId, environmentIds, expiresInDays, protectedAccess }))
}

export async function deleteTokenAction({ tokenId }: { tokenId: string }) {
  asId(tokenId)
  return stepUpOr(async () => {
    await deleteToken({ ...await tokenLogin(), tokenId })
    return { ok: true }
  })
}

// A new value and expiry for the same token; the value before keeps working
// for graceDays. Shows the new key once, like making one.
export async function regenerateTokenAction({ tokenId, prefix, expiresInDays, graceDays }: { tokenId: string; prefix: string; expiresInDays: number; graceDays: number }) {
  asId(tokenId)
  asString(prefix)
  asOneOf(expiresInDays, TOKEN_EXPIRY_DAYS)
  asOneOf(graceDays, GRACE_DAYS)
  return stepUpOr(async () => regenerateToken({ ...await tokenLogin(), tokenId, prefix, expiresInDays, graceDays }))
}

export async function stopPreviousValueAction({ tokenId }: { tokenId: string }) {
  asId(tokenId)
  return stepUpOr(async () => {
    await stopPreviousValue({ ...await tokenLogin(), tokenId })
    return { ok: true }
  })
}

// ── Workload identities ─────────────────────────────────────────────
// Trust rules (workload.ts), each change an org admin's with their passkey

export async function createTrustRuleAction(rule: TrustRuleInput) {
  const fields = asObject(rule)
  const checked: TrustRuleInput = {
    projectId: asId(fields.projectId),
    name: asText(fields.name),
    issuer: asText(fields.issuer),
    jwks: optional(fields.jwks, asText),
    audience: asText(fields.audience),
    subject: asText(fields.subject),
    claims: asStringRecord(fields.claims),
    environmentIds: asList(fields.environmentIds, asId),
    protectedAccess: asBool(fields.protectedAccess),
    expiresInDays: asOneOf(fields.expiresInDays, TOKEN_EXPIRY_DAYS),
  }
  return stepUpOr(async () => {
    const session = await requireSession()
    return createTrustRule({ userId: session.userId, sessionId: session.sessionId, request: getActionRequest(), ownHost: new URL(getActionRequest().url).hostname, rule: checked })
  })
}

export async function deleteTrustRuleAction({ ruleId }: { ruleId: string }) {
  asId(ruleId)
  return stepUpOr(async () => {
    const session = await requireSession()
    await deleteTrustRule({ userId: session.userId, sessionId: session.sessionId, request: getActionRequest(), ruleId })
    return { ok: true }
  })
}

export async function replaceTrustRuleKeysAction({ ruleId, jwks }: { ruleId: string; jwks: string }) {
  asId(ruleId)
  asText(jwks)
  return stepUpOr(async () => {
    const session = await requireSession()
    await replaceTrustRuleKeys({ userId: session.userId, sessionId: session.sessionId, request: getActionRequest(), ruleId, jwks })
    return { ok: true }
  })
}

// A new expiry for the same rule, which becomes the renewing admin's
export async function renewTrustRuleAction({ ruleId, expiresInDays }: { ruleId: string; expiresInDays: number }) {
  asId(ruleId)
  asOneOf(expiresInDays, TOKEN_EXPIRY_DAYS)
  return stepUpOr(async () => {
    const session = await requireSession()
    const request = getActionRequest()
    return renewTrustRule({ userId: session.userId, sessionId: session.sessionId, request, ownHost: new URL(request.url).hostname, ruleId, expiresInDays })
  })
}

// What the renewal dialog shows about a rule's use, for org admins
export async function trustRuleEvidenceAction({ ruleId }: { ruleId: string }) {
  asId(ruleId)
  const session = await requireSession()
  return trustRuleEvidence({ userId: session.userId, ruleId })
}

export async function syncMissingSecretsAction(args: {
  sourceEnvironmentId: string
  targetEnvironmentId: string
  names: string[]
}) {
  asId(args.sourceEnvironmentId)
  asId(args.targetEnvironmentId)
  asList(args.names, asText)
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
  asText(name)
  optional(enableAutoJoin, asBool)
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
  asId(orgId)
  asBool(enabled)
  return stepUpOr(async () => {
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
  asId(memberId)
  nullable(projectIds, (value) => asList(value, asId))
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
  asId(environmentId)
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
  asId(environmentId)
  asBool(protect)
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
  asId(projectId)
  asText(name)
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
  asId(projectId)
  asText(typedName)
  return stepUpOr(async () => {
    const session = await requireSession()
    await requireProjectChange({ ...session, projectId })
    await requireProjectDeletionTyped({ projectId, typed: typedName })
    const project = await getDb().query.project.findFirst({ where: { id: projectId }, columns: { orgId: true } })
    await deleteProject({ projectId, by: { userId: session.userId, request: getActionRequest() } })
    throw redirect(project ? router.href('/dash/orgs/:orgId', { orgId: project.orgId }) : router.href('/dash'))
  })
}

// A member leaves an organization, as if an admin removed them: auto-join
// doesn't add them back. The last admin can't leave.
export async function leaveOrgAction({ orgId }: { orgId: string }) {
  asId(orgId)
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
  await deleteOrgMember(member, { userId: session.userId, request: getActionRequest() })
  throw redirect(router.href('/dash'))
}

export async function deleteOrgAction({ orgId, typedName }: { orgId: string; typedName: string }) {
  asId(orgId)
  asText(typedName)
  return stepUpOr(async () => {
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
