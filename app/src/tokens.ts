// API tokens: making, regenerating and deleting them, stopping a previous
// value early, and which tokens and trust rules expire soon.
//
// Regenerating a token keeps its row, so its id, name, scope, creator and
// history stay, and gives it a new value and a new expiry. The value before
// keeps working for a grace period of 0, 1 or 7 days, never past its own
// expiry, so CI can switch over; verifyApiToken (db.ts) accepts either. The
// token keeps acting for its creator: an admin regenerating a member's token
// doesn't widen it to the admin's access.
//
// Each change writes its security log row in the same batch
// (security-log.ts). The actions in actions.ts wrap these for the web UI.

import * as orm from 'drizzle-orm'
import { ulid } from 'ulid'
import { getDb, schema } from 'db'
import {
  generateApiToken, getEnvironmentAccessError, getMemberAccess, getOrgIdForProject, getProjectMemberAccess, requireValidName, tokenCreatorError,
} from './db.ts'
import { requireMachineTokenApproval, requireMachineTokenDeletion, requirePasskeyOnceEnrolled, requireTokenDeletion } from './step-up.ts'
import { securityEvent } from './security-log.ts'
import { GRACE_DAYS, MACHINE_TOKEN_MAX_DAYS, TOKEN_EXPIRY_DAYS, describeExpiry, warnWindow } from './lib/utils.ts'

const DAY_MS = 86_400_000

// The signed-in person changing a token, and their request, for the IP
type Login = { userId: string; sessionId: string; request?: Request | null }

// A token reads every secret in its scope, so making, regenerating or
// deleting one needs access to that whole scope: the listed envs, or every
// env of the project for a project-wide token (no env ids). Admin-only envs
// added later stay safe: token use re-checks that the creator is still an admin.
export async function requireTokenScopeAccess({ userId, projectId, environmentIds }: {
  userId: string
  projectId: string
  environmentIds: string[]
}) {
  const orgId = await getOrgIdForProject(projectId)
  if (!orgId) throw new Error('Project not found')
  const [access, envs] = await Promise.all([
    getMemberAccess({ userId, orgId }),
    getDb().query.environment.findMany({
      where: environmentIds.length > 0 ? { projectId, id: { in: environmentIds } } : { projectId },
      columns: { projectId: true, accessRole: true },
    }),
  ])
  if (!access || (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(projectId))) {
    throw new Error('You do not have access to this project')
  }
  if (envs.length < environmentIds.length) throw new Error('Environment not found in this project')
  for (const env of envs) {
    const error = getEnvironmentAccessError(access, env)
    if (error) throw new Error(error)
  }
}

function requireExpiryChoice(expiresInDays: number) {
  if (!TOKEN_EXPIRY_DAYS.some((days) => days === expiresInDays)) throw new Error(`Expiry must be one of ${TOKEN_EXPIRY_DAYS.join(', ')} days`)
}

function tokenEvent({ userId, request, kind, token, details }: {
  userId: string
  request: Request | null
  kind: 'token.created' | 'token.regenerated' | 'token.deleted' | 'token.previous_stopped'
  token: { id: string; name: string | orm.SQL; projectId: string }
  details: Record<string, unknown>
}) {
  return securityEvent({ request, author: { userId, apiTokenId: null }, kind, where: { projectId: token.projectId }, subject: { id: token.id, name: token.name }, details })
}

export async function createToken({ userId, sessionId, request = null, name, projectId, environmentIds = [], expiresInDays, protectedAccess = false }: Login & {
  name: string
  projectId: string
  environmentIds?: string[]
  expiresInDays: number
  // A machine token, which reads protected environments without a passkey
  protectedAccess?: boolean
}): Promise<{ id: string; key: string }> {
  // Token names reach the security log, the CLI and notifications
  requireValidName(name)
  if (!projectId) throw new Error('Project is required')
  requireExpiryChoice(expiresInDays)
  const uniqueEnvIds = Array.from(new Set(environmentIds))
  await requireTokenScopeAccess({ userId, projectId, environmentIds: uniqueEnvIds })
  // A token outlives the session that makes it
  await requirePasskeyOnceEnrolled({ userId, sessionId })
  if (protectedAccess) await requireMachineTokenApproval({ userId, sessionId, projectId, expiresInDays })

  const db = getDb()
  const { key, hashedKey, prefix } = await generateApiToken()
  const id = ulid()
  const expiresAt = Date.now() + expiresInDays * DAY_MS
  await db.batch([
    db.insert(schema.apiToken).values({ id, name: name.trim(), projectId, prefix, hashedKey, createdBy: userId, expiresAt, protectedAccess }),
    ...uniqueEnvIds.map((environmentId) => db.insert(schema.apiTokenEnvironment).values({ tokenId: id, environmentId })),
    tokenEvent({ userId, request, kind: 'token.created', token: { id, name: name.trim(), projectId }, details: { machine: protectedAccess, expiresAt } }),
  ])
  // The only time the key is ever available
  return { id, key }
}

// A token of the Machines tab, with what changing it takes: its creator or
// an org admin, access to its whole scope, and for a machine token an org
// admin. Someone outside its organization gets the same answer as for a token
// that doesn't exist.
async function changeableToken({ userId, sessionId, tokenId }: Login & { tokenId: string }) {
  if (typeof tokenId !== 'string') throw new Error('Invalid input')
  const token = await getDb().query.apiToken.findFirst({
    // A workload's token of an hour is its trust rule's
    where: { id: tokenId, workload: { isNull: true } },
    columns: {
      id: true, name: true, projectId: true, createdBy: true, hashedKey: true, prefix: true, expiresAt: true, protectedAccess: true,
      previousHashedKey: true, previousExpiresAt: true,
    },
    with: { environments: { columns: { environmentId: true } } },
  })
  if (!token || !await getProjectMemberAccess(userId, token.projectId)) throw new Error('Token not found')
  await requireTokenDeletion({ userId, sessionId, token })
  await requireTokenScopeAccess({ userId, projectId: token.projectId, environmentIds: token.environments.map((row) => row.environmentId) })
  return token
}

export async function deleteToken({ userId, sessionId, request = null, tokenId }: Login & { tokenId: string }) {
  const token = await changeableToken({ userId, sessionId, tokenId })
  // Deleting a machine token stops CI: an admin action, like making one
  if (token.protectedAccess) await requireMachineTokenDeletion({ userId, sessionId, projectId: token.projectId })
  const db = getDb()
  await db.batch([
    tokenEvent({ userId, request, kind: 'token.deleted', token, details: { machine: token.protectedAccess } }),
    db.delete(schema.apiToken).where(orm.eq(schema.apiToken.id, token.id)),
  ])
}

const REGENERATED_MEANWHILE = 'Someone regenerated this token meanwhile: reload the page to see its new value\'s expiry'

export async function regenerateToken({ userId, sessionId, request = null, tokenId, prefix, expiresInDays, graceDays }: Login & {
  tokenId: string
  // The prefix of the value the page showed: a regeneration since refuses this one
  prefix: string
  expiresInDays: number
  graceDays: number
}): Promise<{ id: string; key: string; previousExpiresAt: number | null }> {
  requireExpiryChoice(expiresInDays)
  if (!GRACE_DAYS.some((days) => days === graceDays)) throw new Error('The previous value keeps working for 0, 1 or 7 days')
  const token = await changeableToken({ userId, sessionId, tokenId })
  if (token.protectedAccess && expiresInDays > MACHINE_TOKEN_MAX_DAYS) throw new Error(`A machine token expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  if (token.prefix !== prefix) throw new Error(REGENERATED_MEANWHILE)
  // It keeps acting for its creator, so it must still be of use to them
  if (await tokenCreatorError({ createdBy: token.createdBy, projectId: token.projectId, needsAdmin: token.protectedAccess })) {
    throw new Error('Its creator can no longer use this token: make a new one')
  }
  // A new value is standing access, like a new token
  await requirePasskeyOnceEnrolled({ userId, sessionId })
  if (token.protectedAccess) await requireMachineTokenApproval({ userId, sessionId, projectId: token.projectId, expiresInDays })

  const db = getDb()
  const generated = await generateApiToken()
  const now = Date.now()
  const expiresAt = now + expiresInDays * DAY_MS
  // The value before keeps working for the grace, never past its own expiry.
  // An expired one stays expired: then this is a plain replacement.
  const previousExpiresAt = token.expiresAt !== null && token.expiresAt <= now ? null : Math.min(now + graceDays * DAY_MS, token.expiresAt ?? Infinity)
  try {
    await db.batch([
      // Only the value the page showed: of two regenerations at once, one wins
      db.update(schema.apiToken).set({
        hashedKey: generated.hashedKey,
        prefix: generated.prefix,
        expiresAt,
        // The value that was previous until now stops at once
        previousHashedKey: previousExpiresAt === null ? null : token.hashedKey,
        previousExpiresAt,
        previousLastUsedAt: null,
        previousLastUsedIp: null,
        regeneratedAt: now,
        regeneratedBy: userId,
      }).where(orm.and(orm.eq(schema.apiToken.id, token.id), orm.eq(schema.apiToken.hashedKey, token.hashedKey))),
      tokenEvent({
        userId, request, kind: 'token.regenerated',
        // Named from the row with its new value: when another regeneration
        // came first, the update above changed nothing, the name is null,
        // and the whole batch fails
        token: { ...token, name: orm.sql`(select ${schema.apiToken.name} from ${schema.apiToken} where ${schema.apiToken.id} = ${token.id} and ${schema.apiToken.hashedKey} = ${generated.hashedKey})` },
        details: { machine: token.protectedAccess, expiresAt, previousExpiresAt, graceDays },
      }),
    ])
  } catch (error) {
    const current = await db.query.apiToken.findFirst({ where: { id: token.id }, columns: { hashedKey: true } })
    if (!current) throw new Error('Token not found')
    if (current.hashedKey !== token.hashedKey) throw new Error(REGENERATED_MEANWHILE)
    throw error
  }
  return { id: token.id, key: generated.key, previousExpiresAt }
}

// Stops a regenerated token's previous value before its grace ends, once CI
// uses the new one. Takes what deleting the token takes.
export async function stopPreviousValue({ userId, sessionId, request = null, tokenId }: Login & { tokenId: string }) {
  const token = await changeableToken({ userId, sessionId, tokenId })
  if (token.protectedAccess) await requireMachineTokenDeletion({ userId, sessionId, projectId: token.projectId })
  if (!token.previousHashedKey || token.previousExpiresAt === null || token.previousExpiresAt <= Date.now()) {
    throw new Error('Its previous value has already stopped working')
  }
  const db = getDb()
  // Only the value read above: a regeneration since made another value the
  // previous one, which keeps its grace
  const unchanged = orm.and(orm.eq(schema.apiToken.id, token.id), orm.eq(schema.apiToken.previousHashedKey, token.previousHashedKey))
  try {
    await db.batch([
      tokenEvent({
        userId, request, kind: 'token.previous_stopped',
        // Named only while that value is still the previous one: otherwise
        // the name is null, and the whole batch fails before the update below
        // could match nothing
        token: { ...token, name: orm.sql`(select ${schema.apiToken.name} from ${schema.apiToken} where ${unchanged})` },
        details: { machine: token.protectedAccess, previousExpiresAt: token.previousExpiresAt },
      }),
      db.update(schema.apiToken)
        .set({ previousHashedKey: null, previousExpiresAt: null, previousLastUsedAt: null, previousLastUsedIp: null })
        .where(unchanged),
    ])
  } catch (error) {
    const current = await db.query.apiToken.findFirst({ where: { id: token.id }, columns: { previousHashedKey: true } })
    if (!current) throw new Error('Token not found')
    if (current.previousHashedKey !== token.previousHashedKey) throw new Error(REGENERATED_MEANWHILE)
    throw error
  }
}

// ── Expiring soon ───────────────────────────────────────────────────

export type ExpiringCredential = {
  kind: 'token' | 'machine token' | 'trust rule'
  id: string
  name: string
  projectId: string
  projectName: string
  // Null for a token from before tokens expired
  expiresAt: number | null
  // "in 3 days", "never expires"
  when: string
}

// Tokens and trust rules that expire soon (describeExpiry), for the
// dashboard banner: in an organization where the user is an admin, all of
// them, since admins regenerate machine tokens and renew rules; elsewhere the
// tokens they made. Soonest first, those that never expire last.
export async function expiringCredentials({ userId, orgs, now = Date.now() }: {
  userId: string
  orgs: { id: string; role: 'admin' | 'member' }[]
  now?: number
}): Promise<ExpiringCredential[]> {
  const orgIds = orgs.map((org) => org.id)
  const adminOrgIds = orgs.filter((org) => org.role === 'admin').map((org) => org.id)
  if (orgIds.length === 0) return []
  const db = getDb()
  // Not expired yet, and within the longest warning window: describeExpiry
  // below applies each one's own
  const soon = (column: typeof schema.apiToken.expiresAt | typeof schema.trustRule.expiresAt) =>
    orm.and(orm.gt(column, now), orm.lt(column, now + warnWindow(Infinity)))
  const [tokens, rules] = await Promise.all([
    db.select({
      id: schema.apiToken.id, name: schema.apiToken.name, projectId: schema.project.id, projectName: schema.project.name,
      expiresAt: schema.apiToken.expiresAt, createdAt: schema.apiToken.createdAt, regeneratedAt: schema.apiToken.regeneratedAt,
      protectedAccess: schema.apiToken.protectedAccess,
    }).from(schema.apiToken)
      .innerJoin(schema.project, orm.eq(schema.project.id, schema.apiToken.projectId))
      .where(orm.and(
        orm.inArray(schema.project.orgId, orgIds),
        orm.isNull(schema.apiToken.workload),
        orm.or(orm.isNull(schema.apiToken.expiresAt), soon(schema.apiToken.expiresAt)),
        orm.or(orm.inArray(schema.project.orgId, adminOrgIds), orm.eq(schema.apiToken.createdBy, userId)),
      )),
    adminOrgIds.length === 0 ? [] : db.select({
      id: schema.trustRule.id, name: schema.trustRule.name, projectId: schema.project.id, projectName: schema.project.name,
      expiresAt: schema.trustRule.expiresAt, createdAt: schema.trustRule.createdAt, renewedAt: schema.trustRule.renewedAt,
    }).from(schema.trustRule)
      .innerJoin(schema.project, orm.eq(schema.project.id, schema.trustRule.projectId))
      .where(orm.and(orm.inArray(schema.project.orgId, adminOrgIds), soon(schema.trustRule.expiresAt))),
  ])
  const items = [
    ...tokens.map((token) => ({
      kind: token.protectedAccess ? 'machine token' as const : 'token' as const,
      ...token, lifetimeStart: token.regeneratedAt ?? token.createdAt,
    })),
    ...rules.map((rule) => ({ kind: 'trust rule' as const, ...rule, lifetimeStart: rule.renewedAt ?? rule.createdAt })),
  ].flatMap(({ kind, id, name, projectId, projectName, expiresAt, lifetimeStart }) => {
    const expiry = describeExpiry({ expiresAt, lifetimeStart, now })
    return expiry.level === 'warning' ? [{ kind, id, name, projectId, projectName, expiresAt, when: expiry.text }] : []
  })
  return items.sort((a, b) => (a.expiresAt ?? Infinity) - (b.expiresAt ?? Infinity))
}

// The dashboard banner: up to five items, or null when there are none or
// the banner was dismissed for the same soonest one (EXPIRY_BANNER_COOKIE)
export async function expiryBanner({ userId, orgs, dismissed, now = Date.now() }: {
  userId: string
  orgs: { id: string; role: 'admin' | 'member' }[]
  // The cookie's value
  dismissed: string | null
  now?: number
}) {
  const items = await expiringCredentials({ userId, orgs, now })
  if (items.length === 0) return null
  const dismissKey = String(items[0]!.expiresAt ?? 'never')
  if (dismissed === dismissKey) return null
  return { items: items.slice(0, 5), more: Math.max(0, items.length - 5), dismissKey }
}
