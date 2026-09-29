/**
 * Workload identity. A GitHub Actions job, a Kubernetes pod or another
 * workload exchanges the JWT its platform issues for an API token of one
 * hour, when a trust rule of the project accepts that JWT.
 *
 * A rule names the issuer, the keys its JWTs are signed with (through OIDC
 * discovery, or pasted by an admin for a cluster Cloudflare can't reach), and
 * the audience, subject and further claims a JWT must carry, each exactly.
 * The token a workload gets is an ordinary api_token row acting for the
 * rule's creator, so every check of API tokens applies to it, and the read
 * log shows the job or pod behind each read.
 */

import * as jose from 'jose'
import * as orm from 'drizzle-orm'
import { ulid } from 'ulid'
import { getDb, schema } from 'db'
import { ForbiddenError, InvalidInputError, generateApiToken, getProjectMemberAccess, isAllowed, requireValidName } from './db.ts'
import { requireAdminWithPasskey } from './step-up.ts'
import { securityEvent } from './security-log.ts'
import { GITHUB_ISSUER, MACHINE_TOKEN_MAX_DAYS, TOKEN_EXPIRY_DAYS } from './lib/utils.ts'

export const WORKLOAD_TOKEN_MS = 60 * 60 * 1000
const ALGORITHMS = ['RS256', 'ES256']
const CLOCK_TOLERANCE_S = 60
// Kubelets renew a pod's token after a day at most
const MAX_TOKEN_AGE_S = 24 * 60 * 60
const MAX_JWT_LENGTH = 16 * 1024
const MAX_CLAIMS_LENGTH = 8 * 1024
const MAX_DOCUMENT_BYTES = 64 * 1024
const MAX_KEYS = 100
const MAX_CLAIM_RULES = 20
// Anyone can send a JWT with an unknown key id, so it refetches an issuer's
// keys at most this often
const REFRESH_FLOOR_MS = 5 * 60 * 1000
// And once a day anyway, so keys the issuer dropped stop working
const KEYS_MAX_AGE_MS = 24 * 60 * 60 * 1000
const MAX_NAME_LENGTH = 100
const DAY_MS = 86_400_000

type Jwks = { keys: Array<Record<string, unknown>> }
type Rule = typeof schema.trustRule.$inferSelect

// An exchange refused, with the status the API answers
export class WorkloadError extends Error {
  constructor(message: string, readonly status = 403) {
    super(message)
    this.name = 'WorkloadError'
  }
}

// ── Keys ────────────────────────────────────────────────────────────

// The only URLs the Worker fetches that someone typed: https on the default
// port, a host name rather than an address, and not this instance
function checkedUrl(value: string, ownHost: string): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new InvalidInputError(`Not a URL: ${value}`)
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash) {
    throw new InvalidInputError(`${value} must be an https URL without a port, query or credentials`)
  }
  if (/^[\d.]+$/.test(url.hostname) || url.hostname.startsWith('[') || url.hostname === ownHost) {
    throw new InvalidInputError(`${url.hostname} can't be fetched: it must be another host's name`)
  }
  return url
}

// No redirects, 5 seconds, 64 KiB, and nothing of it ever goes back to a caller
async function fetchJson(url: URL): Promise<unknown> {
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } })
    .catch(() => { throw new InvalidInputError(`${url.href} didn't answer`) })
  if (res.status !== 200) throw new InvalidInputError(`${url.href} answered ${res.status}`)
  const tooLarge = new InvalidInputError(`${url.href} answered with more than ${MAX_DOCUMENT_BYTES / 1024} KiB`)
  if (Number(res.headers.get('content-length')) > MAX_DOCUMENT_BYTES) throw tooLarge
  const reader = res.body!.getReader()
  const decoder = new TextDecoder()
  let text = ''
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > MAX_DOCUMENT_BYTES) {
      await reader.cancel()
      throw tooLarge
    }
    text += decoder.decode(value, { stream: true })
  }
  try {
    return JSON.parse(text + decoder.decode())
  } catch {
    throw new InvalidInputError(`${url.href} didn't answer with JSON`)
  }
}

// The issuer's keys through OIDC discovery. Its document must name the
// issuer exactly, or another issuer's keys would be trusted for this one.
async function discoverKeys(issuer: string, ownHost: string): Promise<{ jwksUri: string; jwks: Jwks }> {
  const base = checkedUrl(issuer, ownHost)
  const document = await fetchJson(new URL(`${base.href.replace(/\/$/, '')}/.well-known/openid-configuration`)) as { issuer?: unknown; jwks_uri?: unknown } | null
  if (document?.issuer !== issuer) throw new InvalidInputError(`The discovery document of ${issuer} names another issuer: ${String(document?.issuer)}`)
  if (typeof document.jwks_uri !== 'string') throw new InvalidInputError(`The discovery document of ${issuer} has no jwks_uri`)
  const jwksUrl = checkedUrl(document.jwks_uri, ownHost)
  return { jwksUri: jwksUrl.href, jwks: await parseJwks(await fetchJson(jwksUrl)) }
}

// The keys of a key set that verify RS256 or ES256 signatures
export async function parseJwks(value: unknown): Promise<Jwks> {
  const keys = (value as { keys?: unknown } | null)?.keys
  if (!Array.isArray(keys)) throw new InvalidInputError('Not a key set (JWKS): it has no "keys" list')
  const usable: Jwks['keys'] = []
  for (const key of keys.slice(0, MAX_KEYS)) {
    if (!key || typeof key !== 'object') continue
    const { kty, crv, use, d, alg: named } = key as Record<string, unknown>
    if (d !== undefined) throw new InvalidInputError('That key set holds a private key: paste only the public keys')
    if (use !== undefined && use !== 'sig') continue
    const alg = kty === 'RSA' ? 'RS256' : kty === 'EC' && crv === 'P-256' ? 'ES256' : null
    // jose picks a key only for the algorithm it names
    if (!alg || (named !== undefined && named !== alg) || !await jose.importJWK(key as jose.JWK, alg).then(() => true, () => false)) continue
    usable.push(key as Record<string, unknown>)
  }
  if (usable.length === 0) throw new InvalidInputError('The key set has no RSA or P-256 signing key')
  return { keys: usable }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    throw new InvalidInputError('Paste the keys as JSON, as `kubectl get --raw /openid/v1/jwks` prints them')
  }
}

// An issuer's keys again. The fetch is claimed first, so requests that
// arrive together fetch once, and a failed fetch keeps the old keys.
async function refreshKeys(rule: Rule, ownHost: string, floorMs: number): Promise<Rule | null> {
  const db = getDb()
  const jwksFetchedAt = Date.now()
  const claimed = await db.update(schema.trustRule).set({ jwksFetchedAt })
    .where(orm.and(
      orm.eq(schema.trustRule.id, rule.id),
      orm.or(orm.isNull(schema.trustRule.jwksFetchedAt), orm.lt(schema.trustRule.jwksFetchedAt, jwksFetchedAt - floorMs)),
    ))
    .returning({ id: schema.trustRule.id })
  if (claimed.length === 0) return null
  const jwks = await fetchJson(checkedUrl(rule.jwksUri!, ownHost)).then(parseJwks).catch(() => null)
  if (!jwks) return null
  await db.update(schema.trustRule).set({ jwks }).where(orm.eq(schema.trustRule.id, rule.id))
  return { ...rule, jwks, jwksFetchedAt }
}

// ── Matching ────────────────────────────────────────────────────────

// A claim by name, or a nested one by JSON pointer (/kubernetes.io/namespace)
function claimAt(payload: Record<string, unknown>, key: string): unknown {
  const path = key.startsWith('/') ? key.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')) : [key]
  let value: unknown = payload
  for (const name of path) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, name)) return undefined
    value = (value as Record<string, unknown>)[name]
  }
  return value
}

function matchesClaims(payload: Record<string, unknown>, claims: Record<string, string>): boolean {
  return Object.entries(claims).every(([key, expected]) => {
    const value = claimAt(payload, key)
    return (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') && String(value) === expected
  })
}

function verifyWith(rule: Rule, jwt: string) {
  return jose.jwtVerify(jwt, jose.createLocalJWKSet(rule.jwks as jose.JSONWebKeySet), {
    algorithms: ALGORITHMS,
    issuer: rule.issuer,
    audience: rule.audience,
    subject: rule.subject,
    requiredClaims: ['exp', 'iat', 'sub'],
    maxTokenAge: MAX_TOKEN_AGE_S,
    clockTolerance: CLOCK_TOLERANCE_S,
  })
}

// What the read log shows for a token: the rule, and the job or pod
function workloadName(ruleName: string, payload: Record<string, unknown>): string {
  const k8s = payload['kubernetes.io'] as { namespace?: unknown; serviceaccount?: { name?: unknown }; pod?: { name?: unknown } } | undefined
  const text = (value: unknown) => (typeof value === 'string' || typeof value === 'number' ? String(value) : '')
  let detail = text(payload.sub)
  if (typeof payload.repository === 'string') {
    const where = payload.environment ? `environment ${text(payload.environment)}` : text(payload.ref)
    detail = `${payload.repository} ${where} run ${text(payload.run_id)}.${text(payload.run_attempt)}`
  } else if (typeof k8s?.namespace === 'string') {
    detail = `${k8s.namespace}/${text(k8s.serviceaccount?.name)}${k8s.pod?.name ? ` pod ${text(k8s.pod.name)}` : ''}`
  }
  return `${ruleName} · ${detail}`.slice(0, 200)
}

// ── Exchange ────────────────────────────────────────────────────────

/**
 * An API token for a workload's JWT, when exactly one unexpired trust rule
 * accepts it. Until a rule accepts the JWT, a refusal says only what the
 * JWT itself says, never which rules exist, so a stranger can't probe them.
 */
export async function exchangeWorkloadToken({ jwt, project, ruleId, ownHost, ipAddress }: {
  jwt: unknown
  // The project's ID, when several projects trust the same workload. Not
  // its name: names repeat across organizations.
  project?: string
  ruleId?: string
  ownHost: string
  ipAddress: string | null
}): Promise<{ key: string; tokenId: string; expiresAt: number; projectId: string; environmentIds: string[]; ruleId: string; ruleExpiresAt: number; ruleLifetimeStart: number }> {
  if (typeof jwt !== 'string' || jwt.length > MAX_JWT_LENGTH || jwt.split('.').length !== 3) throw new WorkloadError('Not a JWT', 400)
  let header: jose.ProtectedHeaderParameters
  let unverified: jose.JWTPayload
  try {
    header = jose.decodeProtectedHeader(jwt)
    unverified = jose.decodeJwt(jwt)
  } catch {
    throw new WorkloadError('Not a JWT', 400)
  }
  if (!ALGORITHMS.includes(String(header.alg))) throw new WorkloadError(`JWTs signed with ${String(header.alg)} aren't accepted, only ${ALGORITHMS.join(' and ')}`, 400)
  if (typeof unverified.iss !== 'string' || unverified.iss.length > 512) throw new WorkloadError('The JWT names no issuer', 400)
  const now = Date.now()
  if (typeof unverified.exp !== 'number' || (unverified.exp + CLOCK_TOLERANCE_S) * 1000 < now) throw new WorkloadError('The JWT has expired, or never does', 401)
  if (typeof unverified.iat !== 'number' || now - unverified.iat * 1000 > MAX_TOKEN_AGE_S * 1000) throw new WorkloadError('The JWT is older than 24 hours, or doesn\'t say when it was issued', 401)

  const db = getDb()
  const rules = await db.query.trustRule.findMany({
    where: { issuer: unverified.iss, expiresAt: { gt: now }, ...(ruleId ? { id: ruleId } : {}), ...(project ? { projectId: project } : {}) },
  })
  const accepted: Array<{ rule: Rule; payload: jose.JWTPayload; kid: string | null }> = []
  for (const candidate of rules) {
    const stale = candidate.jwksUri && now - (candidate.jwksFetchedAt ?? 0) > KEYS_MAX_AGE_MS
    const rule = (stale && await refreshKeys(candidate, ownHost, KEYS_MAX_AGE_MS)) || candidate
    const result = await verifyWith(rule, jwt).catch(async (error) => {
      // An issuer's new key
      if (!(error instanceof jose.errors.JWKSNoMatchingKey) || !rule.jwksUri) return null
      const refreshed = await refreshKeys(rule, ownHost, REFRESH_FLOOR_MS)
      return refreshed && verifyWith(refreshed, jwt).catch(() => null)
    })
    if (result && matchesClaims(result.payload, rule.claims)) accepted.push({ rule, payload: result.payload, kid: result.protectedHeader.kid ?? null })
  }
  if (accepted.length === 0) {
    throw new WorkloadError(`No trust rule accepts this JWT (issuer ${unverified.iss}, subject ${String(unverified.sub)}, audience ${JSON.stringify(unverified.aud)})`)
  }
  if (accepted.length > 1) throw new WorkloadError('Several trust rules accept this JWT: name the project or the rule', 409)
  const { rule, payload, kid } = accepted[0]!
  if (JSON.stringify(payload).length > MAX_CLAIMS_LENGTH) throw new WorkloadError('The JWT carries more than 8 KiB of claims', 400)

  // Its tokens act for its creator, while they are an org admin who may sign in
  const creator = await db.query.user.findFirst({ where: { id: rule.createdBy }, columns: { email: true, emailVerified: true } })
  const access = creator && isAllowed(creator) ? await getProjectMemberAccess(rule.createdBy, rule.projectId) : null
  if (access?.role !== 'admin') throw new WorkloadError('The admin who owns this trust rule no longer is one: another admin has to renew it on the project\'s Machines tab')
  const existing = await db.query.environment.findMany({ where: { projectId: rule.projectId }, columns: { id: true } })
  const environmentIds = rule.environmentIds.filter((id) => existing.some((env) => env.id === id))
  if (rule.environmentIds.length > 0 && environmentIds.length === 0) throw new WorkloadError("None of this trust rule's environments exists any more")

  const { key, hashedKey, prefix } = await generateApiToken()
  const tokenId = ulid()
  const expiresAt = Math.min(now + WORKLOAD_TOKEN_MS, rule.expiresAt)
  await db.batch([
    db.insert(schema.apiToken).values({
      id: tokenId,
      name: workloadName(rule.name, payload),
      projectId: rule.projectId,
      prefix,
      hashedKey,
      createdBy: rule.createdBy,
      expiresAt,
      lastUsedAt: now,
      lastUsedIp: ipAddress,
      protectedAccess: rule.protectedAccess,
      trustRuleId: rule.id,
      workload: { kid, claims: payload },
    }),
    ...environmentIds.map((environmentId) => db.insert(schema.apiTokenEnvironment).values({ tokenId, environmentId })),
    db.update(schema.trustRule).set({ lastUsedAt: now }).where(orm.eq(schema.trustRule.id, rule.id)),
  ])
  return { key, tokenId, expiresAt, projectId: rule.projectId, environmentIds, ruleId: rule.id, ruleExpiresAt: rule.expiresAt, ruleLifetimeStart: rule.renewedAt ?? rule.createdAt }
}

// ── Rules ───────────────────────────────────────────────────────────

export type TrustRuleInput = {
  projectId: string
  name: string
  issuer: string
  // Pasted keys, as JSON. Without them, the keys come from OIDC discovery.
  jwks?: string
  audience: string
  subject: string
  claims: Record<string, string>
  environmentIds: string[]
  protectedAccess: boolean
  expiresInDays: number
}

export async function createTrustRule({ userId, sessionId, request = null, ownHost, rule }: {
  userId: string
  sessionId: string
  request?: Request | null
  ownHost: string
  rule: TrustRuleInput
}): Promise<{ id: string }> {
  requireValidName(rule.name)
  if (rule.name.length > MAX_NAME_LENGTH) throw new InvalidInputError(`Name it in ${MAX_NAME_LENGTH} characters at most`)
  if (!Array.isArray(rule.environmentIds) || !rule.environmentIds.every((id) => typeof id === 'string')) throw new InvalidInputError('Environments must be a list of IDs')
  if (!rule.claims || typeof rule.claims !== 'object' || Array.isArray(rule.claims)) throw new InvalidInputError('Claims must map names to values')
  const [issuer, audience, subject] = [rule.issuer.trim(), rule.audience.trim(), rule.subject.trim()]
  for (const [label, value] of [['Issuer', issuer], ['Audience', audience], ['Subject', subject]] as const) {
    if (!value || value.length > 512) throw new InvalidInputError(`${label} is required, and at most 512 characters`)
  }
  const claims: Record<string, string> = Object.fromEntries(Object.entries(rule.claims).map(([name, value]) => [name.trim(), String(value).trim()]).filter(([name]) => name))
  if (Object.keys(claims).length > MAX_CLAIM_RULES || Object.entries(claims).some(([name, value]) => name.length > 200 || !value || value.length > 512)) {
    throw new InvalidInputError(`Up to ${MAX_CLAIM_RULES} further claims, each with a name and a value`)
  }
  if (!TOKEN_EXPIRY_DAYS.some((days) => days === rule.expiresInDays)) throw new InvalidInputError(`Expiry must be one of ${TOKEN_EXPIRY_DAYS.join(', ')} days`)
  if (rule.protectedAccess && rule.expiresInDays > MACHINE_TOKEN_MAX_DAYS) {
    throw new InvalidInputError(`A rule for protected environments expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  }
  await requireAdminWithPasskey({ userId, sessionId, projectId: rule.projectId })
  const db = getDb()
  const environmentIds = [...new Set(rule.environmentIds)]
  if (environmentIds.length > 0) {
    const found = await db.query.environment.findMany({ where: { projectId: rule.projectId, id: { in: environmentIds } }, columns: { id: true } })
    if (found.length < environmentIds.length) throw new InvalidInputError('Environment not found in this project')
  }
  const keys = rule.jwks?.trim()
    ? { jwksUri: null, jwks: await parseJwks(parseJson(rule.jwks)), jwksFetchedAt: null }
    : { ...await discoverKeys(issuer, ownHost), jwksFetchedAt: Date.now() }
  const id = ulid()
  const expiresAt = Date.now() + rule.expiresInDays * DAY_MS
  await db.batch([
    db.insert(schema.trustRule).values({
      id,
      projectId: rule.projectId,
      name: rule.name,
      issuer,
      ...keys,
      audience,
      subject,
      claims,
      environmentIds,
      protectedAccess: rule.protectedAccess,
      createdBy: userId,
      expiresAt,
    }),
    ruleEvent({ userId, request, kind: 'rule.created', rule: { id, name: rule.name, projectId: rule.projectId }, details: { protected: rule.protectedAccess, expiresAt } }),
  ])
  return { id }
}

async function findRule(ruleId: string) {
  const rule = await getDb().query.trustRule.findFirst({ where: { id: ruleId }, with: { creator: { columns: { id: true, name: true } } } })
  if (!rule) throw new InvalidInputError('Trust rule not found')
  return rule
}

function ruleEvent({ userId, request, kind, rule, details }: {
  userId: string
  request: Request | null
  kind: 'rule.created' | 'rule.renewed' | 'rule.deleted' | 'rule.keys_replaced'
  rule: { id: string; name: string; projectId: string }
  details: Record<string, unknown>
}) {
  return securityEvent({ request, author: { userId, apiTokenId: null }, kind, where: { projectId: rule.projectId }, subject: { id: rule.id, name: rule.name }, details })
}

// Its tokens stop with it. Their rows stay, for the read log.
export async function deleteTrustRule({ userId, sessionId, request = null, ruleId }: { userId: string; sessionId: string; request?: Request | null; ruleId: string }) {
  const rule = await findRule(ruleId)
  await requireAdminWithPasskey({ userId, sessionId, projectId: rule.projectId })
  const db = getDb()
  const now = Date.now()
  await db.batch([
    db.update(schema.apiToken).set({ expiresAt: now }).where(orm.and(orm.eq(schema.apiToken.trustRuleId, ruleId), orm.gt(schema.apiToken.expiresAt, now))),
    ruleEvent({ userId, request, kind: 'rule.deleted', rule, details: { protected: rule.protectedAccess } }),
    db.delete(schema.trustRule).where(orm.eq(schema.trustRule.id, ruleId)),
  ])
}

// After a private cluster rotates its signing key, its admin pastes the new
// key set. Rules with discovered keys refresh on their own.
export async function replaceTrustRuleKeys({ userId, sessionId, request = null, ruleId, jwks }: { userId: string; sessionId: string; request?: Request | null; ruleId: string; jwks: string }) {
  const rule = await findRule(ruleId)
  if (rule.jwksUri) throw new InvalidInputError('This rule gets its keys from its issuer')
  await requireAdminWithPasskey({ userId, sessionId, projectId: rule.projectId })
  const keys = await parseJwks(parseJson(jwks))
  const db = getDb()
  await db.batch([
    db.update(schema.trustRule).set({ jwks: keys }).where(orm.eq(schema.trustRule.id, ruleId)),
    ruleEvent({ userId, request, kind: 'rule.keys_replaced', rule, details: { keyIds: keyIdsOf(keys) } }),
  ])
}

function keyIdsOf(jwks: Jwks): string[] {
  return jwks.keys.map((key) => String(key.kid ?? '')).filter(Boolean)
}

// ── Renewal ─────────────────────────────────────────────────────────

// A rule renewed in place keeps its id, the identity ESO names, and gets a
// new expiry: nothing that uses it changes. The admin who renews it vouches
// for its fields again and owns it from then on, so its tokens act for them.
// An expired rule can be renewed too. Keys from discovery are fetched again,
// and the renewal fails when the issuer no longer answers.
export async function renewTrustRule({ userId, sessionId, request = null, ownHost, ruleId, expiresInDays }: {
  userId: string
  sessionId: string
  request?: Request | null
  ownHost: string
  ruleId: string
  expiresInDays: number
}): Promise<{ id: string; expiresAt: number }> {
  const rule = await findRule(ruleId)
  if (!TOKEN_EXPIRY_DAYS.some((days) => days === expiresInDays)) throw new InvalidInputError(`Expiry must be one of ${TOKEN_EXPIRY_DAYS.join(', ')} days`)
  if (rule.protectedAccess && expiresInDays > MACHINE_TOKEN_MAX_DAYS) {
    throw new InvalidInputError(`A rule for protected environments expires after ${MACHINE_TOKEN_MAX_DAYS} days at most`)
  }
  await requireAdminWithPasskey({ userId, sessionId, projectId: rule.projectId })
  const keys = rule.jwksUri ? { ...await discoverKeys(rule.issuer, ownHost), jwksFetchedAt: Date.now() } : {}
  const now = Date.now()
  const expiresAt = now + expiresInDays * DAY_MS
  const db = getDb()
  await db.batch([
    db.update(schema.trustRule)
      .set({ ...keys, expiresAt, renewedAt: now, renewals: orm.sql`${schema.trustRule.renewals} + 1`, createdBy: userId })
      .where(orm.eq(schema.trustRule.id, ruleId)),
    ruleEvent({
      userId, request, kind: 'rule.renewed', rule,
      details: { expiresAt, previousExpiresAt: rule.expiresAt, wasExpired: rule.expiresAt <= now, previousOwner: { id: rule.createdBy, name: rule.creator?.name ?? null } },
    }),
  ])
  return { id: rule.id, expiresAt }
}

const MONTH_MS = 30 * DAY_MS

// What the renewal dialog shows before an admin vouches for a rule again:
// how it has been used, which workloads got its tokens, and what looks
// stale. Drift, a renamed repository or a recreated service account, is
// what expiry is there to catch.
export async function trustRuleEvidence({ userId, ruleId, now = Date.now() }: { userId: string; ruleId: string; now?: number }) {
  const db = getDb()
  const rule = await findRule(ruleId)
  const access = await getProjectMemberAccess(userId, rule.projectId)
  if (access?.role !== 'admin') throw new ForbiddenError('Only admins can do this')
  const [recent, [counts], owner] = await Promise.all([
    db.query.apiToken.findMany({
      where: { trustRuleId: ruleId },
      columns: { id: true, name: true, createdAt: true, lastUsedIp: true, workload: true },
      orderBy: { createdAt: 'desc' },
      limit: 100,
    }),
    db.select({
      total: orm.count(),
      lastMonth: orm.sql<number>`coalesce(sum(case when ${schema.apiToken.createdAt} > ${now - MONTH_MS} then 1 else 0 end), 0)`,
    }).from(schema.apiToken).where(orm.eq(schema.apiToken.trustRuleId, ruleId)),
    db.query.user.findFirst({ where: { id: rule.createdBy }, columns: { email: true, emailVerified: true } })
      .then((user) => user && isAllowed(user) ? getProjectMemberAccess(rule.createdBy, rule.projectId) : null),
  ])
  const github = rule.issuer === GITHUB_ISSUER
  const warnings: string[] = []
  if (rule.lastUsedAt === null) warnings.push('Never used: no workload has got a token under it. Delete it instead?')
  else if (now - rule.lastUsedAt > 2 * MONTH_MS) warnings.push('Not used in 60 days. Delete it instead?')
  if (owner?.role !== 'admin') warnings.push(`${rule.creator?.name ?? 'Its owner'} is no longer an admin: its tokens don't work until an admin renews it.`)
  if (github && /^repo:[^@:/]+\/[^@:]+:/.test(rule.subject) && !rule.claims.repository_id) {
    warnings.push('Its subject names the repository, not its ID: a repository that takes over the name after a rename would match.')
  }
  if (github && rule.protectedAccess && !rule.subject.includes(':environment:')) {
    warnings.push('Without a GitHub environment, anyone who can push to the branch reads these environments. Name an environment with required reviewers.')
  }
  if (now - rule.createdAt > 365 * DAY_MS) warnings.push('Made over a year ago: consider making it again with today\'s IDs.')
  return {
    exchanges: {
      total: counts?.total ?? 0,
      lastMonth: Number(counts?.lastMonth ?? 0),
      last: recent.slice(0, 5).map((token) => ({ id: token.id, name: token.name.replace(`${rule.name} · `, ''), createdAt: token.createdAt, ipAddress: token.lastUsedIp })),
    },
    seen: identitiesSeen(rule, recent.map((token) => token.workload?.claims ?? {})),
    keys: { discovered: rule.jwksUri !== null, fetchedAt: rule.jwksFetchedAt, keyIds: keyIdsOf(rule.jwks) },
    warnings,
  }
}

// Who got tokens under a rule, from the verified JWTs of its last exchanges:
// for GitHub its actors, refs, events, runners and repositories; for
// Kubernetes its pods, by name without the random part, and their nodes;
// otherwise their subjects
function identitiesSeen(rule: Rule, claims: Record<string, unknown>[]): Array<{ label: string; values: string[] }> {
  const distinct = (label: string, pick: (claims: Record<string, unknown>) => unknown) => ({
    label,
    values: [...new Set(claims.map(pick).filter((value) => typeof value === 'string' || typeof value === 'number').map(String))].sort(),
  })
  const found = (seen: Array<{ label: string; values: string[] }>) => seen.filter(({ values }) => values.length > 0)
  if (rule.issuer === GITHUB_ISSUER || claims.some((c) => typeof c.repository === 'string')) {
    return found([
      distinct('actors', (c) => c.actor),
      distinct('refs', (c) => c.ref),
      distinct('events', (c) => c.event_name),
      distinct('runners', (c) => c.runner_environment),
      distinct('repositories', (c) => c.repository),
    ])
  }
  if (claims.some((c) => c['kubernetes.io'])) {
    const pod = (c: Record<string, unknown>) => claimAt(c, '/kubernetes.io/pod/name')
    return found([
      distinct('pods', (c) => typeof pod(c) === 'string' ? (pod(c) as string).replace(/(-[a-z0-9]{5,10})?-[a-z0-9]{5}$/, '') : undefined),
      distinct('nodes', (c) => claimAt(c, '/kubernetes.io/node/name')),
    ])
  }
  return found([distinct('subjects', (c) => c.sub)])
}
