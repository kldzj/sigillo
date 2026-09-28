// Schema for the self-hosted app D1 database.
// Contains BetterAuth core tables for local auth (genericOAuth sessions)
// and the secrets domain tables.

import { defineRelations } from 'drizzle-orm'
import * as sqliteCore from 'drizzle-orm/sqlite-core'
import { ulid } from 'ulid'

// Integer column that stores epoch milliseconds as a plain number.
// Unlike integer({ mode: 'number' }), this accepts Date objects in toDriver
// so BetterAuth's internal Date params don't crash D1's .bind() which only
// accepts string | number | null | ArrayBuffer. TypeScript type stays `number`.
export const epochMs = sqliteCore.customType<{ data: number; driverParam: number }>({
  dataType() { return 'integer' },
  toDriver(value: unknown): number {
    if (value instanceof Date) return value.getTime()
    return value as number
  },
  fromDriver(value: unknown): number { return value as number },
})

// ── BetterAuth core tables ──────────────────────────────────────────

export const user = sqliteCore.sqliteTable('user', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull(),
  email: sqliteCore.text('email').notNull().unique(),
  emailVerified: sqliteCore.integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  image: sqliteCore.text('image'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

export const session = sqliteCore.sqliteTable('session', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  token: sqliteCore.text('token').notNull().unique(),
  expiresAt: epochMs('expires_at').notNull(),
  ipAddress: sqliteCore.text('ip_address'),
  userAgent: sqliteCore.text('user_agent'),
  // Made by signing in, not by approving a CLI login from another session:
  // only such a session, and only while fresh, may add a first passkey
  signedIn: sqliteCore.integer('signed_in', { mode: 'boolean' }).notNull().default(false),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('session_user_id_idx').on(table.userId),
])

export const account = sqliteCore.sqliteTable('account', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  accountId: sqliteCore.text('account_id').notNull(),
  providerId: sqliteCore.text('provider_id').notNull(),
  accessToken: sqliteCore.text('access_token'),
  refreshToken: sqliteCore.text('refresh_token'),
  accessTokenExpiresAt: epochMs('access_token_expires_at'),
  refreshTokenExpiresAt: epochMs('refresh_token_expires_at'),
  scope: sqliteCore.text('scope'),
  idToken: sqliteCore.text('id_token'),
  password: sqliteCore.text('password'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('account_user_id_idx').on(table.userId),
])

// ── Step-up (app/src/step-up.ts) ────────────────────────────────────
// A person reads a protected environment only with a grant: a passkey
// approval for one session and some environments, for 15 minutes. The
// browser asks for one on the spot; the CLI opens a request that the user
// approves on /approve by typing its code.
export const stepUpRequest = sqliteCore.sqliteTable('step_up_request', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  // The session that asked, and that gets the grant
  sessionId: sqliteCore.text('session_id').notNull().references(() => session.id, { onDelete: 'cascade' }),
  // access: reading and changing environmentIds; admin: admin actions and managing
  // passkeys; enroll: adding one passkey, approved on another device or by an admin
  purpose: sqliteCore.text('purpose', { enum: ['access', 'admin', 'enroll'] }).notNull(),
  environmentIds: sqliteCore.text('environment_ids', { mode: 'json' }).$type<string[]>().notNull(),
  // Typed on /approve for a CLI request, never part of a link; null when the browser asks for itself
  userCode: sqliteCore.text('user_code'),
  // The WebAuthn challenge of the approval in progress
  challenge: sqliteCore.text('challenge'),
  status: sqliteCore.text('status', { enum: ['pending', 'approved'] }).notNull().default('pending'),
  ipAddress: sqliteCore.text('ip_address'),
  country: sqliteCore.text('country'),
  userAgent: sqliteCore.text('user_agent'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  expiresAt: epochMs('expires_at').notNull(),
}, (table) => [
  sqliteCore.uniqueIndex('step_up_request_user_code_unique').on(table.userCode),
  sqliteCore.index('step_up_request_user_id_idx').on(table.userId),
])

export const stepUpGrant = sqliteCore.sqliteTable('step_up_grant', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  // Ends with the session it was approved for
  sessionId: sqliteCore.text('session_id').notNull().references(() => session.id, { onDelete: 'cascade' }),
  purpose: sqliteCore.text('purpose', { enum: ['access', 'admin', 'enroll'] }).notNull(),
  environmentIds: sqliteCore.text('environment_ids', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  expiresAt: epochMs('expires_at').notNull(),
}, (table) => [
  sqliteCore.index('step_up_grant_session_id_idx').on(table.sessionId),
])

// Every passkey added or removed, shown to the admins of the user's orgs.
// No foreign keys: the history outlives the passkey and the people.
export const passkeyEvent = sqliteCore.sqliteTable('passkey_event', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull(),
  // Who did it: the user, an org admin, or 'self-host' for the recovery command
  actor: sqliteCore.text('actor').notNull(),
  action: sqliteCore.text('action', { enum: ['added', 'removed'] }).notNull(),
  passkeyName: sqliteCore.text('passkey_name'),
  ipAddress: sqliteCore.text('ip_address'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('passkey_event_user_id_idx').on(table.userId),
])

// Passkeys, added and managed through better-auth's passkey plugin. They
// approve reads of protected environments (app/src/step-up.ts) and never
// sign anyone in.
export const passkey = sqliteCore.sqliteTable('passkey', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name'),
  publicKey: sqliteCore.text('public_key').notNull(),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  credentialID: sqliteCore.text('credential_id').notNull(),
  counter: sqliteCore.integer('counter').notNull(),
  deviceType: sqliteCore.text('device_type').notNull(),
  backedUp: sqliteCore.integer('backed_up', { mode: 'boolean' }).notNull(),
  transports: sqliteCore.text('transports'),
  createdAt: epochMs('created_at'),
  aaguid: sqliteCore.text('aaguid'),
}, (table) => [
  sqliteCore.index('passkey_user_id_idx').on(table.userId),
  sqliteCore.index('passkey_credential_id_idx').on(table.credentialID),
])

export const verification = sqliteCore.sqliteTable('verification', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  identifier: sqliteCore.text('identifier').notNull(),
  value: sqliteCore.text('value').notNull(),
  expiresAt: epochMs('expires_at').notNull(),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

// ── Org tables ──────────────────────────────────────────────────────

export const org = sqliteCore.sqliteTable('org', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull(),
  // Email domain for automatic member join (e.g. 'acme.com').
  // When set, any user with a verified email ending in this domain
  // is automatically added as a member on their next dashboard visit.
  // Unique: one org per domain, the first claim wins.
  autoJoinDomain: sqliteCore.text('auto_join_domain'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.uniqueIndex('org_auto_join_domain_unique').on(table.autoJoinDomain),
])

export const orgMember = sqliteCore.sqliteTable('org_member', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  orgId: sqliteCore.text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  role: sqliteCore.text('role', { enum: ['admin', 'member'] }).notNull().default('member'),
  // 'selected' = only projects in member_access (zero rows = no projects).
  // Explicit because deleting a project cascades its member_access rows: when
  // "zero rows" meant "all", deleting a member's last project unlocked all.
  projectAccess: sqliteCore.text('project_access', { enum: ['all', 'selected'] }).notNull().default('all'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('org_member_org_id_idx').on(table.orgId),
  sqliteCore.index('org_member_user_id_idx').on(table.userId),
  sqliteCore.uniqueIndex('org_member_org_id_user_id_unique').on(table.orgId, table.userId),
])

// Someone removed from an org. Auto-join by email domain doesn't add them
// back; accepting an invite does.
export const orgRemoval = sqliteCore.sqliteTable('org_removal', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  orgId: sqliteCore.text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.uniqueIndex('org_removal_org_id_user_id_unique').on(table.orgId, table.userId),
])

// ── Org invitation table ────────────────────────────────────────────
// Secret invite links: anyone with the link can join the org after login.
// No email column — not tied to a specific user. No status column — just
// delete the row when accepted or expired.

export const orgInvitation = sqliteCore.sqliteTable('org_invitation', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  orgId: sqliteCore.text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
  role: sqliteCore.text('role', { enum: ['admin', 'member'] }).notNull().default('member'),
  // JSON array of project IDs the invited user will have access to.
  // null = all projects (unrestricted). When set, acceptInviteAction
  // creates memberAccess rows for each listed project.
  projectIds: sqliteCore.text('project_ids'),
  createdBy: sqliteCore.text('created_by').notNull().references(() => user.id, { onDelete: 'cascade' }),
  expiresAt: epochMs('expires_at').notNull(),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('org_invitation_org_id_idx').on(table.orgId),
])

// ── Secrets domain tables ───────────────────────────────────────────
// Doppler-style hierarchy: org → project → environment → secretEvent
// Each project gets default environments: dev, preview, prod
//
// Secrets use event sourcing: the secretEvent table is an append-only log.
// Current secret values are derived by replaying events per (environmentId, name).
// Events are immutable — never update or delete rows in this table.

export const project = sqliteCore.sqliteTable('project', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull(),
  orgId: sqliteCore.text('org_id').notNull().references(() => org.id, { onDelete: 'cascade' }),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('project_org_id_idx').on(table.orgId),
])

export const environment = sqliteCore.sqliteTable('environment', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  projectId: sqliteCore.text('project_id').notNull().references(() => project.id, { onDelete: 'cascade' }),
  name: sqliteCore.text('name').notNull(),
  slug: sqliteCore.text('slug').notNull(),
  // Minimum org role required to access secrets in this environment.
  // 'member' = everyone, 'admin' = only admins can read/write secrets.
  // Use this to restrict production environments to admins only.
  accessRole: sqliteCore.text('access_role', { enum: ['admin', 'member'] }).notNull().default('member'),
  // Protected environments record every read of their values in secret_read.
  protected: sqliteCore.integer('protected', { mode: 'boolean' }).notNull().default(false),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('environment_project_id_idx').on(table.projectId),
  sqliteCore.uniqueIndex('environment_project_id_slug_unique').on(table.projectId, table.slug),
])

// Append-only event log for secrets. Each row is an immutable event.
// "set" = create or update a secret value. "delete" = remove the secret.
// Current state is derived by taking the last event per (environmentId, name).
// NEVER update or delete rows in this table — it is the audit trail.
export const secretEvent = sqliteCore.sqliteTable('secret_event', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  environmentId: sqliteCore.text('environment_id').notNull().references(() => environment.id, { onDelete: 'cascade' }),
  name: sqliteCore.text('name').notNull(),
  // "set" = create or update, "delete" = remove
  operation: sqliteCore.text('operation', { enum: ['set', 'delete'] }).notNull(),
  // Encrypted with Web Crypto AES-GCM, stored as base64. Null for delete events.
  valueEncrypted: sqliteCore.text('value_encrypted'),
  // AES-GCM initialization vector, stored as base64. Null for delete events.
  iv: sqliteCore.text('iv'),
  // Who performed the action: userId for session auth, apiTokenId for bearer
  // tokens. SET NULL, never CASCADE: deleting a token or user must not delete
  // the secrets it wrote (cascade used to revert values to older versions).
  // Both null = author was deleted.
  userId: sqliteCore.text('user_id').references(() => user.id, { onDelete: 'set null' }),
  apiTokenId: sqliteCore.text('api_token_id').references(() => apiToken.id, { onDelete: 'set null' }),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  // Hash chain per environment (app/src/audit.ts): seq numbers the rows 1, 2,
  // 3..., hash covers the row and the previous hash, signature is the
  // Worker's Ed25519 signature of it. actor is the author as written
  // ('user:<id>' or 'token:<id>'), which stays when user_id goes null.
  // Rows from before the chain have no seq until their environment's next write.
  actor: sqliteCore.text('actor'),
  seq: sqliteCore.integer('seq'),
  hash: sqliteCore.text('hash'),
  signature: sqliteCore.text('signature'),
  // Joined the chain from before it existed: the Worker signed a row it found
  // in the database, not a change it made. Its preimage says so.
  adopted: sqliteCore.integer('adopted', { mode: 'boolean' }).notNull().default(false),
}, (table) => [
  sqliteCore.index('secret_event_env_name_idx').on(table.environmentId, table.name, table.createdAt),
  sqliteCore.uniqueIndex('secret_event_env_seq_unique').on(table.environmentId, table.seq),
])

// Every read of a protected environment's values, written before the values
// leave the server. A hash chain per environment like secret_event's. Also
// records protection being turned on and off, so a gap in the log shows.
// value: one or more values revealed or fetched; event-log: an old value
// revealed there; copy: copied into another environment on the server
export const SECRET_READ_KINDS = ['list', 'value', 'download', 'event-log', 'copy', 'protected', 'unprotected'] as const

export const secretRead = sqliteCore.sqliteTable('secret_read', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  environmentId: sqliteCore.text('environment_id').notNull().references(() => environment.id, { onDelete: 'cascade' }),
  // 'user:<id>' or 'token:<id>', no foreign key, so it never changes
  actor: sqliteCore.text('actor').notNull(),
  kind: sqliteCore.text('kind', { enum: SECRET_READ_KINDS }).notNull(),
  // Names of the secrets whose values were returned
  names: sqliteCore.text('names', { mode: 'json' }).$type<string[]>().notNull(),
  ipAddress: sqliteCore.text('ip_address'),
  createdAt: epochMs('created_at').notNull(),
  seq: sqliteCore.integer('seq').notNull(),
  hash: sqliteCore.text('hash').notNull(),
  signature: sqliteCore.text('signature').notNull(),
}, (table) => [
  sqliteCore.uniqueIndex('secret_read_env_seq_unique').on(table.environmentId, table.seq),
])

// ── API tokens ──────────────────────────────────────────────────────
// Programmatic access tokens scoped to a project. Optional env allowlist
// lives in apiTokenEnvironment (same 0-rows = all pattern as memberAccess).
// The full key is shown once at creation and never stored — only a SHA-256
// hash is persisted. A short prefix (e.g. "sig_abc1...") is kept for display.

export const apiToken = sqliteCore.sqliteTable('api_token', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull(),
  projectId: sqliteCore.text('project_id').notNull().references(() => project.id, { onDelete: 'cascade' }),
  // First 12 chars after the "sig_" prefix, for display (e.g. "sig_a1b2c3d4e5f6...")
  prefix: sqliteCore.text('prefix').notNull(),
  // SHA-256 hex digest of the full key — used for verification lookups
  hashedKey: sqliteCore.text('hashed_key').notNull().unique(),
  createdBy: sqliteCore.text('created_by').notNull().references(() => user.id, { onDelete: 'cascade' }),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  // Null only for tokens made before expiry existed: those never expire
  expiresAt: epochMs('expires_at'),
  // Written at most once an hour, so a busy CI token isn't a D1 write per request
  lastUsedAt: epochMs('last_used_at'),
  lastUsedIp: sqliteCore.text('last_used_ip'),
  // A machine token may read protected environments without a passkey, since
  // a pod or a CI job can't approve anything. Made by an org admin with a
  // passkey approval, and it must expire.
  protectedAccess: sqliteCore.integer('protected_access', { mode: 'boolean' }).notNull().default(false),
}, (table) => [
  sqliteCore.index('api_token_project_id_idx').on(table.projectId),
  sqliteCore.index('api_token_hashed_key_idx').on(table.hashedKey),
])

// Env allowlist for a token. Zero rows = all envs in the project.
// One or more rows = only those envs. Migration 0007 adds a trigger that
// revokes the token when its last row is deleted, so cascade cannot widen
// a scoped token to all. D1 keeps foreign_keys ON (PRAGMA foreign_keys=OFF
// is ignored), so any DROP TABLE of a parent fires child ON DELETE actions.
export const apiTokenEnvironment = sqliteCore.sqliteTable('api_token_environment', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  tokenId: sqliteCore.text('token_id').notNull().references(() => apiToken.id, { onDelete: 'cascade' }),
  environmentId: sqliteCore.text('environment_id').notNull().references(() => environment.id, { onDelete: 'cascade' }),
}, (table) => [
  sqliteCore.uniqueIndex('api_token_environment_token_env_unique').on(table.tokenId, table.environmentId),
  sqliteCore.index('api_token_environment_token_id_idx').on(table.tokenId),
  sqliteCore.index('api_token_environment_environment_id_idx').on(table.environmentId),
])

// ── Member access (project-level permissions) ──────────────────────
// Projects a member with orgMember.projectAccess = 'selected' can access.
// Ignored for projectAccess = 'all' and for admins.

export const memberAccess = sqliteCore.sqliteTable('member_access', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  orgMemberId: sqliteCore.text('org_member_id').notNull()
    .references(() => orgMember.id, { onDelete: 'cascade' }),
  projectId: sqliteCore.text('project_id').notNull()
    .references(() => project.id, { onDelete: 'cascade' }),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.uniqueIndex('member_access_member_project_unique')
    .on(table.orgMemberId, table.projectId),
  sqliteCore.index('member_access_org_member_id_idx').on(table.orgMemberId),
  sqliteCore.index('member_access_project_id_idx').on(table.projectId),
])

// Default environments created for every new project
export const DEFAULT_ENVIRONMENTS = [
  { name: 'Dev', slug: 'dev' },
  { name: 'Preview', slug: 'preview' },
  { name: 'Prod', slug: 'prod' },
] as const

// ── oauthDomain table ────────────────────────────────────────────────
// Stores the provider client registration for each app hostname.
export const oauthDomain = sqliteCore.sqliteTable('oauth_domain', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  host: sqliteCore.text('host').notNull().unique(),
  oauthClientId: sqliteCore.text('oauth_client_id').notNull(),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

// ── deviceCode table (device authorization plugin, RFC 8628) ────────
// Stores pending device codes for CLI/agent login flows.
// Agents call /api/auth/device/code to get a code, user enters it at /device.

export const deviceCode = sqliteCore.sqliteTable('device_code', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  deviceCode: sqliteCore.text('device_code').notNull().unique(),
  userCode: sqliteCore.text('user_code').notNull().unique(),
  userId: sqliteCore.text('user_id').references(() => user.id, { onDelete: 'cascade' }),
  expiresAt: epochMs('expires_at').notNull(),
  status: sqliteCore.text('status', { enum: ['pending', 'approved', 'denied', 'expired'] }).notNull().default('pending'),
  lastPolledAt: epochMs('last_polled_at'),
  pollingInterval: sqliteCore.integer('polling_interval', { mode: 'number' }),
  clientId: sqliteCore.text('client_id'),
  scope: sqliteCore.text('scope'),
}, (table) => [
  sqliteCore.index('device_code_user_id_idx').on(table.userId),
])

// ── Relations (v2 API) ──────────────────────────────────────────────

export const relations = defineRelations(
  { user, session, account, verification, passkey, passkeyEvent, stepUpRequest, stepUpGrant, org, orgMember, orgInvitation, project, environment, secretEvent, secretRead, apiToken, apiTokenEnvironment, deviceCode, oauthDomain, memberAccess },
  (r) => ({
    user: {
      sessions: r.many.session(),
      accounts: r.many.account(),
      passkeys: r.many.passkey(),
      orgs: r.many.org({
        from: r.user.id.through(r.orgMember.userId),
        to: r.org.id.through(r.orgMember.orgId),
      }),
    },
    session: {
      user: r.one.user({ from: r.session.userId, to: r.user.id }),
    },
    account: {
      user: r.one.user({ from: r.account.userId, to: r.user.id }),
    },
    verification: {},
    passkey: {
      user: r.one.user({ from: r.passkey.userId, to: r.user.id }),
    },
    org: {
      members: r.many.orgMember(),
      invitations: r.many.orgInvitation(),
      projects: r.many.project(),
      users: r.many.user({
        from: r.org.id.through(r.orgMember.orgId),
        to: r.user.id.through(r.orgMember.userId),
      }),
    },
    orgMember: {
      org: r.one.org({ from: r.orgMember.orgId, to: r.org.id }),
      user: r.one.user({ from: r.orgMember.userId, to: r.user.id }),
      accessRules: r.many.memberAccess(),
    },
    orgInvitation: {
      org: r.one.org({ from: r.orgInvitation.orgId, to: r.org.id }),
      creator: r.one.user({ from: r.orgInvitation.createdBy, to: r.user.id }),
    },
    project: {
      org: r.one.org({ from: r.project.orgId, to: r.org.id }),
      environments: r.many.environment(),
      apiTokens: r.many.apiToken(),
    },
    environment: {
      project: r.one.project({ from: r.environment.projectId, to: r.project.id }),
      secretEvents: r.many.secretEvent(),
      secretReads: r.many.secretRead(),
      apiTokenEnvironments: r.many.apiTokenEnvironment(),
    },
    secretRead: {
      environment: r.one.environment({ from: r.secretRead.environmentId, to: r.environment.id }),
    },
    secretEvent: {
      environment: r.one.environment({ from: r.secretEvent.environmentId, to: r.environment.id }),
      user: r.one.user({ from: r.secretEvent.userId, to: r.user.id }),
      apiToken: r.one.apiToken({ from: r.secretEvent.apiTokenId, to: r.apiToken.id }),
    },
    apiToken: {
      project: r.one.project({ from: r.apiToken.projectId, to: r.project.id }),
      creator: r.one.user({ from: r.apiToken.createdBy, to: r.user.id }),
      environments: r.many.apiTokenEnvironment(),
    },
    apiTokenEnvironment: {
      token: r.one.apiToken({ from: r.apiTokenEnvironment.tokenId, to: r.apiToken.id }),
      environment: r.one.environment({ from: r.apiTokenEnvironment.environmentId, to: r.environment.id }),
    },
    deviceCode: {
      user: r.one.user({ from: r.deviceCode.userId, to: r.user.id }),
    },
    memberAccess: {
      orgMember: r.one.orgMember({ from: r.memberAccess.orgMemberId, to: r.orgMember.id }),
      project: r.one.project({ from: r.memberAccess.projectId, to: r.project.id }),
    },
    oauthDomain: {},
  }),
)
