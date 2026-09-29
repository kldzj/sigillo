// The security log: a row for each change to what can reach secrets. Tokens
// made, regenerated or deleted, trust rules made, renewed or deleted,
// protection turned on or off, environments deleted, old values purged,
// members removed or given another role, passkeys reset.
//
// Each row is a statement in the same D1 batch as its change, so it exists
// exactly when the change happened. Its names are copied in and it has no
// foreign keys, so it outlives the org, the project and the people. It never
// holds a value, a token or a JWT. Nothing shows it yet; notifications will
// send it.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { actorOf } from './db.ts'

export type SecurityEventKind = (typeof schema.SECURITY_EVENT_KINDS)[number]

// Who made the change, and the request it came with, for the IP
export type ChangedBy = { userId: string; request?: Request | null }

export function securityEvent({ request = null, author, kind, where, subject, details = {} }: {
  request?: Request | null
  author: { userId: string | null; apiTokenId: string | null }
  kind: SecurityEventKind
  // A project's event, or the organization's own
  where: { projectId: string } | { orgId: string }
  // The token, rule, environment or member, by its name at the time
  subject: { id: string; name: string | orm.SQL }
  details?: Record<string, unknown>
}) {
  const projectId = 'projectId' in where ? where.projectId : null
  // Read in the statement itself: a project that is gone fails the batch
  const ofProject = (column: typeof schema.project.orgId | typeof schema.project.name) =>
    orm.sql`(select ${column} from ${schema.project} where ${schema.project.id} = ${projectId})`
  return getDb().insert(schema.securityEvent).values({
    orgId: 'orgId' in where ? where.orgId : ofProject(schema.project.orgId),
    projectId,
    projectName: projectId ? ofProject(schema.project.name) : null,
    kind,
    subjectId: subject.id,
    subjectName: subject.name,
    actor: actorOf(author),
    actorName: author.userId ? userName(author.userId)
      : author.apiTokenId ? orm.sql`(select ${schema.apiToken.name} from ${schema.apiToken} where ${schema.apiToken.id} = ${author.apiTokenId})`
      : null,
    ipAddress: request?.headers.get('cf-connecting-ip') ?? null,
    details,
  })
}

// A person's name, read in the statement
export function userName(userId: string) {
  return orm.sql`(select ${schema.user.name} from ${schema.user} where ${schema.user.id} = ${userId})`
}
