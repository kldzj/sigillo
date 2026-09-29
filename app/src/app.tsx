// Spiceflow entry for the self-hosted secret sharing app.
// Pages for secrets management UI. REST API routes live in api.ts.
// Also serves as the Cloudflare Worker entry via the default export.
//
// Two nested layouts:
// 1. /* — HTML shell (head, body, fonts, ProgressBar)
// 2. /dash/* — Authenticated app shell with sidebar
//
// Standalone pages (no sidebar): /login, /device, /approve, /invite/:id.
// The docs and landing page are a separate static site (src/docs-site.tsx),
// so an instance only serves the app: / goes to the dashboard.

import './globals.css'
import { Spiceflow } from 'spiceflow'
import { Head, Link, ProgressBar, router } from 'spiceflow/react'
import { env } from 'cloudflare:workers'
import { initStrada, trace } from '@strada.sh/sdk'
import {
  getDb, getAuth, getSession, getRequestOrigin, ensureOAuthClient,
  requirePageSession,
  requirePageOrgMember,
  getOrgIdForProject,
  deriveEnvironmentSecretsAndNames,
  autoJoinOrgsByDomain,
  getAccessibleProjectIds,
  getEnvironmentAccessError,
  getProjectMemberAccess,
  listUserSessions,
  isSessionFresh,
  actorOf,
  countSecrets,
  listFormerMembers,
  firstAccessibleProject,
  requirePageProjectAccess,
  internalErrorMessage,
} from './db.ts'
import { apiApp } from './api.ts'
import { countOldValues } from './audit.ts'
import { isFreshSignIn, enrollmentState, pendingEnrollments, requirePasskeyOnceEnrolled, StepUpRequiredError } from './step-up.ts'
import { rememberCacheOrigin } from './lib/memoize.ts'
import { cn, loginErrorMessage, DOCS_URL, ENV_SLUG_REGEX } from 'sigillo-app/src/lib/utils'
import { CreateOrgForm } from 'sigillo-app/src/components/create-org-form'
import { SigilloLogo } from 'sigillo-app/src/components/logo'
// Tailwind and the base styles, which the docs site loads with its pages
import '@holocron.so/vite/src/styles/globals.css'


const cliBannerCookieName = 'sigillo-cli-banner-dismissed'

function isTruthy<T>(value: T | null | undefined): value is T {
  return value != null
}

// Names for the authors the history chains record, 'user:<id>' or
// 'token:<id>': the rows' user_id and api_token_id aren't covered by them
async function actorNames(actors: (string | null)[]): Promise<Map<string, string>> {
  const db = getDb()
  const ids = (prefix: string) => [...new Set(actors.filter((a): a is string => !!a?.startsWith(prefix)).map((a) => a.slice(prefix.length)))]
  const [users, tokens] = await Promise.all([
    db.query.user.findMany({ where: { id: { in: ids('user:') } }, columns: { id: true, name: true } }),
    db.query.apiToken.findMany({ where: { id: { in: ids('token:') } }, columns: { id: true, name: true, workload: true } }),
  ])
  return new Map<string, string>([
    ...users.map((u) => [`user:${u.id}`, u.name] as const),
    ...tokens.map((t) => [`token:${t.id}`, `${t.name} (${t.workload ? 'workload' : 'token'})`] as const),
  ])
}

function actorName(names: Map<string, string>, actor: string | null): string {
  return (actor && names.get(actor)) ?? (actor?.startsWith('token:') ? 'Deleted token' : 'Deleted user')
}

// Only allow local app paths for redirects — prevents open redirects and
// avoids sending logged-in users to API routes or obvious 404s.
function safeRedirectPath(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/dash'
  if (['/device', '/approve'].includes(value)) return value
  if (value === '/dash' || value.startsWith('/dash/') || value.startsWith('/invite/')) return value
  return '/dash'
}

function hasCookie(args: { cookieHeader: string; name: string }) {
  return args.cookieHeader
    .split(';')
    .some((part) => part.trim().startsWith(`${args.name}=`))
}

// ── Remembered environment ─────────────────────────────────────────
// Each project remembers the environment last opened (its secrets or its
// history) in a cookie, so its tabs and links return there instead of
// jumping to the first environment.
const envPagePath = /^\/dash\/projects\/([^/]+)\/envs\/([^/]+)(?:\/history(?:\/reads)?)?$/

function envCookieName(projectId: string) {
  return `sigillo-env-${projectId}`
}

function getCookie(cookieHeader: string, name: string): string | null {
  for (const part of cookieHeader.split(';')) {
    const [key, ...value] = part.trim().split('=')
    if (key === name) return decodeURIComponent(value.join('='))
  }
  return null
}

// The project's remembered environment while it still exists, else its first
function projectEnvSlug(request: Request, projectId: string, environments: { slug: string; createdAt: number }[]): string | null {
  const sorted = [...environments].sort((a, b) => a.createdAt - b.createdAt)
  const remembered = getCookie(request.headers.get('cookie') ?? '', envCookieName(projectId))
  return sorted.find((env) => env.slug === remembered)?.slug ?? sorted[0]?.slug ?? null
}

// Strada observability (strada.sh). trace.getTracer returns a proxy that
// delegates to the provider registered by initStrada() in the fetch handler,
// so module-level creation is safe. Self-hosted instances have no
// STRADA_PROJECT_ID binding → tracer stays a noop and zero requests are made.
const tracer = trace.getTracer('sigillo-app')

export const app = new Spiceflow({ tracer })

  // What the server didn't mean to say stays in its logs. Without this, a
  // page or server action that fails in a query sends the query's SQL and
  // parameters to the browser, and pages a stack trace too. The REST API
  // answers its errors itself (api.ts).
  .onError(({ error, path }) => {
    if (path.startsWith('/api/v0/')) return
    const message = internalErrorMessage(error)
    if (message === null) return
    console.error(error)
    // A server action sends the error's message to the browser
    if (error instanceof Error) error.message = message
    return Response.json({ error: message }, { status: 500 })
  })

  // ── BetterAuth middleware ──────────────────────────────────────
  // BetterAuth runs in the worker, not the DO. Only SQL crosses the
  // DO boundary via sqlite-proxy.
  .use(async ({ request }, next) => {
    const url = new URL(request.url)
    // The REST API takes the session cookie too, and parses any body as JSON:
    // a write that a page on another origin sends with the cookie is
    // refused. The CLI and scripts send a bearer token and no Origin.
    const origin = request.headers.get('origin')
    if (url.pathname.startsWith('/api/v0/') && !['GET', 'HEAD', 'OPTIONS'].includes(request.method)
      && !request.headers.has('authorization') && origin && origin !== url.origin) {
      return Response.json({ error: 'cross-origin request refused' }, { status: 403 })
    }
    // Approving a CLI login makes a login that outlives this session: once
    // you have a passkey, it takes an approval with it (step-up.ts)
    if (url.pathname === '/api/auth/device/approve' && request.method === 'POST') {
      const session = await getSession(request)
      if (session) {
        try {
          await requirePasskeyOnceEnrolled(session)
        } catch (error) {
          if (!(error instanceof StepUpRequiredError)) throw error
          return Response.json({ code: 'PASSKEY_APPROVAL_REQUIRED', message: 'Approve with your passkey first' }, { status: 403 })
        }
      }
    }
    if (url.pathname.startsWith('/api/auth')) {
      const auth = await getAuth(request)
      const res = await auth.handler(request)
      if (res.ok || res.status !== 404) return res
    }
    return next()
  })

  // Remember the environment of every environment page that loads
  .use(async ({ request }, next) => {
    const response = await next()
    const url = new URL(request.url)
    const match = request.method === 'GET' ? envPagePath.exec(url.pathname) : null
    if (!match || !(response instanceof Response) || response.status !== 200) return response
    const [, projectId, envSlug] = match
    if (!ENV_SLUG_REGEX.test(envSlug!)) return response
    const headers = new Headers(response.headers)
    headers.append('Set-Cookie', [
      `${envCookieName(decodeURIComponent(projectId!))}=${envSlug}`,
      'Path=/dash', 'Max-Age=31536000', 'SameSite=Lax', 'HttpOnly',
      ...(url.protocol === 'https:' ? ['Secure'] : []),
    ].join('; '))
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
  })

  // ── Layout: Dashboard routes (HTML shell + sidebar chrome) ──────
  // Each route group registers AppShell separately.
  .layout('/dash/*', async ({ children, request }) => {
    const { MobileMenuButton } = await import('sigillo-app/src/components/sidebar')
    return (
      <AppShell request={request} mobileMenuSlot={<MobileMenuButton />}>
        {children}
      </AppShell>
    )
  })

  // ── Layout: Standalone pages (login, device, invite, new-org) ──
  .layout('/login', async ({ children, request }) => <AppShell request={request}>{children}</AppShell>)
  .layout('/device', async ({ children, request }) => <AppShell request={request}>{children}</AppShell>)
  .layout('/approve', async ({ children, request }) => <AppShell request={request}>{children}</AppShell>)
  .layout('/invite/*', async ({ children, request }) => <AppShell request={request}>{children}</AppShell>)

  .loader('/dash/*', async ({ request }) => {
    const db = getDb()
    const pathname = new URL(request.url).pathname
    const projectId = new URLPattern({ pathname: '/dash/projects/:projectId/*' })
      .exec(request.url)?.pathname.groups.projectId ?? null
    const session = await requirePageSession(request)
    // Auto-join orgs by email domain before querying memberships.
    // Uses waitUntil so the page doesn't block on the insert if it's slow,
    // but we await it here because the membership list below needs to include
    // any newly joined orgs for correct sidebar rendering.
    await autoJoinOrgsByDomain(session)
    const members = await db.query.orgMember.findMany({
      where: { userId: session.userId },
      with: { org: true },
    })

    const orgs = members.filter((m) => m.org != null).map((m) => ({
      id: m.org!.id!, name: m.org!.name!, role: m.role,
      createdAt: m.org!.createdAt!, updatedAt: m.org!.updatedAt!,
    }))

    return {
      orgs,
      projectId,
      pathname,
      currentProjectEnvSlug: null,
      user: { name: session.user.name || 'User', email: session.user.email || '' },
    }
  })

  .loader('/dash/orgs/:orgId', async ({ params, request }) => {
    const session = await requirePageSession(request)
    await requirePageOrgMember(session.userId, params.orgId)
    return orgSidebar({ request, userId: session.userId, orgId: params.orgId })
  })

  // ── Organization settings ───────────────────────────────────────
  .loader('/dash/orgs/:orgId/settings', async ({ params, request }) => {
    const db = getDb()
    const session = await requirePageSession(request)
    const { role } = await requirePageOrgMember(session.userId, params.orgId)
    // What deleting the organization takes with it, only for the admins who
    // can: a member may not know every project's name
    const [sidebar, orgRow, projects] = await Promise.all([
      orgSidebar({ request, userId: session.userId, orgId: params.orgId }),
      db.query.org.findFirst({ where: { id: params.orgId }, columns: { name: true, autoJoinDomain: true } }),
      role === 'admin' ? db.query.project.findMany({ where: { orgId: params.orgId }, columns: { id: true, name: true }, orderBy: { createdAt: 'asc' } }) : [],
    ])
    const environments = projects.length > 0
      ? await db.query.environment.findMany({ where: { projectId: { in: projects.map((p) => p.id) } }, columns: { id: true } })
      : []
    const secretCounts = await countSecrets(environments.map((env) => env.id))
    return {
      ...sidebar,
      role,
      orgName: orgRow?.name ?? 'Organization',
      autoJoinDomain: orgRow?.autoJoinDomain ?? null,
      projectNames: projects.map((p) => p.name),
      environmentCount: environments.length,
      secretCount: Object.values(secretCounts).reduce((sum, count) => sum + count, 0),
    }
  })

  .page('/dash/orgs/:orgId/settings', async () => {
    const { OrgSettingsPage } = await import('sigillo-app/src/components/settings-page')
    return (
      <div className="flex flex-col gap-3 w-full">
        <OrgSettingsPage />
      </div>
    )
  })

  // ── Members ─────────────────────────────────────────────────────
  .loader('/dash/orgs/:orgId/members', async ({ params, request }) => {
    const db = getDb()
    const { orgId } = params
    const session = await requirePageSession(request)
    const { role } = await requirePageOrgMember(session.userId, orgId)

    // Which projects there are and who opens which, only for admins: a
    // member may not know every project's name
    const [sidebar, orgRow, allMembers, orgProjects] = await Promise.all([
      orgSidebar({ request, userId: session.userId, orgId }),
      db.query.org.findFirst({ where: { id: orgId }, columns: { name: true } }),
      db.query.orgMember.findMany({
        where: { orgId },
        with: {
          user: { columns: { id: true, name: true, email: true, image: true } },
          accessRules: { columns: { projectId: true } },
        },
        orderBy: { createdAt: 'asc' },
      }),
      role === 'admin' ? db.query.project.findMany({
        where: { orgId },
        columns: { id: true, name: true },
        orderBy: { createdAt: 'asc' },
      }) : [],
    ])
    const members = role === 'admin' ? allMembers : allMembers.map((member) => ({ ...member, accessRules: [] }))

    // Admins see who has passkeys, and every passkey added or removed. People
    // who left still need this organization's approval for a first passkey,
    // so their requests show here too.
    const userIds = members.map((member) => member.userId)
    const formerMembers = role === 'admin' ? await listFormerMembers(orgId) : []
    const [passkeys, events, enrollments] = role === 'admin'
      ? await Promise.all([
        db.query.passkey.findMany({ where: { userId: { in: userIds } }, columns: { userId: true } }),
        db.query.passkeyEvent.findMany({ where: { userId: { in: userIds } }, orderBy: { createdAt: 'desc' }, limit: 50 }),
        pendingEnrollments({ userIds: [...userIds, ...formerMembers.map((user) => user.id)], orgId }),
      ])
      : [[], [], []]
    const nameOf = (userId: string) => {
      const member = members.find((member) => member.userId === userId)?.user
      if (member) return member.name
      const former = formerMembers.find((user) => user.id === userId)
      return former ? `${former.name} (left)` : 'Former member'
    }
    const passkeyCounts = Object.fromEntries(userIds.map((userId) => [userId, passkeys.filter((p) => p.userId === userId).length]))
    const passkeyEvents = events.map((event) => ({
      id: event.id,
      member: nameOf(event.userId),
      action: event.action,
      passkeyName: event.passkeyName,
      by: event.actor === 'self-host' ? 'self-host' : event.actor === `user:${event.userId}` ? 'themselves' : nameOf(event.actor.replace(/^user:/, '')),
      ipAddress: event.ipAddress,
      createdAt: event.createdAt,
    }))

    // Members asking an admin to approve their first passkey
    const passkeyRequests = enrollments.map((row) => ({
      id: row.id,
      member: nameOf(row.userId),
      isYou: row.userId === session.userId,
      userAgent: row.userAgent,
      ipAddress: row.ipAddress,
      country: row.country,
      createdAt: row.createdAt,
      approvedHere: row.approvedHere,
      waitingForOthers: row.waitingForOthers,
    }))

    return {
      ...sidebar,
      orgId,
      orgName: orgRow?.name ?? 'Organization',
      role,
      currentUserId: session.userId,
      members,
      orgProjects,
      passkeyCounts,
      passkeyEvents,
      passkeyRequests,
    }
  })

  .page('/dash/orgs/:orgId/members', async () => {
    const { MembersPage } = await import('sigillo-app/src/components/access-table')

    return <MembersPage />
  })

  .loader('/dash/projects/:projectId/*', async ({ params, request }) => {
    const db = getDb()
    const url = new URL(request.url)
    const { projectId } = params
    const session = await requirePageSession(request)
    const orgId = await getOrgIdForProject(projectId)
    if (!orgId) throw Response.redirect(new URL('/', request.url).toString(), 302)

    // One access lookup covers org membership ([] for non-members), the
    // current-project check, AND the sidebar project filter — previously
    // three sequential round-trips. Run it in parallel with the project list.
    const [accessibleIds, allProjects] = await Promise.all([
      getAccessibleProjectIds(session.userId, orgId),
      db.query.project.findMany({
        where: { orgId },
        with: { environments: true },
        orderBy: { createdAt: 'desc' },
      }),
    ])
    if (accessibleIds !== null && !accessibleIds.includes(projectId)) {
      throw Response.redirect(new URL('/', request.url).toString(), 302)
    }

    const projects = allProjects
      .filter((p) => accessibleIds === null || accessibleIds.includes(p.id))
      .map((p) => ({ id: p.id, name: p.name, envSlug: projectEnvSlug(request, p.id, p.environments || []) }))
    const currentProject = allProjects.find((project) => project.id === projectId)
    const environments = [...(currentProject?.environments || [])].sort((a, b) => a.createdAt - b.createdAt)

    return {
      orgId,
      projectId,
      projectName: currentProject?.name ?? 'Project',
      pathname: url.pathname,
      projects,
      environments,
      currentProjectEnvSlug: projects.find((project) => project.id === projectId)?.envSlug ?? null,
    }
  })

  // ── Layout 2: Authenticated app shell with sidebar ─────────────
  .layout('/dash/*', async ({ children, loaderData }) => {
    const { Sidebar, MobileDrawer } = await import('sigillo-app/src/components/sidebar')
    const projectId = loaderData.projectId
    return (
      <>
        {projectId && (
          <>
            <TabBar
              projectId={projectId}
              pathname={loaderData.pathname}
              envSlug={loaderData.currentProjectEnvSlug}
            />
            <div className="border-t border-border" />
          </>
        )}
        <div className="isolate min-h-0 grow relative flex max-w-(--content-max-width) mx-auto w-full border-x border-border">
          <GridDot position="tl" />
          <GridDot position="tr" />
          <Sidebar />
          <MobileDrawer />
          <main className="flex-1 p-4 sm:p-6 overflow-x-hidden overflow-y-auto min-w-0">
            {children}
          </main>
        </div>
      </>
    )
  })

  // ── /dash redirect → resolve user's default project+env in one hop ──
  // / and the navbar logo link to /dash. This resolves the full path
  // (org → project → env) in a single worker invocation instead of
  // chaining through /dash/orgs/:orgId → /dash/projects/:id → /envs/:slug.
  .get('/dash', async ({ request }) => {
    const session = await getSession(request)
    if (!session) return Response.redirect(new URL('/login?redirect=/dash', request.url).toString(), 302)
    const db = getDb()
    const members = await db.query.orgMember.findMany({
      where: { userId: session.userId },
      with: { org: true },
    })
    const orgs = members
      .filter((m) => m.org != null)
      .sort((a, b) => b.org!.createdAt! - a.org!.createdAt!)
    if (orgs.length === 0) {
      return Response.redirect(new URL('/dash/new-org', request.url).toString(), 302)
    }
    // The newest project they can open, in the newest organization that has
    // one: a member with access to only some projects may have none in theirs
    for (const member of orgs) {
      const firstProject = await firstAccessibleProject(session.userId, member.orgId)
      if (!firstProject) continue
      const envSlug = projectEnvSlug(request, firstProject.id, firstProject.environments || []) ?? '_'
      const href = `/dash/projects/${encodeURIComponent(firstProject.id)}/envs/${encodeURIComponent(envSlug)}`
      return Response.redirect(new URL(href, request.url).toString(), 302)
    }
    return Response.redirect(new URL(`/dash/orgs/${encodeURIComponent(orgs[0]!.org!.id)}`, request.url).toString(), 302)
  })

  // ── Org root redirect → resolve first project+env in one hop ──
  .get('/dash/orgs/:orgId', async ({ params, request }) => {
    const session = await requirePageSession(request)
    await requirePageOrgMember(session.userId, params.orgId)
    const firstProject = await firstAccessibleProject(session.userId, params.orgId)
    if (firstProject) {
      const envSlug = projectEnvSlug(request, firstProject.id, firstProject.environments || []) ?? '_'
      const href = `/dash/projects/${encodeURIComponent(firstProject.id)}/envs/${encodeURIComponent(envSlug)}`
      return Response.redirect(new URL(href, request.url).toString(), 302)
    }
    return null
  })

  // ── Org page (redirects to first project, or shows empty state) ─
  .page('/dash/orgs/:orgId', async ({ params, request }) => {
    const session = await requirePageSession(request)
    await requirePageOrgMember(session.userId, params.orgId)

    const firstProject = await firstAccessibleProject(session.userId, params.orgId)
    if (firstProject) {
      return Response.redirect(new URL(`/dash/projects/${encodeURIComponent(firstProject.id)}`, request.url).toString(), 302)
    }
    const anyProject = await getDb().query.project.findFirst({ where: { orgId: params.orgId }, columns: { id: true } })
    if (anyProject) {
      return (
        <div className="max-w-3xl">
          <h1 className="text-2xl font-bold tracking-tight mb-2">No projects for you yet</h1>
          <p className="text-muted-foreground">Ask an admin of this organization for access to a project.</p>
        </div>
      )
    }

    const { NewProjectButton } = await import('sigillo-app/src/components/sidebar')

    return (
      <div className="max-w-3xl">
        <h1 className="text-2xl font-bold tracking-tight mb-2">No projects yet</h1>
        <p className="text-muted-foreground mb-6">Create your first project to start managing secrets.</p>
        <NewProjectButton orgId={params.orgId} />
      </div>
    )
  })

  // ── New Organization page (standalone, no sidebar) ─────────────
  .page('/dash/new-org', async () => {
    return (
      <div className="max-w-md mx-auto py-12">
        <h1 className="text-2xl font-bold tracking-tight mb-2">New Organization</h1>
        <p className="text-muted-foreground mb-6">
          Organizations group your projects and team members.
        </p>
        <CreateOrgForm />
      </div>
    )
  })

  // ── Project root redirect → first env ─────────────────────────
  .page('/dash/projects/:projectId', async ({ params, request, redirect }) => {
    const db = getDb()
    const session = await requirePageSession(request)
    const orgId = await getOrgIdForProject(params.projectId)
    if (!orgId) throw Response.redirect(new URL('/', request.url).toString(), 302)
    await requirePageOrgMember(session.userId, orgId)
    const environments = await db.query.environment.findMany({
      where: { projectId: params.projectId },
      orderBy: { createdAt: 'asc' },
    })
    const envSlug = projectEnvSlug(request, params.projectId, environments) || '_'
    throw redirect(`/dash/projects/${encodeURIComponent(params.projectId)}/envs/${encodeURIComponent(envSlug)}`)
  })

  .loader('/dash/projects/:projectId/envs/:envSlug', async ({ request, params, redirect }) => {
    const db = getDb()
    const { projectId, envSlug } = params
    const session = await requirePageSession(request)

    const environments = await db.query.environment.findMany({
      where: { projectId },
      orderBy: { createdAt: 'asc' },
    })

    const matchedEnv = environments.find((e) => e.slug === envSlug)
    const selectedEnvId = matchedEnv?.id ?? environments[0]?.id ?? null

    if (selectedEnvId && !matchedEnv && environments[0]) {
      throw redirect(`/dash/projects/${encodeURIComponent(projectId)}/envs/${encodeURIComponent(environments[0].slug)}`)
    }

    // Never decrypt envs the user can't access (admin-only for members).
    // Loaders run in parallel, so don't rely on the parent loader's checks.
    const access = await getProjectMemberAccess(session.userId, projectId)
    const readableEnvIds = environments.filter((e) => !getEnvironmentAccessError(access, e)).map((e) => e.id)
    const locked = !!selectedEnvId && !readableEnvIds.includes(selectedEnvId)

    // Names only: values are fetched when revealed (see readSecretValues)
    let secrets: { id: string; name: string; createdAt: number; updatedAt: number; createdBy: { id: string; name: string } | null }[] = []
    // One D1 batch derives the selected env's secrets AND the union of names
    // across all readable envs, instead of a separate names round-trip.
    const { secrets: derived, allNames: allSecretNames } = await deriveEnvironmentSecretsAndNames({
      environmentIds: readableEnvIds,
      selectedEnvId: locked ? null : selectedEnvId,
    })
    if (selectedEnvId && !locked) {
      const names = await actorNames(derived.map((d) => d.actor))
      secrets = derived.map((d) => ({
        id: d.id, name: d.name,
        createdAt: d.createdAt, updatedAt: d.updatedAt,
        createdBy: { id: d.actor, name: actorName(names, d.actor) },
      }))
    }

    const cookieHeader = request.headers.get('cookie') ?? ''

    return {
      selectedEnvId,
      locked,
      secrets,
      allSecretNames,
      showBanner: !hasCookie({ cookieHeader, name: cliBannerCookieName }),
      apiUrl: getRequestOrigin(request),
    }
  })

  // ── Project detail with env ───────────────────────────────────
  .page('/dash/projects/:projectId/envs/:envSlug', async ({ loaderData }) => {
    const { ProjectPage } = await import('sigillo-app/src/components/project-page')
    return <ProjectPage key={loaderData.selectedEnvId ?? 'none'} />
  })

  .loader('/dash/projects/:projectId/environments', async ({ params, request }) => {
    // How many secrets each environment has, so deleting one with secrets
    // asks for its slug
    const session = await requirePageSession(request)
    const access = await requirePageProjectAccess(session.userId, params.projectId)
    const environments = await getDb().query.environment.findMany({ where: { projectId: params.projectId }, columns: { id: true, projectId: true, accessRole: true } })
    const visible = environments.filter((env) => !getEnvironmentAccessError(access, env)).map((env) => env.id)
    return { projectId: params.projectId, secretCounts: await countSecrets(visible) }
  })

  .page('/dash/projects/:projectId/environments', async () => {
    const { EnvironmentsPage } = await import('sigillo-app/src/components/environments-table')

    return <EnvironmentsPage />
  })

  // ── History: changes ───────────────────────────────────────────
  // At /history, not /event-log: EasyPrivacy (on by default in uBlock
  // Origin Lite) blocks `/event-log?`, so navigating to it and its actions failed.
  .get('/dash/projects/:projectId/history', async ({ params, request, redirect }) => {
    // Only someone who can open the project learns its environments' slugs
    const session = await requirePageSession(request)
    const access = await getProjectMemberAccess(session.userId, params.projectId)
    if (!access || (access.accessibleProjectIds !== null && !access.accessibleProjectIds.includes(params.projectId))) throw redirect('/dash')
    const db = getDb()
    const environments = await db.query.environment.findMany({
      where: { projectId: params.projectId },
      orderBy: { createdAt: 'asc' },
    })
    const envSlug = projectEnvSlug(request, params.projectId, environments) || '_'
    throw redirect(`/dash/projects/${encodeURIComponent(params.projectId)}/envs/${encodeURIComponent(envSlug)}/history`)
  })

  .loader('/dash/projects/:projectId/envs/:envSlug/history', async ({ params, request, redirect }) => {
    const db = getDb()
    const { projectId, envSlug } = params
    const session = await requirePageSession(request)

    const environments = await db.query.environment.findMany({ where: { projectId }, orderBy: { createdAt: 'asc' } })

    const matchedEnv = environments.find((e) => e.slug === envSlug)
    const selectedEnvId = matchedEnv?.id ?? environments[0]?.id ?? null

    if (selectedEnvId && !matchedEnv && environments[0]) {
      throw redirect(`/dash/projects/${encodeURIComponent(projectId)}/envs/${encodeURIComponent(environments[0].slug)}/history`)
    }

    const access = await getProjectMemberAccess(session.userId, projectId)
    const locked = !!matchedEnv && !!getEnvironmentAccessError(access, matchedEnv)

    // Load events for selected env, sorted by createdAt DESC
    let events: { id: string; name: string; operation: string; valueEncrypted: string | null; iv: string | null; createdAt: number; environmentName: string; userName: string; unsigned: boolean; purged: boolean }[] = []
    if (selectedEnvId && !locked) {
      const envMap = new Map(environments.map((e) => [e.id, e.name]))
      const rows = await db.query.secretEvent.findMany({
        where: { environmentId: selectedEnvId },
        orderBy: { createdAt: 'desc' },
      })
      const names = await actorNames(rows.map((r) => r.actor ?? actorOf(r)))
      events = rows.map((r) => ({
        id: r.id,
        name: r.name,
        operation: r.operation,
        valueEncrypted: r.valueEncrypted,
        iv: r.iv,
        createdAt: r.createdAt,
        environmentName: envMap.get(r.environmentId) ?? '—',
        userName: actorName(names, r.actor ?? actorOf(r)),
        // Not part of the signed history: added to the database around it
        unsigned: r.seq === null,
        // Removed by an admin; the row keeps its digest (audit.ts)
        purged: r.operation === 'set' && !r.valueEncrypted && !!r.valueDigest,
      }))
    }

    // No values: an old value is fetched when revealed (see readEventValue)
    const eventsWithoutValues = events.map(({ valueEncrypted, iv, ...evt }) => ({ ...evt, hasValue: evt.operation === 'set' && !!valueEncrypted && !!iv }))
    // Admins may purge the old values
    const isAdmin = access?.role === 'admin'
    const oldValues = isAdmin && selectedEnvId && !locked ? await countOldValues(selectedEnvId) : 0

    return {
      events: eventsWithoutValues,
      selectedEnvId,
      locked,
      projectId,
      isAdmin,
      oldValues,
    }
  })

  .page('/dash/projects/:projectId/envs/:envSlug/history', async () => {
    const { ChangesTable } = await import('sigillo-app/src/components/changes-table')

    return (
      <div className="flex flex-col gap-3 w-full">
        <ChangesTable />
      </div>
    )
  })

  // ── History: reads ─────────────────────────────────────────────
  // Reads of a protected environment's values, for org admins
  .loader('/dash/projects/:projectId/envs/:envSlug/history/reads', async ({ params, request, redirect }) => {
    const db = getDb()
    const { projectId, envSlug } = params
    const session = await requirePageSession(request)

    const environments = await db.query.environment.findMany({ where: { projectId }, orderBy: { createdAt: 'asc' } })
    const matchedEnv = environments.find((e) => e.slug === envSlug)
    if (!matchedEnv && environments[0]) {
      throw redirect(`/dash/projects/${encodeURIComponent(projectId)}/envs/${encodeURIComponent(environments[0].slug)}/history/reads`)
    }

    const access = await getProjectMemberAccess(session.userId, projectId)
    const isAdmin = access?.role === 'admin'
    let reads: { id: string; seq: number; kind: string; names: string[]; ipAddress: string | null; createdAt: number; who: string }[] = []
    if (matchedEnv && isAdmin) {
      const rows = await db.query.secretRead.findMany({
        where: { environmentId: matchedEnv.id },
        orderBy: { seq: 'desc' },
        limit: 500,
      })
      const names = await actorNames(rows.map((r) => r.actor))
      reads = rows.map((r) => ({
        id: r.id, seq: r.seq, kind: r.kind, names: r.names, ipAddress: r.ipAddress, createdAt: r.createdAt,
        who: actorName(names, r.actor),
      }))
    }

    return {
      reads,
      selectedEnvId: matchedEnv?.id ?? null,
      isProtected: matchedEnv?.protected ?? false,
      isAdmin,
      projectId,
    }
  })

  .page('/dash/projects/:projectId/envs/:envSlug/history/reads', async () => {
    const { ReadsTable } = await import('sigillo-app/src/components/reads-table')

    return (
      <div className="flex flex-col gap-3 w-full">
        <ReadsTable />
      </div>
    )
  })

  // ── Your passkeys ──────────────────────────────────────────────────
  .loader('/dash/passkeys', async ({ request }) => {
    const session = await requirePageSession(request)
    const passkeys = await getDb().query.passkey.findMany({
      where: { userId: session.userId },
      columns: { id: true, name: true, backedUp: true, createdAt: true },
      orderBy: { createdAt: 'asc' },
    })
    return {
      passkeys: passkeys.map((p) => ({ ...p, createdAt: p.createdAt ?? 0 })),
      // The first passkey needs a sign-in from the last 5 minutes, and any
      // further one a login from the last day (better-auth's freshAge)
      freshSignIn: isFreshSignIn(session),
      recentLogin: await isSessionFresh(request, session.sessionCreatedAt),
      // Approvals to add a passkey: on another device, or by an admin
      enrollment: await enrollmentState(session),
      approveUrl: new URL('/approve', getRequestOrigin(request)).toString(),
    }
  })

  .page('/dash/passkeys', async () => {
    const { PasskeysPage } = await import('sigillo-app/src/components/passkeys-page')
    return (
      <div className="flex flex-col gap-3 w-full">
        <PasskeysPage />
      </div>
    )
  })

  // ── Approving a CLI read ───────────────────────────────────────────
  // The CLI prints this page and a code; the code is typed here, never part
  // of a link, so a link someone sends you approves nothing.
  .page('/approve', async ({ request }) => {
    const session = await getSession(request)
    if (!session) return Response.redirect(new URL('/login?redirect=/approve', request.url).toString(), 302)
    const { ApprovePage } = await import('sigillo-app/src/components/approve-page')
    return <ContentFrame><ApprovePage /></ContentFrame>
  })

  // ── Your sessions ──────────────────────────────────────────────────
  .loader('/dash/sessions', async ({ request }) => {
    const sessions = await listUserSessions(request)
    return { sessions: sessions ?? [], signInAgain: sessions === null }
  })

  .page('/dash/sessions', async () => {
    const { SessionsPage } = await import('sigillo-app/src/components/sessions-page')
    return (
      <div className="flex flex-col gap-3 w-full">
        <SessionsPage />
      </div>
    )
  })

  // ── Tokens page ────────────────────────────────────────────────────
  .loader('/dash/projects/:projectId/machines', async ({ params, request }) => {
    const db = getDb()
    const { projectId } = params
    const session = await requirePageSession(request)
    const access = await requirePageProjectAccess(session.userId, projectId)

    const isAdmin = access?.role === 'admin'
    const [tokens, rules] = await Promise.all([
      // Tokens workloads got for their JWTs show under their trust rule
      db.query.apiToken.findMany({
        where: { projectId, workload: { isNull: true } },
        with: {
          creator: { columns: { id: true, name: true } },
          environments: { with: { environment: { columns: { id: true, name: true } } } },
        },
        orderBy: { createdAt: 'desc' },
      }),
      isAdmin
        ? db.query.trustRule.findMany({
          where: { projectId },
          with: {
            creator: { columns: { name: true } },
            tokens: { columns: { id: true, name: true, createdAt: true, expiresAt: true, lastUsedIp: true }, orderBy: { createdAt: 'desc' }, limit: 20 },
          },
          orderBy: { createdAt: 'desc' },
        })
        : [],
    ])

    return {
      projectId,
      isAdmin,
      origin: getRequestOrigin(request),
      rules: rules.map((rule) => ({
        id: rule.id,
        name: rule.name,
        issuer: rule.issuer,
        discovered: rule.jwksUri !== null,
        keyIds: rule.jwks.keys.map((key) => String(key.kid ?? '')).filter(Boolean),
        audience: rule.audience,
        subject: rule.subject,
        claims: rule.claims,
        environmentIds: rule.environmentIds,
        protectedAccess: rule.protectedAccess,
        createdBy: rule.creator?.name ?? '—',
        createdAt: rule.createdAt,
        expiresAt: rule.expiresAt,
        lastUsedAt: rule.lastUsedAt,
        exchanges: rule.tokens,
      })),
      tokens: tokens.map((t) => ({
        id: t.id,
        name: t.name,
        prefix: t.prefix,
        environmentNames: t.environments
          .map((row) => row.environment?.name)
          .filter((name): name is string => Boolean(name)),
        createdBy: t.creator?.name ?? '—',
        // Its creator or an admin deletes it
        deletable: access?.role === 'admin' || t.createdBy === session.userId,
        createdAt: t.createdAt,
        expiresAt: t.expiresAt,
        lastUsedAt: t.lastUsedAt,
        lastUsedIp: t.lastUsedIp,
        protectedAccess: t.protectedAccess,
      })),
    }
  })

  .page('/dash/projects/:projectId/machines', async () => {
    const { TokensPage } = await import('sigillo-app/src/components/tokens-page')

    return (
      <div className="flex flex-col gap-3 w-full">
        <TokensPage />
      </div>
    )
  })

  // ── Settings page ────────────────────────────────────────────────
  .loader('/dash/projects/:projectId/settings', async ({ params, request }) => {
    const db = getDb()
    const session = await requirePageSession(request)
    await requirePageProjectAccess(session.userId, params.projectId)
    // What deleting the project takes with it
    const environments = await db.query.environment.findMany({ where: { projectId: params.projectId }, columns: { id: true } })
    const secretCounts = await countSecrets(environments.map((env) => env.id))
    return {
      environmentCount: environments.length,
      secretCount: Object.values(secretCounts).reduce((sum, count) => sum + count, 0),
    }
  })

  .page('/dash/projects/:projectId/settings', async () => {
    const { ProjectSettingsPage } = await import('sigillo-app/src/components/project-settings-page')

    return (
      <div className="flex flex-col gap-3 w-full">
        <ProjectSettingsPage />
      </div>
    )
  })

  // ── Device flow verification page (standalone, no sidebar) ─────
  // Uses the proper BetterAuth device authorization client flow:
  // 1. Validate code via authClient.device({ query: { user_code } })
  // 2. Approve/deny via authClient.device.approve() / .deny()
  .page('/device', async ({ request }) => {
    // User must be logged in to approve device codes
    const session = await getSession(request)
    if (!session) return Response.redirect(new URL('/login', request.url).toString(), 302)
    // The code is typed, never taken from the link (like /approve): a link
    // someone sends you then approves nothing
    const { DeviceFlow } = await import('sigillo-app/src/components/device-flow')
    return <ContentFrame><DeviceFlow /></ContentFrame>
  })

  // ── Sign out ────────────────────────────────────────────────────
  // Clears the local session, then hands off to the provider so the SSO
  // session at PROVIDER_URL dies too. Signing out only here is not enough:
  // the provider would still hold a live session and the next sign-in would
  // silently reuse it, making it impossible to switch Google accounts.
  //
  // This is a full navigation (not authClient.signOut() in the browser)
  // because the second half has to be a cross-origin redirect the browser
  // follows, so the provider can set its own expired Set-Cookie.
  // Another site's link or form doesn't sign anyone out unasked: it gets a
  // page that asks first. Sigillo's own pages and a typed address go through.
  .get('/logout', async ({ request }) => {
    const site = request.headers.get('sec-fetch-site')
    if (site && site !== 'same-origin' && site !== 'none') return confirmLogout(request)
    return logout(request)
  })
  .post('/logout', async ({ request }) => {
    const origin = request.headers.get('origin')
    if (origin && origin !== new URL(request.url).origin) return confirmLogout(request)
    return logout(request)
  })

  // ── Login page (standalone, no sidebar) ─────────────────────────
  .page('/login', async ({ request, redirect }) => {
    const session = await getSession(request)
    const url = new URL(request.url)
    const redirectTo = safeRedirectPath(url.searchParams.get('redirect'))
    const error = url.searchParams.get('error')
    if (session) throw redirect(redirectTo)
    const { LoginButton } = await import('sigillo-app/src/components/login-button')
    return (
      <ContentFrame className="flex grow justify-center items-center">
        <div className="text-center max-w-sm">
          <SigilloLogo className="h-[40px] w-auto mx-auto mb-2" />
          <p className="text-muted-foreground mb-6">Sign in to manage your secrets</p>
          {error && <p className="text-sm text-destructive mb-6">{loginErrorMessage(error)}</p>}
          <LoginButton callbackURL={redirectTo} />
        </div>
      </ContentFrame>
    )
  })

  // ── Invite accept page (standalone, no sidebar) ────────────────
  .page('/invite/:id', async ({ params, request, redirect }) => {
    const db = getDb()
    const invite = await db.query.orgInvitation.findFirst({
      where: { id: params.id },
      with: { org: { columns: { id: true, name: true } }, creator: { columns: { name: true } } },
    })
    if (!invite || invite.expiresAt < Date.now()) {
      return (
        <ContentFrame className="flex grow justify-center items-center">
          <div className="text-center max-w-sm">
            <h1 className="text-2xl font-bold tracking-tight mb-2">Invalid Invitation</h1>
            <p className="text-muted-foreground">This invitation link is invalid or has expired.</p>
          </div>
        </ContentFrame>
      )
    }
    const session = await getSession(request)
    if (!session) {
      const redirectPath = `/invite/${encodeURIComponent(params.id)}`
      return Response.redirect(new URL(`/login?redirect=${encodeURIComponent(redirectPath)}`, request.url).toString(), 302)
    }
    // Already a member? Skip straight to the org
    const existing = await db.query.orgMember.findFirst({
      where: { orgId: invite.orgId, userId: session.userId },
    })
    if (existing) throw redirect(`/dash/orgs/${encodeURIComponent(invite.orgId)}`)
    const { AcceptInviteButton } = await import('sigillo-app/src/components/accept-invite-button')
    return (
      <ContentFrame className="flex grow justify-center items-center">
        <div className="text-center max-w-sm space-y-4">
          <h1 className="text-2xl font-bold tracking-tight">Join {invite.org!.name}</h1>
          <p className="text-muted-foreground text-sm">
            <span className="font-medium text-foreground">{invite.creator!.name}</span> invited you to join this organization.
          </p>
          <p className="text-muted-foreground text-xs">
            This will give you access to <strong>all projects</strong> in this organization.
          </p>
          <AcceptInviteButton invitationId={params.id} />
        </div>
      </ContentFrame>
    )
  })

  // ── REST API (separate sub-app) ─────────────────────────────────
  .use(apiApp)

  .get('/', ({ request }) => Response.redirect(new URL('/dash', request.url).toString(), 302))

// Signs out of the app, then of the login provider, which sends the browser
// back to /login
async function logout(request: Request) {
  const origin = getRequestOrigin(request)
  // "Sign in again" comes back to the page it was on
  const login = new URL('/login', origin)
  const back = new URL(request.url).searchParams.get('redirect')
  if (back) login.searchParams.set('redirect', safeRedirectPath(back))
  const providerSignOut = new URL('/sign-out', env.PROVIDER_URL)
  providerSignOut.searchParams.set('client_id', await ensureOAuthClient(request))
  providerSignOut.searchParams.set('post_logout_redirect_uri', login.toString())

  const res = new Response(null, { status: 302, headers: { Location: providerSignOut.toString() } })

  // signOut throws when there is no session cookie, so only call it when a
  // session actually resolved. Hitting /logout while already signed out is
  // normal and must still forward to the provider.
  if (await getSession(request)) {
    const auth = await getAuth(request)
    const { headers } = await auth.api.signOut({ headers: request.headers, returnHeaders: true })
    for (const cookie of headers.getSetCookie()) res.headers.append('Set-Cookie', cookie)
  }

  return res
}

function confirmLogout(request: Request) {
  const back = new URL(request.url).searchParams.get('redirect')
  const action = back ? `/logout?${new URLSearchParams({ redirect: safeRedirectPath(back) })}` : '/logout'
  const escaped = action.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
  return new Response(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log out · Sigillo</title>
<style>
  body { margin: 0; min-height: 90vh; display: grid; place-items: center; font: 16px system-ui, sans-serif; color: #171717; background: #fdfcfb; }
  @media (prefers-color-scheme: dark) { body { color: #f5f5f5; background: #0a0a0a; } }
</style>
<form method="post" action="${escaped}">
  <p>Log out of Sigillo?</p>
  <button type="submit">Log out</button> <a href="/dash">Cancel</a>
</form>
</html>
`, { headers: { 'content-type': 'text/html; charset=utf-8' } })
}

// The projects of an organization for its sidebar
async function orgSidebar({ request, userId, orgId }: { request: Request; userId: string; orgId: string }) {
  const accessibleIds = await getAccessibleProjectIds(userId, orgId)
  const allProjects = await getDb().query.project.findMany({
    where: { orgId },
    with: { environments: true },
    orderBy: { createdAt: 'desc' },
  })
  const projects = allProjects
    .filter((p) => accessibleIds === null || accessibleIds.includes(p.id))
    .map((p) => ({ id: p.id, name: p.name, envSlug: projectEnvSlug(request, p.id, p.environments || []) }))
  return {
    orgId,
    projectId: null,
    projects,
    environments: [],
    currentProjectEnvSlug: null,
  }
}

/** Shared HTML shell for all pages (dash, login, device, invite).
 *  This replaces the old global layout('/*'). */
const appThemeScript = `(function(){var d=document.documentElement;var m=document.cookie.match(/(?:^|;\\s*)color-theme=(light|dark)(?:;|$)/);var t=m?m[1]:null;if(!t)t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';if(t==='dark')d.classList.add('dark');else d.classList.remove('dark')})()`

function getInitialThemeClass(request: Request) {
  const cookie = request.headers.get('cookie') ?? ''
  return /(?:^|;\s*)color-theme=dark(?:;|$)/.test(cookie) ? 'dark' : undefined
}

function AppShell({ children, mobileMenuSlot, request }: { children: React.ReactNode; mobileMenuSlot?: React.ReactNode; request: Request }) {
  return (
    <html lang="en" className={cn("h-dvh", getInitialThemeClass(request))} data-default-theme="system" suppressHydrationWarning>
      <Head>
        <Head.Meta charSet="UTF-8" />
        <Head.Meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <Head.Title>Sigillo — Secret Manager</Head.Title>
        <Head.Link rel="icon" type="image/png" href="/favicon.png" />
      </Head>
      <body className="relative flex h-dvh flex-col bg-background font-sans antialiased">
        <StradaShellBrowser />
        <script dangerouslySetInnerHTML={{ __html: appThemeScript }} />
        <ProgressBar color="var(--primary)" />
        <Navbar mobileMenuSlot={mobileMenuSlot} />
        <div className="shrink-0 border-t border-border" />
        <div className="flex min-h-0 grow flex-col">
          {children ?? (
            <div className="relative flex min-h-0 grow items-center justify-center max-w-(--content-max-width) mx-auto w-full border-x border-border text-muted-foreground py-12">
              <GridDot position="tl" />
              <GridDot position="tr" />
              Page not found
            </div>
          )}
        </div>
        <Footer />
      </body>
    </html>
  )
}


function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} xmlns="http://www.w3.org/2000/svg">
      <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
    </svg>
  )
}

function TabBar({
  projectId,
  pathname,
  envSlug: rememberedEnvSlug,
}: {
  projectId: string
  pathname: string
  envSlug: string | null
}) {
  const base = `/dash/projects/${projectId}`
  const envMatch = pathname.match(new RegExp(`^${base}/envs/([^/]+)(?:/(history)(?:/reads)?)?$`))
  const envSlug = envMatch?.[1] ?? rememberedEnvSlug
  // The tab under an environment; matched by position, since an environment can be named `history`
  const envTab = envMatch ? envMatch[2] ?? 'secrets' : null
  const secretsHref = envSlug
    ? router.href('/dash/projects/:projectId/envs/:envSlug', { projectId, envSlug })
    : router.href('/dash/projects/:projectId', { projectId })
  const historyHref = envSlug
    ? router.href('/dash/projects/:projectId/envs/:envSlug/history', { projectId, envSlug })
    : router.href('/dash/projects/:projectId/history', { projectId })
  const tabs = [
    { label: 'Secrets', href: secretsHref, active: pathname === base || envTab === 'secrets' },
    { label: 'Environments', href: router.href('/dash/projects/:projectId/environments', { projectId }), active: pathname === `${base}/environments` },
    { label: 'Machines', href: router.href('/dash/projects/:projectId/machines', { projectId }), active: pathname === `${base}/machines` },
    { label: 'History', href: historyHref, active: pathname === `${base}/history` || envTab === 'history' },
    { label: 'Settings', href: router.href('/dash/projects/:projectId/settings', { projectId }), active: pathname === `${base}/settings` },
  ] as const

  return (
    <div className="relative max-w-(--content-max-width) mx-auto w-full border-x border-border">
      <GridDot position="tl" />
      <GridDot position="tr" />
      <GridDot position="bl" />
      <GridDot position="br" />
      <div className="flex h-10 items-stretch gap-4 sm:gap-6 px-4 sm:px-6 overflow-x-auto scrollbar-hide">
        {tabs.map((tab) => (
          <Link
            key={tab.href}
            href={tab.href}
            className={cn(
              "relative flex items-center shrink-0 whitespace-nowrap text-sm no-underline transition-colors duration-150",
              tab.active
                ? "font-medium text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            {tab.active && (
              <div className="absolute bottom-0 left-0 w-full h-[2.5px] bg-primary rounded-sm" />
            )}
          </Link>
        ))}
      </div>
    </div>
  )
}

/** Decorative dot placed at border intersections. Must be inside a relative container.
    Outer circle masks the border crossing with the page bg, inner dot marks the joint. */
const gridDotPosition = {
  tl: 'top-0 left-0 -translate-x-1/2 -translate-y-1/2',
  tr: 'top-0 right-0 translate-x-1/2 -translate-y-1/2',
  bl: 'bottom-0 left-0 -translate-x-1/2 translate-y-1/2',
  br: 'bottom-0 right-0 translate-x-1/2 translate-y-1/2',
} as const

function GridDot({ position }: { position: keyof typeof gridDotPosition }) {
  return (
    <div aria-hidden className={cn(
      'absolute z-20 size-5 rounded-full bg-background pointer-events-none',
      'after:content-[""] after:block after:size-[2px] after:rounded-full after:bg-foreground/40 after:m-auto',
      'flex items-center justify-center',
      gridDotPosition[position],
    )} />
  )
}

function ContentFrame({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("min-h-0 grow max-w-(--content-max-width) mx-auto w-full border-x border-border", className)}>
      {children}
    </div>
  )
}

function Navbar({ mobileMenuSlot }: { mobileMenuSlot?: React.ReactNode }) {
  return (
    <nav className="sticky top-0 z-50 w-full shrink-0 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="relative max-w-(--content-max-width) mx-auto border-x border-border">
        <GridDot position="bl" />
        <GridDot position="br" />
        <div className="flex h-14 items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-2">
            {mobileMenuSlot}
            <Link href={router.href('/dash')} className="text-primary hover:opacity-80 transition-opacity">
              <SigilloLogo className="h-[36px] w-auto shrink-0" />
            </Link>
          </div>
          <div className="hidden md:flex items-center gap-3">
            <a
              href={DOCS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              docs
            </a>
            <a
              href="https://github.com/kldzj/sigillo/issues/new"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              feedback
            </a>
            <a
              href="https://github.com/kldzj/sigillo"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              github
            </a>
          </div>
        </div>
      </div>
    </nav>
  )
}

async function Footer() {
  const { FooterColo, ThemeSelect } = await import('sigillo-app/src/components/sidebar')
  return (
    <footer className="flex shrink-0 flex-col">
      <div className="border-t border-border" />
      <div className="relative max-w-(--content-max-width) grow mx-auto w-full border-x border-border">
        <GridDot position="tl" />
        <GridDot position="tr" />
        <div className="flex flex-wrap items-center justify-end gap-4 px-6 py-5">
          <ThemeSelect />
          <FooterColo />
          <a
            href="https://github.com/remorses/sigillo"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Based on Sigillo by Tommy D. Rossi
          </a>
          <a
            href="https://github.com/kldzj/sigillo"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <GitHubIcon className="size-4" />
          </a>
        </div>
      </div>
    </footer>
  )
}

// Browser telemetry: project id is passed at request time from the worker
// env instead of being inlined at build time, because the same vite build
// output is packaged into the self-host bundle. Self-hosted instances have
// no STRADA_PROJECT_ID binding, so this renders nothing for them.
async function StradaShellBrowser() {
  if (!env.STRADA_PROJECT_ID) return null
  const { StradaBrowser } = await import('sigillo-app/src/components/strada-browser')
  return <StradaBrowser projectId={env.STRADA_PROJECT_ID} environment={env.STRADA_ENVIRONMENT} />
}

export type App = typeof app

export default {
  fetch: async (request: Request) => {
    // Cache API keys must live on this Worker's own origin, and that origin is
    // only knowable from a real request (preview, production, and every
    // self-hosted instance run on different domains). No-op after the first call.
    rememberCacheOrigin(request.url)
    // Safe to call on every request — no-op after the first call.
    // Gated so self-hosted instances (no STRADA_PROJECT_ID binding) send nothing.
    if (env.STRADA_PROJECT_ID) {
      initStrada({
        projectId: env.STRADA_PROJECT_ID,
        token: env.STRADA_TOKEN,
        service: 'sigillo-app',
        environment: env.STRADA_ENVIRONMENT,
      })
    }
    // An instance is private: search engines shouldn't list any of it
    const response = await app.handle(request)
    const headers = new Headers(response.headers)
    headers.set('X-Robots-Tag', 'noindex, nofollow')
    // No page is meant to be embedded: another page could frame /device or
    // /approve and have someone click through them unseen
    headers.set('X-Frame-Options', 'DENY')
    headers.set('Content-Security-Policy', "frame-ancestors 'none'")
    headers.set('X-Content-Type-Options', 'nosniff')
    headers.set('Referrer-Policy', 'same-origin')
    // Browsers that saw the instance once never ask for it over plain http
    headers.set('Strict-Transport-Security', 'max-age=31536000')
    // Secret values, names and logins stay out of the browser's and any
    // proxy's cache; the static assets don't come through here
    if (!headers.has('Cache-Control')) headers.set('Cache-Control', 'no-store')
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
  },
} satisfies ExportedHandler<Env>

declare module 'spiceflow/react' {
  interface SpiceflowRegister { app: typeof app }
}
