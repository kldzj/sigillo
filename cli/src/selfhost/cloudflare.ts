// Cloudflare authentication + API client for `npx @kldzj/sigillo self-host`.
//
// Auth ladder (first working credential wins):
//   1. --api-token flag / CLOUDFLARE_API_TOKEN env
//   2. token stored by a previous `sigillo self-host` run (refreshed if expired)
//   3. wrangler's own stored OAuth token (~/.wrangler config), refreshed and
//      written BACK to wrangler's config — refresh tokens are single-use, so
//      not writing back would break the user's `wrangler` CLI
//   4. interactive: OAuth PKCE browser flow (wrangler's public client id, same
//      approach as alchemy.run) or a pre-filled API-token creation deep link
//      for remote/headless machines
//
// Cloudflare's dash OAuth has NO device-code grant (RFC 8628), so the
// token-creation deep link is the "works over SSH" fallback.

import { createHash, randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync, chmodSync, rmSync, statSync } from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import * as clack from '@clack/prompts'
import { colors, isAgent, openInBrowser } from 'goke'

const OAUTH_CLIENT_ID = '54d11594-84e4-41aa-b438-e81b8fa78ee7' // wrangler's public PKCE client
const OAUTH_AUTH_URL = 'https://dash.cloudflare.com/oauth2/auth'
const OAUTH_TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token'
const OAUTH_CALLBACK = 'http://localhost:8976/oauth/callback'
const OAUTH_SCOPES = [
  'account:read',
  'user:read',
  'workers:write',
  'workers_scripts:write',
  'workers_routes:write',
  'd1:write',
  'zone:read',
  'offline_access',
]
export const CF_API_BASE = 'https://api.cloudflare.com/client/v4'

// Pre-filled token creation page (any device, works over SSH).
// https://developers.cloudflare.com/fundamentals/api/access-tokens/create-token/template-urls/
export const TOKEN_TEMPLATE_URL =
  'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
  encodeURIComponent(
    JSON.stringify([
      { key: 'account_settings', type: 'read' },
      { key: 'user_details', type: 'read' },
      { key: 'memberships', type: 'read' },
      { key: 'workers_scripts', type: 'edit' },
      { key: 'd1', type: 'edit' },
      { key: 'workers_routes', type: 'edit' },
      { key: 'zone', type: 'read' },
    ]),
  ) +
  '&name=sigillo-self-host&accountId=*&zoneId=all'

// ── State file (shared with deploy.ts) ─────────────────────────────

export interface OAuthTokens {
  oauth_token: string
  refresh_token: string
  /** ISO date */
  expiration_time: string
}

export interface WorkerSettings {
  /** plain_text bindings carry their value in text */
  bindings?: Array<{ type: string; name: string; text?: string }>
}

export interface DeploymentState {
  accountId: string
  workerName: string
  databaseId: string
  betterAuthSecret?: string
  /** Every new deployment's own key (random or SIGILLO_ENCRYPTION_KEY); unset for older ones that derive it */
  encryptionKey?: string
  /** the deployment's own login provider (unset when it uses another one) */
  providerWorkerName?: string
  providerDatabaseId?: string
  providerAuthSecret?: string
  googleClientId?: string
  googleClientSecret?: string
  deployedVersion?: string
  url?: string
  customDomain?: string
  /** ALLOWED_USERS on both workers: email addresses and domains, comma-separated; empty lets anyone in */
  allowedUsers?: string
}

export interface SelfhostState {
  cloudflare?: OAuthTokens
  deployments?: Record<string, DeploymentState>
}

const STATE_PATH = path.join(os.homedir(), '.sigillo', 'selfhost.json')
const LOCK_PATH = path.join(os.homedir(), '.sigillo', 'selfhost.lock')

export function readState(): SelfhostState {
  try {
    return JSON.parse(readFileSync(STATE_PATH, 'utf-8'))
  } catch {
    return {}
  }
}

// The state file holds Cloudflare tokens, BETTER_AUTH_SECRET, ENCRYPTION_KEY
// (the DB encryption key) and the provider's secrets: write it 0600, atomically (tmp + rename so
// a crash can't truncate the only copy), and re-chmod existing files that
// were created before this hardening.
export function writeState(state: SelfhostState) {
  mkdirSync(path.dirname(STATE_PATH), { recursive: true })
  const tmp = `${STATE_PATH}.tmp`
  writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 })
  renameSync(tmp, STATE_PATH)
  chmodSync(STATE_PATH, 0o600)
}

/**
 * Exclusive lock so two concurrent `self-host` runs can't race the state file
 * and generate diverging BETTER_AUTH_SECRET values. Stale locks (dead pid or
 * older than 30 minutes) are broken automatically.
 */
export function acquireLock(): () => void {
  mkdirSync(path.dirname(LOCK_PATH), { recursive: true })
  try {
    writeFileSync(LOCK_PATH, String(process.pid), { flag: 'wx', mode: 0o600 })
  } catch {
    let stale = false
    try {
      const pid = Number(readFileSync(LOCK_PATH, 'utf-8').trim())
      const age = Date.now() - statSync(LOCK_PATH).mtimeMs
      let alive = false
      try {
        process.kill(pid, 0)
        alive = true
      } catch {}
      stale = !alive || age > 30 * 60 * 1000
    } catch {
      stale = true
    }
    if (!stale) {
      throw new Error('Another `sigillo self-host` run is in progress. If that is wrong, delete ~/.sigillo/selfhost.lock')
    }
    writeFileSync(LOCK_PATH, String(process.pid), { mode: 0o600 })
  }
  const release = () => {
    try {
      rmSync(LOCK_PATH)
    } catch {}
  }
  // Prompt cancellations call process.exit() directly, which skips finally
  // blocks — clean the lock on process exit too (release is idempotent).
  process.on('exit', release)
  return release
}

// ── API client ──────────────────────────────────────────────────────

export class CloudflareApiError extends Error {
  status: number
  errors: Array<{ code: number; message: string }>
  constructor({ status, errors, context }: {
    status: number
    errors: Array<{ code: number; message: string }>
    context: string
  }) {
    const detail = errors.map((e) => `${e.message} [${e.code}]`).join('; ') || `HTTP ${status}`
    super(`Cloudflare API error (${context}): ${detail}`)
    this.status = status
    this.errors = errors
  }
}

export class CfClient {
  constructor(public token: string) {}

  async fetch<T>(args: {
    method: string
    path: string
    body?: object
    formData?: FormData
    headers?: Record<string, string>
  }): Promise<T> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      ...args.headers,
    }
    let body: string | FormData | undefined
    if (args.formData) {
      body = args.formData
    } else if (args.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify(args.body)
    }
    const res = await fetch(`${CF_API_BASE}${args.path}`, { method: args.method, headers, body })
    const text = await res.text()
    let envelope: { success: boolean; errors: Array<{ code: number; message: string }>; result: T }
    try {
      envelope = JSON.parse(text)
    } catch {
      throw new CloudflareApiError({
        status: res.status,
        errors: [{ code: res.status, message: text.slice(0, 300) }],
        context: args.path,
      })
    }
    if (!res.ok || !envelope.success) {
      throw new CloudflareApiError({ status: res.status, errors: envelope.errors ?? [], context: args.path })
    }
    return envelope.result
  }

  get<T>(path: string) {
    return this.fetch<T>({ method: 'GET', path })
  }

  /** GET that resolves to null on 404/1000-series "not found" errors */
  async getOrNull<T>(path: string): Promise<T | null> {
    try {
      return await this.get<T>(path)
    } catch (error) {
      if (error instanceof CloudflareApiError && (error.status === 404 || error.status === 400)) return null
      throw error
    }
  }

  listAccounts() {
    return this.get<Array<{ id: string; name: string }>>('/accounts?per_page=50')
  }

  listZones(accountId: string) {
    return this.get<Array<{ id: string; name: string }>>(`/zones?account.id=${accountId}&per_page=50`)
  }

  async findD1ByName(accountId: string, name: string) {
    const list = await this.get<Array<{ uuid: string; name: string }>>(
      `/accounts/${accountId}/d1/database?name=${encodeURIComponent(name)}&per_page=100`,
    )
    return list.find((db) => db.name === name) ?? null
  }

  createD1(accountId: string, name: string) {
    return this.fetch<{ uuid: string; name: string }>({
      method: 'POST',
      path: `/accounts/${accountId}/d1/database`,
      body: { name },
    })
  }

  d1Query({ accountId, databaseId, sql, params = [] }: {
    accountId: string
    databaseId: string
    sql: string
    params?: string[]
  }) {
    return this.fetch<Array<{ results: Array<Record<string, unknown>> }>>({
      method: 'POST',
      path: `/accounts/${accountId}/d1/database/${databaseId}/query`,
      body: { sql, params },
    })
  }

  /** Script settings, or null when the worker doesn't exist. Bindings are
   *  used to fingerprint whether an existing worker is a Sigillo deployment. */
  getWorkerSettings(accountId: string, scriptName: string) {
    return this.getOrNull<WorkerSettings>(
      `/accounts/${accountId}/workers/scripts/${scriptName}/settings`,
    )
  }

  putWorker({ accountId, scriptName, formData }: { accountId: string; scriptName: string; formData: FormData }) {
    return this.fetch<{ id: string }>({
      method: 'PUT',
      path: `/accounts/${accountId}/workers/scripts/${scriptName}`,
      formData,
    })
  }

  createAssetsUploadSession({ accountId, scriptName, manifest }: {
    accountId: string
    scriptName: string
    manifest: Record<string, { hash: string; size: number }>
  }) {
    return this.fetch<{ jwt: string; buckets?: string[][] } | null>({
      method: 'POST',
      path: `/accounts/${accountId}/workers/scripts/${scriptName}/assets-upload-session`,
      body: { manifest },
    })
  }

  uploadAssetsBucket({ accountId, uploadJwt, formData }: {
    accountId: string
    uploadJwt: string
    formData: FormData
  }) {
    return this.fetch<{ jwt?: string }>({
      method: 'POST',
      path: `/accounts/${accountId}/workers/assets/upload?base64=true`,
      formData,
      headers: { Authorization: `Bearer ${uploadJwt}` },
    })
  }

  getAccountSubdomain(accountId: string) {
    return this.getOrNull<{ subdomain: string | null }>(`/accounts/${accountId}/workers/subdomain`)
  }

  createAccountSubdomain(accountId: string, subdomain: string) {
    return this.fetch<{ subdomain: string }>({
      method: 'PUT',
      path: `/accounts/${accountId}/workers/subdomain`,
      body: { subdomain },
    })
  }

  // One secret on a deployed worker, without uploading it again
  putWorkerSecret({ accountId, scriptName, name, text }: { accountId: string; scriptName: string; name: string; text: string }) {
    return this.fetch<unknown>({
      method: 'PUT',
      path: `/accounts/${accountId}/workers/scripts/${scriptName}/secrets`,
      body: { name, text, type: 'secret_text' },
    })
  }

  deleteWorkerSecret({ accountId, scriptName, name }: { accountId: string; scriptName: string; name: string }) {
    return this.fetch<unknown>({
      method: 'DELETE',
      path: `/accounts/${accountId}/workers/scripts/${scriptName}/secrets/${name}`,
    })
  }

  enableWorkersDev(accountId: string, scriptName: string) {
    return this.fetch<unknown>({
      method: 'POST',
      path: `/accounts/${accountId}/workers/scripts/${scriptName}/subdomain`,
      body: { enabled: true, previews_enabled: false },
    })
  }

  attachCustomDomain(accountId: string, args: { zoneId: string; hostname: string; service: string }) {
    return this.fetch<{ hostname: string }>({
      method: 'PUT',
      path: `/accounts/${accountId}/workers/domains`,
      body: { zone_id: args.zoneId, hostname: args.hostname, service: args.service, environment: 'production' },
    })
  }
}

async function probeToken(token: string): Promise<boolean> {
  try {
    await new CfClient(token).get('/accounts?per_page=1')
    return true
  } catch {
    return false
  }
}

// ── OAuth PKCE flow ─────────────────────────────────────────────────

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function exchangeToken(body: Record<string, string>): Promise<OAuthTokens> {
  const res = await fetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  })
  if (!res.ok) {
    throw new Error(`Cloudflare OAuth token request failed: ${res.status} ${await res.text()}`)
  }
  const json = (await res.json()) as { access_token: string; refresh_token: string; expires_in: number }
  return {
    oauth_token: json.access_token,
    refresh_token: json.refresh_token,
    expiration_time: new Date(Date.now() + json.expires_in * 1000).toISOString(),
  }
}

export function refreshOAuthToken(refreshToken: string): Promise<OAuthTokens> {
  return exchangeToken({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: OAUTH_CLIENT_ID,
  })
}

/** Browser PKCE login against Cloudflare's dash OAuth. Requires a browser on this machine. */
export async function pkceLogin(): Promise<OAuthTokens> {
  const verifier = base64url(randomBytes(48))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  const state = base64url(randomBytes(16))

  const authUrl = new URL(OAUTH_AUTH_URL)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('client_id', OAUTH_CLIENT_ID)
  authUrl.searchParams.set('redirect_uri', OAUTH_CALLBACK)
  authUrl.searchParams.set('scope', OAUTH_SCOPES.join(' '))
  authUrl.searchParams.set('state', state)
  authUrl.searchParams.set('code_challenge', challenge)
  authUrl.searchParams.set('code_challenge_method', 'S256')

  const code = await new Promise<string>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost:8976')
      if (url.pathname !== new URL(OAUTH_CALLBACK).pathname) {
        res.writeHead(404).end()
        return
      }
      const finish = (message: string) => {
        res.writeHead(200, { 'Content-Type': 'text/html' })
        res.end(`<html><body style="font-family:sans-serif;padding:3rem"><h2>${message}</h2><p>You can close this tab and return to the terminal.</p></body></html>`)
        server.close()
        clearTimeout(timeout)
      }
      const error = url.searchParams.get('error')
      if (error) {
        finish('Sigillo: Cloudflare login was denied.')
        reject(new Error(`Cloudflare login denied: ${error}`))
        return
      }
      if (url.searchParams.get('state') !== state) {
        finish('Sigillo: login state mismatch.')
        reject(new Error('OAuth state mismatch'))
        return
      }
      const authCode = url.searchParams.get('code')
      if (!authCode) {
        finish('Sigillo: missing authorization code.')
        reject(new Error('OAuth callback missing code'))
        return
      }
      finish('Sigillo: Cloudflare login complete.')
      resolve(authCode)
    })
    const timeout = setTimeout(
      () => {
        server.close()
        reject(new Error('Timed out waiting for Cloudflare login (5 minutes)'))
      },
      5 * 60 * 1000,
    )
    server.on('error', (error) => {
      clearTimeout(timeout)
      reject(new Error(`Could not start local OAuth callback server on port 8976: ${error.message}`))
    })
    server.listen(8976, '127.0.0.1', () => {
      void openInBrowser(authUrl.toString())
    })
  })

  return exchangeToken({
    grant_type: 'authorization_code',
    code,
    redirect_uri: OAUTH_CALLBACK,
    client_id: OAUTH_CLIENT_ID,
    code_verifier: verifier,
  })
}

// ── Wrangler token reuse ────────────────────────────────────────────

interface WranglerAuthConfig extends OAuthTokens {
  scopes: string[]
}

function wranglerConfigCandidates(): string[] {
  const home = os.homedir()
  const candidates = [path.join(home, '.wrangler')]
  if (process.platform === 'darwin') {
    candidates.push(path.join(home, 'Library', 'Preferences', '.wrangler'))
  } else if (process.platform === 'win32') {
    if (process.env.APPDATA) candidates.push(path.join(process.env.APPDATA, '.wrangler'))
    if (process.env.LOCALAPPDATA) candidates.push(path.join(process.env.LOCALAPPDATA, '.wrangler'))
  } else {
    const xdg = process.env.XDG_CONFIG_HOME ?? path.join(home, '.config')
    candidates.push(path.join(xdg, '.wrangler'))
  }
  return candidates.map((dir) => path.join(dir, 'config', 'default.toml'))
}

/** Minimal TOML read of wrangler's auth config — flat string keys + a string array. */
export function parseWranglerToml(text: string): WranglerAuthConfig | null {
  const str = (key: string) => text.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, 'm'))?.[1]
  const oauth_token = str('oauth_token')
  const refresh_token = str('refresh_token')
  const expiration_time = str('expiration_time')
  if (!oauth_token || !refresh_token || !expiration_time) return null
  const scopesRaw = text.match(/scopes\s*=\s*\[([\s\S]*?)\]/)?.[1] ?? ''
  const scopes = [...scopesRaw.matchAll(/"([^"]*)"/g)].map((m) => m[1]!)
  return { oauth_token, refresh_token, expiration_time, scopes }
}

export function serializeWranglerToml(config: WranglerAuthConfig): string {
  const scopes = config.scopes.map((s) => JSON.stringify(s)).join(', ')
  return `oauth_token = ${JSON.stringify(config.oauth_token)}\nexpiration_time = ${JSON.stringify(config.expiration_time)}\nrefresh_token = ${JSON.stringify(config.refresh_token)}\nscopes = [ ${scopes} ]\n`
}

function isExpired(expirationTime: string): boolean {
  return new Date(expirationTime).getTime() - Date.now() < 60 * 1000
}

/**
 * Try to reuse (and refresh) wrangler's stored OAuth token. Writes refreshed
 * tokens back to wrangler's config file so `wrangler` keeps working — refresh
 * tokens are single-use.
 */
async function tryWranglerToken(): Promise<string | null> {
  for (const configPath of wranglerConfigCandidates()) {
    if (!existsSync(configPath)) continue
    let config: WranglerAuthConfig | null
    try {
      config = parseWranglerToml(readFileSync(configPath, 'utf-8'))
    } catch {
      continue
    }
    if (!config) continue

    if (!isExpired(config.expiration_time) && (await probeToken(config.oauth_token))) {
      return config.oauth_token
    }
    try {
      const refreshed = await refreshOAuthToken(config.refresh_token)
      writeFileSync(configPath, serializeWranglerToml({ ...refreshed, scopes: config.scopes }))
      if (await probeToken(refreshed.oauth_token)) return refreshed.oauth_token
    } catch {
      // expired/revoked refresh token — fall through to interactive login
    }
  }
  return null
}

// ── Auth ladder ─────────────────────────────────────────────────────

export async function resolveCloudflareAuth(args: { apiToken?: string }): Promise<CfClient> {
  // 1. explicit token (flag or env). If given but broken, fail loudly.
  const explicit = args.apiToken ?? process.env.CLOUDFLARE_API_TOKEN
  if (explicit) {
    if (!(await probeToken(explicit))) {
      throw new Error('The provided Cloudflare API token was rejected by the Cloudflare API')
    }
    return new CfClient(explicit)
  }

  // 2. token from a previous self-host run
  const state = readState()
  if (state.cloudflare) {
    let tokens = state.cloudflare
    if (isExpired(tokens.expiration_time)) {
      try {
        tokens = await refreshOAuthToken(tokens.refresh_token)
        writeState({ ...state, cloudflare: tokens })
      } catch {
        tokens = state.cloudflare
      }
    }
    if (!isExpired(tokens.expiration_time) && (await probeToken(tokens.oauth_token))) {
      return new CfClient(tokens.oauth_token)
    }
  }

  // 3. wrangler's stored token (refreshed + written back if expired)
  const wranglerToken = await tryWranglerToken()
  if (wranglerToken) {
    clack.log.info('Using your existing wrangler login')
    return new CfClient(wranglerToken)
  }

  // 4. interactive
  if (!process.stdin.isTTY) {
    throw new Error(
      'No Cloudflare credentials found. Set CLOUDFLARE_API_TOKEN (create one at ' +
        TOKEN_TEMPLATE_URL +
        ') or run `wrangler login` first.',
    )
  }

  const method = await clack.select({
    message: 'Log in to Cloudflare',
    options: [
      { value: 'browser', label: 'Open browser on this machine', hint: 'OAuth, recommended' },
      { value: 'token', label: 'Paste an API token', hint: 'works from any device / over SSH' },
    ],
    initialValue: isAgent ? 'token' : 'browser',
  })
  if (clack.isCancel(method)) process.exit(0)

  if (method === 'browser') {
    const tokens = await pkceLogin()
    writeState({ ...readState(), cloudflare: tokens })
    if (!(await probeToken(tokens.oauth_token))) {
      throw new Error('Cloudflare login succeeded but the token was rejected by the API')
    }
    clack.log.success('Logged in to Cloudflare')
    return new CfClient(tokens.oauth_token)
  }

  clack.log.info(
    `Create a token with the exact permissions pre-filled:\n${colors.cyan(TOKEN_TEMPLATE_URL)}`,
  )
  const pasted = await clack.password({ message: 'Paste your Cloudflare API token' })
  if (clack.isCancel(pasted)) process.exit(0)
  const token = String(pasted).trim()
  if (!(await probeToken(token))) {
    throw new Error('The pasted Cloudflare API token was rejected by the Cloudflare API')
  }
  return new CfClient(token)
}
