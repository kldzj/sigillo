// `npx @kldzj/sigillo self-host` — deploy Sigillo to the customer's own Cloudflare
// account. TypeScript-only command (goke + clack), invoked from bin.ts before
// the Zig binary is exec'd, so it only exists in the npm package.
//
// Deploys two workers: the app and its own login provider (Google sign-in),
// so a deployment depends on nobody else's infrastructure.
//
// Idempotent: re-running updates both workers to the latest release, applies
// only new D1 migrations, and never rotates BETTER_AUTH_SECRET or ENCRYPTION_KEY.

import { goke, colors, isAgent } from 'goke'
import * as clack from '@clack/prompts'
import { z } from 'zod'
import {
  acquireLock,
  resolveCloudflareAuth,
  readState,
  writeState,
  type CfClient,
  type DeploymentState,
  type WorkerSettings,
} from './cloudflare.js'
import {
  appCompatibilityFlags,
  applyMigrations,
  ensureDatabase,
  fetchReleaseInfo,
  isSigilloProviderWorker,
  isSigilloWorker,
  providerSecretsForDeploy,
  secretsForDeploy,
  loadBundle,
  syncAssets,
  uploadWorker,
  waitForHealth,
  type SelfhostBundle,
} from './deploy.js'

const cli = goke('sigillo self-host')

cli
  .command(
    '',
    'Deploy Sigillo and its own login provider to your Cloudflare account (Workers + D1). Safe to re-run for updates.',
  )
  .option('--name [name]', z.string().optional().describe('Worker name (default: sigillo)'))
  .option('--account [id]', z.string().optional().describe('Cloudflare account id'))
  .option('--api-token [token]', z.string().optional().describe('Cloudflare API token (or CLOUDFLARE_API_TOKEN env)'))
  .option('--bundle [path]', z.string().optional().describe('Deploy a local bundle file instead of the latest release'))
  .option('--release-url [url]', z.string().optional().describe('Download the bundle from a custom URL'))
  .option('--domain [hostname]', z.string().optional().describe('Attach this custom domain (zone must be on your account)'))
  .option('--skip-domain', 'Skip the custom domain prompt')
  .option('--google-client-id [id]', z.string().optional().describe('Google OAuth client ID for the login provider (asked for on a new deployment)'))
  .option('--google-client-secret [secret]', z.string().optional().describe('Google OAuth client secret for the login provider'))
  .option('--yes', 'Accept all defaults (non-interactive)')
  .example('npx @kldzj/sigillo self-host')
  .example('npx @kldzj/sigillo self-host --name sigillo --domain secrets.acme.com')
  .example('CLOUDFLARE_API_TOKEN=xxx npx @kldzj/sigillo self-host --yes --google-client-id xxx --google-client-secret xxx')
  .action(async (options) => {
    clack.intro(colors.bold('sigillo self-host'))
    const releaseLock = acquireLock()
    try {
      await selfHost(options)
    } catch (error) {
      clack.log.error(error instanceof Error ? error.message : String(error))
      process.exitCode = 1
    } finally {
      releaseLock()
    }
  })

interface SelfHostOptions {
  name?: string
  account?: string
  apiToken?: string
  bundle?: string
  releaseUrl?: string
  domain?: string
  skipDomain?: boolean
  googleClientId?: string
  googleClientSecret?: string
  yes?: boolean
}

const interactive = () => process.stdin.isTTY && !isAgent

async function selfHost(options: SelfHostOptions) {
  const client = await resolveCloudflareAuth({ apiToken: options.apiToken })
  const state = readState()
  const savedDeployments = Object.values(state.deployments ?? {})

  // ── Account ───────────────────────────────────────────────────────
  const accounts = await client.listAccounts()
  if (accounts.length === 0) {
    throw new Error('No Cloudflare accounts are accessible with these credentials')
  }
  let accountId: string | undefined = options.account ?? savedDeployments[0]?.accountId
  if (accountId && !accounts.some((a) => a.id === accountId)) {
    if (options.account) throw new Error(`Account ${accountId} is not accessible with these credentials`)
    accountId = undefined
  }
  if (!accountId) {
    if (accounts.length === 1 || options.yes || !interactive()) {
      accountId = accounts[0]!.id
    } else {
      const choice = await clack.select({
        message: 'Which Cloudflare account?',
        options: accounts.map((a) => ({ value: a.id, label: a.name, hint: a.id })),
      })
      if (clack.isCancel(choice)) process.exit(0)
      accountId = choice
    }
  }
  const accountName = accounts.find((a) => a.id === accountId)?.name ?? accountId

  // ── Worker name + saved deployment + conflict detection ──────────
  // An existing worker is only adopted (updated in place) when it's a known
  // deployment from local state OR it fingerprints as a Sigillo worker.
  // An unrelated worker with the same name must never be overwritten.
  let workerName = options.name ?? savedDeployments.find((d) => d.accountId === accountId)?.workerName ?? 'sigillo'
  let saved: DeploymentState | undefined
  let appSettings: WorkerSettings | null = null
  for (;;) {
    saved = readState().deployments?.[`${accountId}/${workerName}`]
    appSettings = await client.getWorkerSettings(accountId, workerName)
    if (!appSettings || saved || isSigilloWorker(appSettings)) break

    const conflict = `A worker named "${workerName}" already exists on this account and does not look like a Sigillo deployment.`
    if (!interactive() || options.yes) {
      throw new Error(`${conflict} Re-run with --name <other-name>.`)
    }
    clack.log.warn(conflict)
    const input = await clack.text({ message: 'Pick a different worker name', placeholder: 'sigillo-secrets' })
    if (clack.isCancel(input) || !String(input).trim()) process.exit(0)
    workerName = String(input).trim()
  }
  const workerExists = appSettings != null
  const stateKey = `${accountId}/${workerName}`
  if (workerExists) {
    clack.log.info(saved ? 'Found existing deployment — updating it' : 'Found an existing Sigillo worker — adopting and updating it')
  }
  clack.log.info(`Deploying worker ${colors.bold(workerName)} to account ${colors.bold(accountName)}`)

  // ── Bundle ────────────────────────────────────────────────────────
  const spinner = clack.spinner()
  spinner.start(options.bundle ? 'Loading local bundle' : 'Downloading latest Sigillo release')
  const bundle: SelfhostBundle = await loadBundle({ bundlePath: options.bundle, url: options.releaseUrl })
  spinner.stop(
    saved?.deployedVersion === bundle.version
      ? `Release v${bundle.version} (already deployed — re-syncing)`
      : `Release v${bundle.version}${saved?.deployedVersion ? ` (updating from v${saved.deployedVersion})` : ''}`,
  )

  // ── workers.dev subdomain ─────────────────────────────────────────
  // Resolved before any upload: both workers are told the provider's URL.
  const subdomain = await ensureWorkersDevSubdomain({ client, accountId, workerName, options })
  const workersDevUrl = `https://${workerName}.${subdomain}.workers.dev`

  // ── D1 + migrations ───────────────────────────────────────────────
  spinner.start('Provisioning D1 database')
  const firstMigrationName = Object.keys(bundle.app.migrations).sort()[0]
  const databaseId =
    saved?.databaseId ??
    (await ensureDatabase({
      client, accountId, name: `${workerName}-db`, firstMigrationName, dataTable: 'secret_event', secretsKept: workerExists,
    }))
  const applied = await applyMigrations({ client, accountId, databaseId, migrations: bundle.app.migrations })
  spinner.stop(
    applied.length > 0
      ? `D1 ready — applied ${applied.length} migration${applied.length > 1 ? 's' : ''}`
      : 'D1 ready — no new migrations',
  )

  // ── Secret handling (see secretsForDeploy) ────────────────────────
  const { betterAuthSecret, encryptionKey } = secretsForDeploy({ workerExists, saved })

  // ── Login provider ────────────────────────────────────────────────
  // Every deployment signs in through its own provider worker. An app that
  // already points at another provider (e.g. deployed by upstream's self-host
  // against auth.sigillo.dev) keeps it: a new provider would give every user
  // a new login identity.
  const providerWorkerName = saved?.providerWorkerName ?? `${workerName}-auth`
  const ownProviderUrl = `https://${providerWorkerName}.${subdomain}.workers.dev`
  const currentProviderUrl = plainTextBinding(appSettings, 'PROVIDER_URL')
  const provider = currentProviderUrl && currentProviderUrl !== ownProviderUrl
    ? undefined
    : await deployProvider({ client, accountId, bundle, options, saved, spinner, workerName: providerWorkerName, url: ownProviderUrl })
  if (!provider) {
    clack.log.warn(`This deployment signs in through ${currentProviderUrl} — keeping it, since a new provider would change every user's login`)
  }
  const providerUrl = provider ? ownProviderUrl : currentProviderUrl!

  // ── Save state before the app upload so re-runs resume cleanly ────
  const deployment: DeploymentState = {
    accountId,
    workerName,
    databaseId,
    betterAuthSecret: betterAuthSecret ?? saved?.betterAuthSecret,
    encryptionKey: encryptionKey ?? saved?.encryptionKey,
    ...provider,
    deployedVersion: saved?.deployedVersion,
    url: workersDevUrl,
    customDomain: saved?.customDomain,
  }
  writeState({ ...readState(), deployments: { ...readState().deployments, [stateKey]: deployment } })

  // ── Assets + worker upload ────────────────────────────────────────
  spinner.start('Uploading static assets')
  const assetsJwt = await syncAssets({
    client,
    accountId,
    scriptName: workerName,
    worker: bundle.app,
    onProgress: (uploaded, total) => {
      spinner.message(`Uploading static assets ${uploaded}/${total}`)
    },
  })
  spinner.stop('Static assets synced')

  spinner.start(`Uploading worker (${Object.keys(bundle.app.modules).length} modules)`)
  await uploadWorker(client, {
    accountId,
    scriptName: workerName,
    worker: bundle.app,
    databaseId,
    assetsJwt,
    vars: { PROVIDER_URL: providerUrl },
    secrets: betterAuthSecret
      ? { BETTER_AUTH_SECRET: betterAuthSecret, ...(encryptionKey ? { ENCRYPTION_KEY: encryptionKey } : {}) }
      : undefined,
    compatibilityFlags: appCompatibilityFlags(bundle.app.compatibilityFlags),
  })
  await client.enableWorkersDev(accountId, workerName)
  spinner.stop('Worker deployed')

  deployment.deployedVersion = bundle.version
  writeState({ ...readState(), deployments: { ...readState().deployments, [stateKey]: deployment } })

  spinner.start('Waiting for the deployment to become healthy')
  const healthy = await waitForHealth(workersDevUrl)
  spinner.stop(healthy ? 'Deployment is live' : 'Deployment uploaded (health check still propagating)')

  // ── Custom domain ─────────────────────────────────────────────────
  const customDomain = await maybeAttachDomain({ client, accountId, workerName, options, saved })
  if (customDomain) {
    deployment.customDomain = customDomain
    writeState({ ...readState(), deployments: { ...readState().deployments, [stateKey]: deployment } })
  }

  const primaryUrl = customDomain ? `https://${customDomain}` : workersDevUrl
  clack.note(
    [
      `${colors.bold('URL:')}        ${primaryUrl}`,
      ...(customDomain ? [`${colors.bold('Fallback:')}   ${workersDevUrl}`] : []),
      `${colors.bold('Version:')}    v${bundle.version}`,
      '',
      `${colors.bold('Login:')}      ${providerUrl} (Google)`,
      `Point the CLI at your instance:  sigillo login --api-url ${primaryUrl}`,
      '',
      'Re-run `npx @kldzj/sigillo self-host` anytime to deploy updates.',
    ].join('\n'),
    'Sigillo is self-hosted 🎉',
  )
  clack.outro('Done')
}

function plainTextBinding(settings: WorkerSettings | null, name: string): string | undefined {
  return settings?.bindings?.find((b) => b.type === 'plain_text' && b.name === name)?.text
}

async function ensureWorkersDevSubdomain({ client, accountId, workerName, options }: {
  client: CfClient
  accountId: string
  workerName: string
  options: SelfHostOptions
}): Promise<string> {
  const existing = (await client.getAccountSubdomain(accountId))?.subdomain
  if (existing) return existing
  let desired = workerName
  for (;;) {
    if (interactive() && !options.yes) {
      const input = await clack.text({
        message: 'Your account has no workers.dev subdomain yet — pick one',
        placeholder: desired,
        defaultValue: desired,
      })
      if (clack.isCancel(input)) process.exit(0)
      desired = String(input).trim() || desired
    }
    try {
      return (await client.createAccountSubdomain(accountId, desired)).subdomain
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      // Taken/invalid subdomains: re-prompt interactively, otherwise fail
      // with a hint since --yes runs can't pick an alternative.
      if (!interactive() || options.yes) {
        throw new Error(`Could not register workers.dev subdomain "${desired}": ${message}`)
      }
      clack.log.warn(`Subdomain "${desired}" was rejected (likely taken): ${message}`)
      desired = `${workerName}-${Math.random().toString(36).slice(2, 6)}`
    }
  }
}

// Only a brand-new login provider needs a Google OAuth client, from the
// flags or asked for here. Re-runs reuse what the state file saved.
async function askGoogleClient({ options, redirectUri }: {
  options: SelfHostOptions
  redirectUri: string
}): Promise<{ clientId: string; clientSecret: string }> {
  if (options.googleClientId && options.googleClientSecret) {
    return { clientId: options.googleClientId, clientSecret: options.googleClientSecret }
  }
  const instructions = [
    'Sign-in goes through your own login provider, which uses Google.',
    'Create an OAuth client at https://console.cloud.google.com/apis/credentials',
    '(Create credentials → OAuth client ID → Web application) with this redirect URI:',
    '',
    `  ${redirectUri}`,
  ].join('\n')
  if (!interactive() || options.yes) {
    throw new Error(`${instructions}\n\nThen re-run with --google-client-id and --google-client-secret.`)
  }
  clack.note(instructions, 'Google sign-in')
  const clientId = options.googleClientId ?? await clack.text({
    message: 'Google OAuth client ID',
    validate: (value) => (value?.trim() ? undefined : 'Required'),
  })
  if (clack.isCancel(clientId)) process.exit(0)
  const clientSecret = options.googleClientSecret ?? await clack.password({
    message: 'Google OAuth client secret',
    validate: (value) => (value?.trim() ? undefined : 'Required'),
  })
  if (clack.isCancel(clientSecret)) process.exit(0)
  return { clientId: String(clientId).trim(), clientSecret: String(clientSecret).trim() }
}

// Deploys (or updates) the deployment's own login provider: a second worker
// with its own D1, reachable at `url`. Returns what the state file keeps.
async function deployProvider({ client, accountId, bundle, options, saved, spinner, workerName, url }: {
  client: CfClient
  accountId: string
  bundle: SelfhostBundle
  options: SelfHostOptions
  saved?: DeploymentState
  spinner: ReturnType<typeof clack.spinner>
  workerName: string
  url: string
}): Promise<Pick<DeploymentState, 'providerWorkerName' | 'providerDatabaseId' | 'providerAuthSecret' | 'googleClientId' | 'googleClientSecret'>> {
  const settings = await client.getWorkerSettings(accountId, workerName)
  const providerExists = settings != null
  if (providerExists && !saved?.providerWorkerName && !isSigilloProviderWorker(settings)) {
    throw new Error(
      `A worker named "${workerName}" already exists on this account and does not look like a Sigillo login provider. ` +
        'Re-run with --name <other-name>.',
    )
  }
  // A new provider needs a Google client: from the flags, else the saved one, else ask
  const useSaved = !options.googleClientId && saved?.googleClientId && saved?.googleClientSecret
  const google = providerExists || useSaved
    ? undefined
    : await askGoogleClient({ options, redirectUri: `${url}/api/auth/callback/google` })

  spinner.start('Deploying the login provider')
  const databaseId =
    saved?.providerDatabaseId ??
    (await ensureDatabase({
      client,
      accountId,
      name: `${workerName}-db`,
      firstMigrationName: Object.keys(bundle.provider.migrations).sort()[0],
      dataTable: 'jwks',
      secretsKept: providerExists,
    }))
  await applyMigrations({ client, accountId, databaseId, migrations: bundle.provider.migrations })
  const secrets = providerSecretsForDeploy({ providerExists, saved, google })
  const assetsJwt = await syncAssets({ client, accountId, scriptName: workerName, worker: bundle.provider })
  await uploadWorker(client, {
    accountId,
    scriptName: workerName,
    worker: bundle.provider,
    databaseId,
    assetsJwt,
    vars: { BETTER_AUTH_URL: url },
    secrets,
  })
  await client.enableWorkersDev(accountId, workerName)
  // The app needs the provider's discovery document before it can boot
  const healthy = await waitForHealth(url, '/api/auth/.well-known/openid-configuration')
  spinner.stop(healthy ? `Login provider is live: ${url}` : `Login provider deployed: ${url} (still propagating)`)

  return {
    providerWorkerName: workerName,
    providerDatabaseId: databaseId,
    providerAuthSecret: secrets?.BETTER_AUTH_SECRET ?? saved?.providerAuthSecret,
    googleClientId: google?.clientId ?? saved?.googleClientId,
    googleClientSecret: google?.clientSecret ?? saved?.googleClientSecret,
  }
}

async function maybeAttachDomain(args: {
  client: CfClient
  accountId: string
  workerName: string
  options: SelfHostOptions
  saved?: DeploymentState
}): Promise<string | undefined> {
  const { client, accountId, workerName, options, saved } = args
  if (options.skipDomain) return saved?.customDomain
  let hostname = options.domain

  if (!hostname) {
    if (saved?.customDomain || options.yes || !interactive()) return saved?.customDomain
    const wants = await clack.confirm({
      message: 'Attach a custom domain? (the domain must already be on this Cloudflare account)',
      initialValue: false,
    })
    if (clack.isCancel(wants) || !wants) return undefined

    const zones = await client.listZones(accountId)
    if (zones.length === 0) {
      clack.log.warn('No zones found on this account — add your domain to Cloudflare first, then re-run with --domain')
      return undefined
    }
    const zoneChoice = await clack.select({
      message: 'Which zone?',
      options: zones.map((zone) => ({ value: zone.id, label: zone.name })),
    })
    if (clack.isCancel(zoneChoice)) return undefined
    const zone = zones.find((z) => z.id === zoneChoice)!
    const input = await clack.text({
      message: 'Hostname',
      placeholder: `secrets.${zone.name}`,
      defaultValue: `secrets.${zone.name}`,
    })
    if (clack.isCancel(input)) return undefined
    hostname = String(input).trim()
    await client.attachCustomDomain(accountId, { zoneId: zone.id, hostname, service: workerName })
    clack.log.success(`Custom domain attached: https://${hostname}`)
    return hostname
  }

  // --domain flag: find the matching zone by suffix
  const zones = await client.listZones(accountId)
  const zone = zones
    .filter((z) => hostname === z.name || hostname!.endsWith(`.${z.name}`))
    .sort((a, b) => b.name.length - a.name.length)[0]
  if (!zone) {
    throw new Error(`No zone on account matches ${hostname} — add the domain to Cloudflare first`)
  }
  await client.attachCustomDomain(accountId, { zoneId: zone.id, hostname, service: workerName })
  clack.log.success(`Custom domain attached: https://${hostname}`)
  return hostname
}

cli.command('version-info', 'Show the latest available self-host release').action(async () => {
  const info = await fetchReleaseInfo()
  console.log(`latest: v${info.version}`)
  console.log(`bundle: ${info.url}`)
})

cli.help()

/** Entry from bin.ts: strips the `self-host` argv token and runs the goke CLI. */
export async function run(): Promise<void> {
  await cli.parse([process.argv[0]!, process.argv[1]!, ...process.argv.slice(3)])
}
