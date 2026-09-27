// `npx sigillo self-host` — deploy Sigillo to the customer's own Cloudflare
// account. TypeScript-only command (goke + clack), invoked from bin.ts before
// the Zig binary is exec'd, so it only exists in the npm package.
//
// Idempotent: re-running updates the worker to the latest release, applies
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
} from './cloudflare.js'
import {
  applyMigrations,
  ensureDatabase,
  fetchReleaseInfo,
  isSigilloWorker,
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
    'Deploy Sigillo to your own Cloudflare account (Worker + D1). Safe to re-run for updates.',
  )
  .option('--name [name]', z.string().optional().describe('Worker name (default: sigillo)'))
  .option('--account [id]', z.string().optional().describe('Cloudflare account id'))
  .option('--api-token [token]', z.string().optional().describe('Cloudflare API token (or CLOUDFLARE_API_TOKEN env)'))
  .option('--bundle [path]', z.string().optional().describe('Deploy a local bundle file instead of the latest release'))
  .option('--release-url [url]', z.string().optional().describe('Download the bundle from a custom URL'))
  .option('--domain [hostname]', z.string().optional().describe('Attach this custom domain (zone must be on your account)'))
  .option('--skip-domain', 'Skip the custom domain prompt')
  .option('--yes', 'Accept all defaults (non-interactive)')
  .example('npx sigillo self-host')
  .example('npx sigillo self-host --name sigillo --domain secrets.acme.com')
  .example('CLOUDFLARE_API_TOKEN=xxx npx sigillo self-host --yes')
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
  let workerExists = false
  for (;;) {
    saved = readState().deployments?.[`${accountId}/${workerName}`]
    const settings = await client.getWorkerSettings(accountId, workerName)
    workerExists = settings != null
    if (!workerExists || saved || isSigilloWorker(settings)) break

    const conflict = `A worker named "${workerName}" already exists on this account and does not look like a Sigillo deployment.`
    if (!interactive() || options.yes) {
      throw new Error(`${conflict} Re-run with --name <other-name>.`)
    }
    clack.log.warn(conflict)
    const input = await clack.text({ message: 'Pick a different worker name', placeholder: 'sigillo-secrets' })
    if (clack.isCancel(input) || !String(input).trim()) process.exit(0)
    workerName = String(input).trim()
  }
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

  // ── D1 + migrations ───────────────────────────────────────────────
  spinner.start('Provisioning D1 database')
  const firstMigrationName = Object.keys(bundle.migrations).sort()[0]
  const databaseId =
    saved?.databaseId ??
    (await ensureDatabase({ client, accountId, name: `${workerName}-db`, firstMigrationName, secretsKept: workerExists }))
  const applied = await applyMigrations({ client, accountId, databaseId, migrations: bundle.migrations })
  spinner.stop(
    applied.length > 0
      ? `D1 ready — applied ${applied.length} migration${applied.length > 1 ? 's' : ''}`
      : 'D1 ready — no new migrations',
  )

  // ── Secret handling (see secretsForDeploy) ────────────────────────
  const { betterAuthSecret, encryptionKey } = secretsForDeploy({ workerExists, saved })

  // ── Assets + worker upload ────────────────────────────────────────
  spinner.start('Uploading static assets')
  const assetsJwt = await syncAssets({
    client,
    accountId,
    scriptName: workerName,
    bundle,
    onProgress: (uploaded, total) => {
      spinner.message(`Uploading static assets ${uploaded}/${total}`)
    },
  })
  spinner.stop('Static assets synced')

  spinner.start(`Uploading worker (${Object.keys(bundle.modules).length} modules)`)
  await uploadWorker(client, { accountId, scriptName: workerName, bundle, databaseId, assetsJwt, betterAuthSecret, encryptionKey })
  spinner.stop('Worker deployed')

  // ── workers.dev URL ───────────────────────────────────────────────
  let subdomain = (await client.getAccountSubdomain(accountId))?.subdomain ?? null
  if (!subdomain) {
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
        subdomain = (await client.createAccountSubdomain(accountId, desired)).subdomain
        break
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
  await client.enableWorkersDev(accountId, workerName)
  const workersDevUrl = `https://${workerName}.${subdomain}.workers.dev`

  // ── Save state before slow steps so re-runs resume cleanly ───────
  const deployment: DeploymentState = {
    accountId,
    workerName,
    databaseId,
    betterAuthSecret: betterAuthSecret ?? saved?.betterAuthSecret,
    encryptionKey: encryptionKey ?? saved?.encryptionKey,
    deployedVersion: bundle.version,
    url: workersDevUrl,
    customDomain: saved?.customDomain,
  }
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
      'Sign in with the hosted Sigillo auth — no OAuth setup needed.',
      `Point the CLI at your instance:  sigillo login --api-url ${primaryUrl}`,
      '',
      'Re-run `npx sigillo self-host` anytime to deploy updates.',
    ].join('\n'),
    'Sigillo is self-hosted 🎉',
  )
  clack.outro('Done')
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
