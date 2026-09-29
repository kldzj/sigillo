// `npx @kldzj/sigillo self-host` — deploy Sigillo to the customer's own Cloudflare
// account. TypeScript-only command (goke + clack), invoked from bin.ts before
// the Zig binary is exec'd, so it only exists in the npm package.
//
// Deploys two workers: the app and its own login provider (Google sign-in),
// so a deployment depends on nobody else's infrastructure.
//
// Idempotent: re-running updates both workers to the latest release, applies
// only new D1 migrations, and never rotates BETTER_AUTH_SECRET or the
// encryption key. The encryption key changes only with --rotate-key.

import { randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { goke, colors, isAgent } from 'goke'
import * as clack from '@clack/prompts'
import { z } from 'zod'
import {
  acquireLock,
  resolveCloudflareAuth,
  readState,
  writeState,
  unlockState,
  changeStatePassphrase,
  type CfClient,
  type DeploymentState,
  type WorkerSettings,
} from './cloudflare.js'
import { PASSPHRASE_ENV, passphraseProblem } from './state-file.js'
import { baseKeyOf, countNotUnder, newKeyId, reencryptAll, type Query } from './rotate.js'
import { LEFT_OUT, backupFileName, dumpDatabase, keyFingerprint, keyIdsInUse, loadDatabase, newBackupIdentity, openBackup, queryOf, sealBackup, type Backup, type DatabaseDump } from './backup.js'
import { auditWitnesses, verifyHistory, type HistoryCheck } from './history.js'
import {
  appCompatibilityFlags,
  applyMigrations,
  assertNoStoredSecrets,
  assertSecretsDecryptDatabase,
  ensureDatabase,
  fetchReleaseInfo,
  isSigilloProviderWorker,
  isSigilloWorker,
  normalizeAllowedUsers,
  providerSecretsForDeploy,
  resolveDeploySecrets,
  updateAllowedUsersSecret,
  loadBundle,
  readExpectedBundle,
  isOlderVersion,
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
  .option('--bundle [path]', z.string().optional().describe("Deploy a local copy of this version's bundle instead of downloading it"))
  .option('--release-url [url]', z.string().optional().describe("Download this version's bundle from a custom URL"))
  .option('--allow-downgrade', 'Deploy even if the instance runs a newer version')
  .option('--domain [hostname]', z.string().optional().describe('Attach this custom domain (zone must be on your account)'))
  .option('--skip-domain', 'Skip the custom domain prompt')
  .option('--google-client-id [id]', z.string().optional().describe('Google OAuth client ID for the login provider (asked for on a new deployment)'))
  .option('--google-client-secret [secret]', z.string().optional().describe('Google OAuth client secret for the login provider'))
  .option('--allowed-users [list]', z.string().optional().describe('Email addresses and domains that may sign in, comma-separated (empty: anyone)'))
  .option('--change-passphrase', 'Encrypt ~/.sigillo/selfhost.json with a new passphrase, then stop')
  // No schema: goke then gives "" for a bare flag instead of undefined, which would deploy
  .option('--reset-passkeys [email]', 'Remove every passkey of this user and sign them out, for a sole admin who lost theirs, then stop')
  .option('--rotate-key', 'Give the instance a new encryption key, re-encrypt every stored value with it and retire the old key, then stop')
  .option('--backup [file]', 'Save an encrypted backup of both databases to this file (default: <name>-<time>.backup.age), then stop')
  .option('--restore [file]', 'Restore both databases from this backup into fresh ones, check their history, and switch the workers to them')
  .option('--yes', 'Accept all defaults (non-interactive)')
  .example('npx @kldzj/sigillo self-host')
  .example('npx @kldzj/sigillo self-host --name sigillo --domain secrets.acme.com')
  .example('CLOUDFLARE_API_TOKEN=xxx SIGILLO_SELFHOST_PASSPHRASE=xxx npx @kldzj/sigillo self-host --yes --google-client-id xxx --google-client-secret xxx')
  .example('# Optional, first deploy only: choose the ENCRYPTION_KEY instead of getting a random one')
  .example('SIGILLO_ENCRYPTION_KEY="$(openssl rand -base64 32)" npx @kldzj/sigillo self-host')
  .action(async (options) => {
    clack.intro(colors.bold('sigillo self-host'))
    const releaseLock = acquireLock()
    try {
      const warning = await unlockState({
        envPassphrase: process.env[PASSPHRASE_ENV],
        interactive: interactive(),
        askPassphrase,
        askNewPassphrase,
        confirmEncrypt: async () => {
          const answer = await clack.confirm({
            message: 'Encrypt ~/.sigillo/selfhost.json with a passphrase? It holds the keys to your deployments.',
          })
          if (clack.isCancel(answer)) process.exit(0)
          return answer
        },
      })
      if (warning) clack.log.warn(warning)
      if (options.resetPasskeys !== undefined) {
        await resetPasskeys(options)
        return
      }
      if (options.rotateKey) {
        await rotateKey(options)
        return
      }
      if (options.backup !== undefined) {
        await backupDeployment(options)
        return
      }
      if (options.restore !== undefined) {
        await restoreDeployment(options)
        return
      }
      if (options.changePassphrase) {
        if (!interactive()) throw new Error('--change-passphrase needs a terminal')
        changeStatePassphrase(await askNewPassphrase())
        clack.outro('~/.sigillo/selfhost.json is encrypted with the new passphrase')
        return
      }
      await selfHost(options)
    } catch (error) {
      clack.log.error(error instanceof Error ? error.message : String(error))
      process.exitCode = 1
    } finally {
      releaseLock()
    }
  })

// Recovery for a sole admin who lost every passkey: whoever controls the
// Cloudflare account controls the instance anyway, so the passkeys are
// removed in D1 directly, and the removal is logged like any other
async function resetPasskeys(options: SelfHostOptions) {
  const email = options.resetPasskeys!.trim()
  if (!email) throw new Error('Pass the email of the user: --reset-passkeys you@acme.com')
  const { deployment } = savedDeployment(options)
  const client = await resolveCloudflareAuth({ apiToken: options.apiToken })
  const database = { accountId: deployment.accountId, databaseId: deployment.databaseId }
  const [found] = await client.d1Query({
    ...database,
    sql: 'SELECT count(*) AS n FROM passkey p JOIN user u ON u.id = p.user_id WHERE lower(u.email) = lower(?)',
    params: [email],
  })
  const count = Number(found?.results[0]?.n ?? 0)
  if (count === 0) {
    clack.outro(`${email} has no passkeys on ${deployment.workerName}`)
    return
  }
  if (interactive() && !options.yes) {
    const sure = await clack.confirm({ message: `Remove ${count} passkey${count === 1 ? '' : 's'} of ${email} on ${deployment.workerName}?` })
    if (clack.isCancel(sure) || !sure) process.exit(0)
  }
  await client.d1Query({
    ...database,
    sql: "INSERT INTO passkey_event (id, user_id, actor, action, passkey_name, created_at) SELECT lower(hex(randomblob(16))), p.user_id, 'self-host', 'removed', p.name, ? FROM passkey p JOIN user u ON u.id = p.user_id WHERE lower(u.email) = lower(?)",
    params: [String(Date.now()), email],
  })
  await client.d1Query({
    ...database,
    sql: 'DELETE FROM passkey WHERE user_id IN (SELECT id FROM user WHERE lower(email) = lower(?))',
    params: [email],
  })
  // Signed out everywhere, like a reset by an admin: a new passkey then takes a fresh Google sign-in
  await client.d1Query({
    ...database,
    sql: 'DELETE FROM session WHERE user_id IN (SELECT id FROM user WHERE lower(email) = lower(?))',
    params: [email],
  })
  clack.outro(`Removed ${count} passkey${count === 1 ? '' : 's'} of ${email} and signed them out. They add new ones after signing in again.`)
}

// The one saved deployment the options point at, with its key in the state file
function savedDeployment(options: SelfHostOptions): { key: string; deployment: DeploymentState } {
  const deployments = Object.entries(readState().deployments ?? {})
    .filter(([, d]) => (!options.account || d.accountId === options.account) && (!options.name || d.workerName === options.name))
  if (deployments.length === 0) throw new Error('No saved deployment matches: pass --name, or run self-host from the machine that deployed it')
  if (deployments.length > 1) throw new Error('Several deployments are saved: pass --name')
  const [key, deployment] = deployments[0]!
  return { key, deployment }
}

function saveDeployment(key: string, deployment: DeploymentState) {
  const state = readState()
  writeState({ ...state, deployments: { ...state.deployments, [key]: deployment } })
}

// A new encryption key. The Worker gets it first, as the current key of its
// ring, so new values use it; then every stored value is re-encrypted here
// (rotate.ts); and once none uses them, the older keys leave the Worker and
// selfhost.json. Stopped halfway, the next run finishes the same rotation.
export async function rotateKey(options: SelfHostOptions) {
  const { key, deployment } = savedDeployment(options)
  const client = await resolveCloudflareAuth({ apiToken: options.apiToken })
  const worker = { accountId: deployment.accountId, scriptName: deployment.workerName }
  const query: Query = async (sql, params) =>
    (await client.d1Query({ accountId: deployment.accountId, databaseId: deployment.databaseId, sql, params }))[0]?.results ?? []
  const baseKey = baseKeyOf(deployment)
  let ring = deployment.encryptionKeys
  const unfinished = ring ? await countNotUnder(query, ring.current) : 0
  if (ring && unfinished > 0) {
    clack.log.info(`The rotation to key ${ring.current} is unfinished: ${unfinished} value${unfinished === 1 ? '' : 's'} still use an older key. Finishing it.`)
    // The run that saved the ring may have stopped before the Worker got it,
    // and the Worker can't read a value under a key it doesn't have
    await client.putWorkerSecret({ ...worker, name: 'ENCRYPTION_KEYS', text: JSON.stringify(ring) })
  } else {
    if (interactive() && !options.yes) {
      const sure = await clack.confirm({ message: `Give ${deployment.workerName} a new encryption key and re-encrypt every stored value with it?` })
      if (clack.isCancel(sure) || !sure) process.exit(0)
    }
    const id = newKeyId(ring)
    ring = { current: id, keys: { ...ring?.keys, [id]: randomBytes(32).toString('base64') } }
    // Saved before the Worker has it: a key the Worker uses is never missing here
    saveDeployment(key, { ...deployment, encryptionKeys: ring })
    await client.putWorkerSecret({ ...worker, name: 'ENCRYPTION_KEYS', text: JSON.stringify(ring) })
  }
  const spinner = clack.spinner()
  spinner.start('Re-encrypting stored values')
  const progress = (done: number) => spinner.message(`Re-encrypting stored values: ${done}`)
  let done = await reencryptAll({ query, ring, baseKey, onProgress: progress })
  // A request the Worker was still serving with its old ring may have written
  // under an older key: give those a minute, then catch them too
  spinner.message('Waiting a minute for requests that began before the new key')
  await new Promise((resolve) => setTimeout(resolve, 60_000))
  done += await reencryptAll({ query, ring, baseKey, onProgress: progress })
  spinner.stop(`Re-encrypted ${done} value${done === 1 ? '' : 's'} with key ${ring.current}`)
  if (await countNotUnder(query, ring.current) > 0) {
    throw new Error('Values under an older key appeared again, so the older keys stay: run --rotate-key again to finish')
  }
  // No value uses the older keys any more
  const retired = { current: ring.current, keys: { [ring.current]: ring.keys[ring.current]! } }
  await client.putWorkerSecret({ ...worker, name: 'ENCRYPTION_KEYS', text: JSON.stringify(retired) })
  if (deployment.encryptionKey) await client.deleteWorkerSecret({ ...worker, name: 'ENCRYPTION_KEY' })
  // Older backups need the retired keys, so their backup key goes too: the next backup makes a new one
  saveDeployment(key, { ...deployment, encryptionKeys: retired, encryptionKey: undefined, backupIdentity: undefined })
  clack.outro(`${deployment.workerName} encrypts with key ${ring.current}. The older keys are gone from the Worker and ~/.sigillo/selfhost.json.`)
  if (deployment.backupIdentity) clack.log.warn("Backups made before this rotation can't be restored any more: make a new one now (--backup).")
}

// Both databases as Cloudflare exports them, without the tables of live
// logins, in one file encrypted to the deployment's backup key (backup.ts)
async function backupDeployment(options: SelfHostOptions) {
  const { key, deployment } = savedDeployment(options)
  const client = await resolveCloudflareAuth({ apiToken: options.apiToken })
  let identity = deployment.backupIdentity
  if (!identity) {
    identity = await newBackupIdentity()
    saveDeployment(key, { ...deployment, backupIdentity: identity })
  }
  const at = new Date()
  const file = options.backup || backupFileName(deployment.workerName, at)
  if (existsSync(file)) throw new Error(`${file} already exists`)
  const app = { client, accountId: deployment.accountId, databaseId: deployment.databaseId }
  const keys = { ring: deployment.encryptionKeys, baseKey: baseKeyOf(deployment) }
  const spinner = clack.spinner()
  spinner.start('Exporting the app database')
  const backup: Backup = {
    format: 'sigillo-backup',
    version: 1,
    createdAt: at.toISOString(),
    workerName: deployment.workerName,
    sigilloVersion: deployment.deployedVersion ?? null,
    keys: Object.fromEntries((await keyIdsInUse(app)).map((id) => {
      const fingerprint = keyFingerprint(id, keys)
      if (!fingerprint) throw new Error(`Some values are encrypted with the key ${id}, which ~/.sigillo/selfhost.json doesn't have, so a backup couldn't be restored`)
      return [id, fingerprint]
    })),
    databases: { app: await dumpDatabase(app, LEFT_OUT.app), provider: null },
  }
  if (deployment.providerDatabaseId) {
    spinner.message('Exporting the login provider database')
    backup.databases.provider = await dumpDatabase({ ...app, databaseId: deployment.providerDatabaseId }, LEFT_OUT.provider)
  }
  writeFileSync(file, await sealBackup(backup, identity), { mode: 0o600, flag: 'wx' })
  spinner.stop(`Saved ${file}`)
  clack.outro('It opens with the backup key in ~/.sigillo/selfhost.json, and restores with the keys there: keep that file with your backups.')
}

// Into fresh databases, whose history is checked before both workers switch
// to them. The databases from before stay, for the operator to delete.
export async function restoreDeployment(options: SelfHostOptions) {
  if (!options.restore) throw new Error('Pass the backup file: --restore sigillo-<time>.backup.age')
  const { key, deployment } = savedDeployment(options)
  if (!deployment.backupIdentity) throw new Error('~/.sigillo/selfhost.json has no backup key for this deployment, so it has no backups to restore')
  if (!deployment.betterAuthSecret) throw new Error("~/.sigillo/selfhost.json has no BETTER_AUTH_SECRET for this deployment, so the backup's history can't be checked")
  const backup = await openBackup(new Uint8Array(readFileSync(options.restore)), deployment.backupIdentity)
  if (backup.workerName !== deployment.workerName) throw new Error(`This is a backup of ${backup.workerName}, not ${deployment.workerName}`)
  const target = readExpectedBundle()?.version ?? deployment.deployedVersion
  if (target && backup.sigilloVersion && isOlderVersion(target, backup.sigilloVersion)) {
    throw new Error(`This backup is from Sigillo ${backup.sigilloVersion}, newer than the ${target} this CLI deploys: restore it with npx @kldzj/sigillo@${backup.sigilloVersion} self-host`)
  }
  const ring = deployment.encryptionKeys
  const baseKey = baseKeyOf(deployment)
  // What `sigillo audit verify` saw on this machine, at either address of the instance
  const witnesses = auditWitnesses([deployment.url, deployment.customDomain && `https://${deployment.customDomain}`].filter((url): url is string => !!url))
  const retired = Object.entries(backup.keys).filter(([id, fingerprint]) => keyFingerprint(id, { ring, baseKey }) !== fingerprint).map(([id]) => `key ${id}`)
  if (retired.length) throw new Error(`This backup's values are encrypted with ${retired.join(', ')}, which a key rotation has since retired from ~/.sigillo/selfhost.json`)
  if (!options.yes) {
    if (!interactive()) throw new Error(`A restore discards every change made to ${deployment.workerName} since the backup of ${backup.createdAt}. Without a terminal to confirm that, pass --yes.`)
    const sure = await clack.confirm({ message: `Restore ${deployment.workerName} to its backup of ${backup.createdAt}? Changes since are lost and everyone signs in again.` })
    if (clack.isCancel(sure) || !sure) process.exit(0)
  }
  const client = await resolveCloudflareAuth({ apiToken: options.apiToken })
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z').toLowerCase()
  const spinner = clack.spinner()
  // The databases this run makes, deleted again if the restore stops
  const created: string[] = []
  const restoreInto = async (name: string, dump: DatabaseDump) => {
    const databaseId = (await client.createD1(deployment.accountId, name)).uuid
    created.push(databaseId)
    await loadDatabase({ client, accountId: deployment.accountId, databaseId }, dump)
    return databaseId
  }
  let check: HistoryCheck
  let appDatabaseId: string
  let providerDatabaseId = deployment.providerDatabaseId
  try {
    spinner.start('Importing the app database')
    appDatabaseId = await restoreInto(`${deployment.workerName}-db-${stamp}`, backup.databases.app)
    if (backup.databases.provider && deployment.providerWorkerName) {
      spinner.message('Importing the login provider database')
      providerDatabaseId = await restoreInto(`${deployment.providerWorkerName}-db-${stamp}`, backup.databases.provider)
    }
    spinner.message('Checking the restored history')
    const app = { client, accountId: deployment.accountId, databaseId: appDatabaseId }
    check = await verifyHistory({ query: queryOf(app), betterAuthSecret: deployment.betterAuthSecret, ring, baseKey, witnesses })
    if (check.problems.length > 0) throw new Error(`The restored history does not verify:\n${check.problems.join('\n')}`)
  } catch (error) {
    spinner.stop('Restore stopped')
    for (const databaseId of created) await client.deleteD1(deployment.accountId, databaseId).catch(() => undefined)
    throw new Error(`${error instanceof Error ? error.message : String(error)}\nThe instance keeps its databases, and the restored copies are deleted again.`)
  }
  spinner.stop(`Restored ${check.environments} environment${check.environments === 1 ? '' : 's'}`)
  reportHistoryCheck(check, witnesses.length > 0)
  saveDeployment(key, { ...deployment, databaseId: appDatabaseId, providerDatabaseId })
  // An update of both workers, bound to the restored databases
  await selfHost(options)
  clack.log.info(`The databases from before the restore stay (${deployment.databaseId}${deployment.providerDatabaseId ? `, ${deployment.providerDatabaseId}` : ''}): delete them once you're happy with it.`)
}

// What the check of a restored history covered, and what it can't
function reportHistoryCheck(check: HistoryCheck, witnessed: boolean) {
  const rows = (n: number) => `${n} row${n === 1 ? '' : 's'}`
  clack.log.info(
    `Checked the signed history: ${rows(check.rows)} match their hashes and the Worker's signatures` +
      (check.outside ? `, and ${rows(check.outside)} added around it are ignored` : '') +
      '. Everything else, such as members, tokens and trust rules, is as it was in the backup, unchecked.',
  )
  if (check.unsigned > 0) {
    clack.log.warn(`${check.unsigned} environment${check.unsigned === 1 ? ' has' : 's have'} changes but no signed history, so nothing checked them.`)
  }
  if (!witnessed) {
    clack.log.info('~/.sigillo/audit.json has no `sigillo audit verify` of this instance, so nothing shows whether rows were removed from the end of a chain before the backup.')
  } else if (check.sinceLastCheck.length > 0) {
    clack.log.warn([
      'Compared with what `sigillo audit verify` last saw on this machine:',
      ...check.sinceLastCheck.map((line) => `  ${line}`),
      'Fewer rows are expected from a backup older than that check, and `sigillo audit verify` reports those environments until you remove them from ~/.sigillo/audit.json. A row that differs means this history was rewritten.',
    ].join('\n'))
  } else {
    clack.log.info('It matches what `sigillo audit verify` last saw on this machine.')
  }
}

async function askPassphrase(): Promise<string> {
  const passphrase = await clack.password({ message: 'Passphrase for ~/.sigillo/selfhost.json' })
  if (clack.isCancel(passphrase)) process.exit(0)
  return passphrase
}

// Asked twice. Losing it loses the file, so it belongs in a password manager.
async function askNewPassphrase(): Promise<string> {
  clack.log.info('~/.sigillo/selfhost.json holds the keys to your deployments. Choose a passphrase to encrypt it, and keep it in your password manager.')
  for (;;) {
    const passphrase = await clack.password({ message: 'New passphrase', validate: (value) => passphraseProblem(value ?? '') })
    if (clack.isCancel(passphrase)) process.exit(0)
    const again = await clack.password({ message: 'Repeat it' })
    if (clack.isCancel(again)) process.exit(0)
    if (again === passphrase) return passphrase
    clack.log.warn('The passphrases differ, try again')
  }
}

export interface SelfHostOptions {
  name?: string
  account?: string
  apiToken?: string
  bundle?: string
  releaseUrl?: string
  allowDowngrade?: boolean
  domain?: string
  skipDomain?: boolean
  googleClientId?: string
  googleClientSecret?: string
  allowedUsers?: string
  changePassphrase?: boolean
  resetPasskeys?: string
  rotateKey?: boolean
  backup?: string
  restore?: string
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
  // A published CLI deploys the bundle of its own version, checked against
  // the SHA-256 it was released with
  const expected = readExpectedBundle()
  if (!expected) clack.log.warn('This CLI is a local build with no recorded bundle digest: the bundle is not checked')
  spinner.start(options.bundle ? 'Loading local bundle' : expected ? `Downloading Sigillo v${expected.version}` : 'Downloading latest Sigillo release')
  const bundle: SelfhostBundle = await loadBundle({ bundlePath: options.bundle, url: options.releaseUrl, expected })
  if (saved?.deployedVersion && isOlderVersion(bundle.version, saved.deployedVersion) && !options.allowDowngrade) {
    spinner.stop(`Release v${bundle.version}`)
    throw new Error(`This instance runs v${saved.deployedVersion}, newer than v${bundle.version}: update the CLI (npx @kldzj/sigillo@latest self-host), or pass --allow-downgrade`)
  }
  spinner.stop(
    saved?.deployedVersion === bundle.version
      ? `Release v${bundle.version} (already deployed — re-syncing)`
      : `Release v${bundle.version}${saved?.deployedVersion ? ` (updating from v${saved.deployedVersion})` : ''}`,
  )

  // Validate before touching anything: a bad SIGILLO_ENCRYPTION_KEY must fail early.
  const { generated, ...secrets } = resolveDeploySecrets({ workerExists, saved, encryptionKeyEnv: process.env.SIGILLO_ENCRYPTION_KEY })
  // Who may sign in: the flag wins, then the saved list; a new deployment asks
  const allowedUsers = normalizeAllowedUsers(
    options.allowedUsers ?? saved?.allowedUsers ?? (workerExists ? '' : await askAllowedUsers(options)),
  )

  // ── workers.dev subdomain ─────────────────────────────────────────
  // Resolved before any upload: both workers are told the provider's URL.
  const subdomain = await ensureWorkersDevSubdomain({ client, accountId, workerName, options })
  const workersDevUrl = `https://${workerName}.${subdomain}.workers.dev`

  // ── Custom domain ─────────────────────────────────────────────────
  // Chosen before any upload, since the provider is told the app's URL, and
  // attached once the app worker exists
  const domain = await chooseDomain({ client, accountId, options, saved })
  const appUrl = domain ? `https://${domain.hostname}` : workersDevUrl

  // ── D1 + migrations ───────────────────────────────────────────────
  spinner.start('Provisioning D1 database')
  const firstMigrationName = Object.keys(bundle.app.migrations).sort()[0]
  const databaseId =
    saved?.databaseId ??
    (await ensureDatabase({ client, accountId, name: `${workerName}-db`, firstMigrationName }))
  if (generated) await assertNoStoredSecrets({ client, accountId, databaseId })
  // A new worker gets its keys from scratch: they must decrypt what's stored
  if (secrets.betterAuthSecret) {
    await assertSecretsDecryptDatabase({ client, accountId, databaseId, betterAuthSecret: secrets.betterAuthSecret, encryptionKey: secrets.encryptionKey, encryptionKeys: saved?.encryptionKeys })
  }
  const applied = await applyMigrations({ client, accountId, databaseId, migrations: bundle.app.migrations })
  spinner.stop(
    applied.length > 0
      ? `D1 ready — applied ${applied.length} migration${applied.length > 1 ? 's' : ''}`
      : 'D1 ready — no new migrations',
  )

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
    : await deployProvider({ client, accountId, bundle, options, saved, spinner, workerName: providerWorkerName, url: ownProviderUrl, appUrl, allowedUsers })
  if (!provider) {
    clack.log.warn(`This deployment signs in through ${currentProviderUrl} — keeping it, since a new provider would change every user's login`)
  }
  const providerUrl = provider ? ownProviderUrl : currentProviderUrl!

  // ── Save state before the app upload so re-runs resume cleanly ────
  const deployment: DeploymentState = {
    accountId,
    workerName,
    databaseId,
    betterAuthSecret: secrets.betterAuthSecret ?? saved?.betterAuthSecret,
    encryptionKey: secrets.encryptionKey ?? saved?.encryptionKey,
    encryptionKeys: saved?.encryptionKeys,
    ...provider,
    // Recorded once both workers have the new list, so a failed run retries
    allowedUsers: saved?.allowedUsers,
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
    secrets: secrets.betterAuthSecret
      ? {
          BETTER_AUTH_SECRET: secrets.betterAuthSecret,
          ...(secrets.encryptionKey ? { ENCRYPTION_KEY: secrets.encryptionKey } : {}),
          // A recreated Worker gets back the key ring of its last rotation
          ...(saved?.encryptionKeys ? { ENCRYPTION_KEYS: JSON.stringify(saved.encryptionKeys) } : {}),
          ...(allowedUsers ? { ALLOWED_USERS: allowedUsers } : {}),
        }
      : undefined,
    compatibilityFlags: appCompatibilityFlags(bundle.app.compatibilityFlags),
  })
  if (!secrets.betterAuthSecret) {
    await updateAllowedUsersSecret({ client, accountId, scriptName: workerName, list: allowedUsers, saved: saved?.allowedUsers })
  }
  await client.enableWorkersDev(accountId, workerName)
  spinner.stop('Worker deployed')

  deployment.deployedVersion = bundle.version
  deployment.allowedUsers = allowedUsers
  writeState({ ...readState(), deployments: { ...readState().deployments, [stateKey]: deployment } })

  spinner.start('Waiting for the deployment to become healthy')
  const healthy = await waitForHealth(workersDevUrl)
  spinner.stop(healthy ? 'Deployment is live' : 'Deployment uploaded (health check still propagating)')

  if (domain?.zoneId) {
    await client.attachCustomDomain(accountId, { zoneId: domain.zoneId, hostname: domain.hostname, service: workerName })
    clack.log.success(`Custom domain attached: ${appUrl}`)
  }
  if (domain) {
    deployment.customDomain = domain.hostname
    writeState({ ...readState(), deployments: { ...readState().deployments, [stateKey]: deployment } })
  }

  clack.note(
    [
      `${colors.bold('URL:')}        ${appUrl}`,
      ...(domain ? [`${colors.bold('Fallback:')}   ${workersDevUrl}`] : []),
      `${colors.bold('Version:')}    v${bundle.version}`,
      '',
      `${colors.bold('Login:')}      ${providerUrl} (Google)`,
      `${colors.bold('Sign-in:')}    ${allowedUsers ? allowedUsers.split(',').join(', ') : 'anyone with a Google account'}`,
      `Point the CLI at your instance:  sigillo login --api-url ${appUrl}`,
      '',
      'Re-run `npx @kldzj/sigillo self-host` anytime to deploy updates.',
    ].join('\n'),
    'Sigillo is self-hosted 🎉',
  )
  if (!allowedUsers) {
    clack.log.warn('Anyone with a Google account can sign in. Limit it: npx @kldzj/sigillo self-host --allowed-users acme.com')
  }
  // A dashboard page often takes more CPU than the free plan allows per request
  if (!workerExists) {
    clack.log.info("On Cloudflare's free plan, a dashboard page fails now and then with error 1102 (Worker exceeded resource limits); Workers Paid, $5 a month, avoids that. See https://sigillo.kldzj.dev/docs/self-hosting#the-free-plan")
  }
  clack.outro('Done')
}

async function askAllowedUsers(options: SelfHostOptions): Promise<string> {
  if (!interactive() || options.yes) return ''
  const input = await clack.text({
    message: 'Who may sign in? Email addresses and domains, comma-separated',
    placeholder: 'acme.com, ops@partner.io (empty: anyone with a Google account)',
    validate: (value) => {
      try {
        normalizeAllowedUsers(value ?? '')
      } catch (error) {
        return error instanceof Error ? error.message : String(error)
      }
    },
  })
  if (clack.isCancel(input)) process.exit(0)
  return String(input)
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
async function deployProvider({ client, accountId, bundle, options, saved, spinner, workerName, url, appUrl, allowedUsers }: {
  client: CfClient
  accountId: string
  bundle: SelfhostBundle
  options: SelfHostOptions
  saved?: DeploymentState
  spinner: ReturnType<typeof clack.spinner>
  workerName: string
  url: string
  /** where the provider's error page sends people back to sign in */
  appUrl: string
  /** the app's ALLOWED_USERS, applied by the provider too */
  allowedUsers: string
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

  const secrets = providerSecretsForDeploy({ providerExists, saved, google })
  if (secrets && allowedUsers) secrets.ALLOWED_USERS = allowedUsers

  spinner.start('Deploying the login provider')
  const databaseId =
    saved?.providerDatabaseId ??
    (await ensureDatabase({
      client,
      accountId,
      name: `${workerName}-db`,
      firstMigrationName: Object.keys(bundle.provider.migrations).sort()[0],
    }))
  // A new provider secret must not meet signing keys encrypted with a lost one
  if (secrets && !saved?.providerAuthSecret) await assertNoStoredSecrets({ client, accountId, databaseId, dataTable: 'jwks' })
  await applyMigrations({ client, accountId, databaseId, migrations: bundle.provider.migrations })
  const assetsJwt = await syncAssets({ client, accountId, scriptName: workerName, worker: bundle.provider })
  await uploadWorker(client, {
    accountId,
    scriptName: workerName,
    worker: bundle.provider,
    databaseId,
    assetsJwt,
    vars: { BETTER_AUTH_URL: url, APP_URL: appUrl },
    secrets,
  })
  if (!secrets) {
    await updateAllowedUsersSecret({ client, accountId, scriptName: workerName, list: allowedUsers, saved: saved?.allowedUsers })
  }
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

// The app's custom domain: the flag, the saved one, or asked for when there
// is none yet. zoneId is set when it still has to be attached.
async function chooseDomain(args: {
  client: CfClient
  accountId: string
  options: SelfHostOptions
  saved?: DeploymentState
}): Promise<{ hostname: string; zoneId?: string } | undefined> {
  const { client, accountId, options, saved } = args
  const savedDomain = saved?.customDomain ? { hostname: saved.customDomain } : undefined
  if (options.skipDomain) return savedDomain
  const hostname = options.domain

  if (!hostname) {
    if (saved?.customDomain || options.yes || !interactive()) return savedDomain
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
    return { hostname: String(input).trim(), zoneId: zone.id }
  }

  // --domain flag: find the matching zone by suffix
  const zones = await client.listZones(accountId)
  const zone = zones
    .filter((z) => hostname === z.name || hostname.endsWith(`.${z.name}`))
    .sort((a, b) => b.name.length - a.name.length)[0]
  if (!zone) {
    throw new Error(`No zone on account matches ${hostname} — add the domain to Cloudflare first`)
  }
  return { hostname, zoneId: zone.id }
}

cli.command('version-info', 'Show the release this CLI deploys, and the latest one').action(async () => {
  const expected = readExpectedBundle()
  const info = await fetchReleaseInfo()
  console.log(`deploys: ${expected ? `v${expected.version} (sha256 ${expected.sha256})` : 'the latest release, unchecked (a local build)'}`)
  console.log(`latest: v${info.version}`)
  console.log(`bundle: ${info.url}`)
})

cli.help()

/** Entry from bin.ts: strips the `self-host` argv token and runs the goke CLI. */
export async function run(): Promise<void> {
  await cli.parse([process.argv[0]!, process.argv[1]!, ...process.argv.slice(3)])
}
