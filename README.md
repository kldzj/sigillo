<div align='center' class='hidden'>
    <br/>
    <br/>
    <h3>sigillo</h3>
    <p>Self-hostable secrets manager for humans & agents</p>
    <br/>
    <br/>
</div>

Sigillo replaces `.env` files with a **secrets manager you self-host** on Cloudflare. Prefix your commands with `sigillo run` and secrets are injected as environment variables, never written to disk.

> **This is [kldzj/sigillo](https://github.com/kldzj/sigillo)**, a fork of [remorses/sigillo](https://github.com/remorses/sigillo) that keeps building on it for teams who want tighter control over their secrets, with features such as passkey approval for production, a signed history of every change and read, and machine tokens for CI. Some of them are opinionated in ways upstream may not want, so they live here, while fixes that suit both go upstream as pull requests. The [releases](https://github.com/kldzj/sigillo/releases) list everything the fork adds. There is no hosted service: every instance runs on your own Cloudflare account with its own Google login. The CLI is published as [`@kldzj/sigillo`](https://www.npmjs.com/package/@kldzj/sigillo), and the docs are at [sigillo.kldzj.dev](https://sigillo.kldzj.dev).

```bash
# instead of this
source .env && next dev

# do this
sigillo run -- next dev
```

```diagram
                                                 ┌────────────────┐
  sigillo run -- next dev                        │   App Worker   │
         │                                       │ (your account) │
         │  1. fetch secrets                     │                │
         │──────────────────────────────────────▶│  decrypt       │
         │  { DB_URL, API_KEY, ... }             │  AES-256-GCM   │
         │◀──────────────────────────────────────│                │
         │                                       └────────────────┘
         │  2. spawn child with env vars
         │
         ▼
  ┌──────────────┐
  │  next dev    │
  │  (child)     │
  └──────┬───────┘
         │
         │  3. stdout / stderr
         ▼
  ┌───────────────┐
  │   redaction   │  high-entropy values replaced with *
  │    filter     │  secrets never reach your terminal
  └──────┬────────┘
         │
         ▼
     terminal
    (safe output)
```

Secrets are **automatically redacted** from process output, so API keys, tokens and passwords don't leak into agent context windows, CI logs, or terminal history. Redaction covers values that look random, 16 characters or longer; see **Output redaction** below.

**Open-source alternative** to [Doppler](https://doppler.com) and [Infisical](https://infisical.com).

## Why Sigillo?

### Why not Doppler or Infisical?

- **Self-hosted**: runs on your own Cloudflare account. No centralized point of failure, no vendor lock-in. Your secrets never leave infrastructure you control.
- **Free**: no per-seat pricing, no usage limits. Deploy it once, use it forever.
- **Open source**: MIT licensed. Read the code, audit it, extend it.

### Why teams need this

- **No more `.env` files**: secrets live in the cloud and are easy to share across machines. No more "can you send me the .env?" on Slack.
- **Single source of truth**: stop duplicating secrets across platforms. In CI, you only need the Sigillo token. Use built-in scripts to sync secrets to Cloudflare, Vercel, Docker, and more.
- **Collaborative secrets**: share secrets between team members through organizations with role-based access, instead of brittle `.env` files or pasting keys in DMs.
- **Multi-environment management**: manage dev, preview, and prod secrets in one place. Switch between environments with `-c prod`.

### Why agents need this

- **Don't let agents read your secrets**: agents should never see your raw secret values. Instead of giving agents access to `.env` files, use `sigillo run` to inject secrets into processes without exposing them.
- **Automatic output redaction**: `sigillo run` replaces secret values that look random in stdout/stderr with `*`, so keys and tokens stay out of your chat context window. Even if an agent runs `printenv`, it won't see them in the output.

## Install skill for AI agents

```bash
npx -y skills add kldzj/sigillo
```

This installs [skills](https://skills.sh) for AI coding agents like Claude Code, Cursor, Windsurf, and others.

## Install

**curl** (downloads the native binary to `~/.sigillo/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/kldzj/sigillo/main/app/public/install.sh | bash
```

**npm**:

```bash
npm i -g @kldzj/sigillo
```

**Run without installing** via npx or bunx:

```bash
npx @kldzj/sigillo run -- next dev
bunx @kldzj/sigillo run -- next dev
```

## Quick start

**1. Deploy your instance** to your Cloudflare account (see [Self-hosting](#self-hosting)):

```bash
npx @kldzj/sigillo self-host
```

**2. Add your secrets** in your instance's web UI. Create a project, add environments, and paste in your secrets.

**3. Login from the terminal** (opens a browser for device flow authentication: type the code the terminal shows, then approve; once you have a passkey, approving takes it):

```bash
sigillo login --api-url https://sigillo.<your-subdomain>.workers.dev
```

**4. Link your project** (picks the default project and environment for this directory):

```bash
sigillo setup
```

This saves the project and environment for the current directory in `~/.sigillo/config.json` (not in the repo). Run it in the project root if you have a single project, or in each subfolder of a monorepo. Since the config is local to your machine, you need to run `sigillo setup` again after cloning the repo on a new machine. Alternatively, skip setup entirely and always pass `--project` and `--env` (or `-c`) flags.

**5. Run your app** with secrets injected as environment variables:

```bash
sigillo run -- next dev
```

That's it. No `.env` files, no copy-pasting keys. Go back to your instance any time to add, edit, or rotate secrets. The next `sigillo run` picks them up automatically.

Migrating from Doppler? See the [Doppler migration guide](https://sigillo.kldzj.dev/docs/doppler-migration).

## Setting up a new project

The Quick Start above assumes you already have a project with secrets. This section walks through creating everything from scratch, either from the CLI or your instance's dashboard.

Sigillo organizes secrets into a simple hierarchy:

```diagram
Organization (my-company)
│
├── Project (api)
│   ├── dev
│   │   ├── DATABASE_URL = postgres://localhost/mydb
│   │   ├── API_KEY = sk-dev-xxx
│   │   └── AUTH_SECRET = random-dev-key
│   ├── preview
│   │   ├── DATABASE_URL = postgres://preview-host/mydb
│   │   └── API_KEY = sk-preview-xxx
│   └── prod
│       ├── DATABASE_URL = postgres://prod-host/mydb
│       └── API_KEY = sk-live-xxx
│
└── Project (web)
    ├── dev
    │   └── NEXT_PUBLIC_API_URL = http://localhost:3001
    └── prod
        └── NEXT_PUBLIC_API_URL = https://api.example.com
```

Each **organization** contains multiple **projects**. Each project has **environments** (dev, preview, prod by default). Secrets are scoped to a single environment.

### Create an organization

Organizations group projects and team members together. You need one before creating any project.

**CLI:**

```bash
sigillo orgs create --name my-company
```

**Dashboard:** Open your instance and click "Create Organization" from the sidebar.

### Create a project

A project holds secrets for one app or service. Creating a project automatically gives you three environments: **dev**, **preview**, and **prod**.

```bash
sigillo orgs   # find your org ID
sigillo projects create --org <ORG_ID> --name my-app
```

**Dashboard:** Open your org, click "New Project", and give it a name. The three default environments are created for you.

### Link a directory

`sigillo setup` saves the **default project and environment** for the current directory. This is a local-only setting stored in `~/.sigillo/config.json`, not in the repository. After setup, every `sigillo run` in that directory (or any subdirectory) resolves the right secrets without extra flags.

Run it in the **project root** for single-project repos, or in **each subfolder** of a monorepo:

```bash
# single project
cd my-app
sigillo setup --project <PROJECT_ID> --env dev

# monorepo
cd monorepo/api     && sigillo setup --project api_xxx --env dev
cd monorepo/web     && sigillo setup --project web_xxx --env dev
```

Since the config lives on your machine (not in the repo), you need to re-run `sigillo setup` after cloning on a new machine. If you prefer not to run setup at all, you can always pass `--project` and `--env` explicitly:

```bash
sigillo run --project <PROJECT_ID> -c dev -- next dev
```

Without flags, `sigillo setup` shows an interactive picker. Use `--project` and `--env` for non-interactive/CI workflows.

### Add secrets

Add the secrets your app needs. You can set real values now, or leave them empty and fill them in later from the dashboard.

```bash
sigillo secrets set DATABASE_URL "postgres://localhost:5432/mydb" -c dev
sigillo secrets set API_KEY "" -c dev
sigillo secrets set AUTH_SECRET "" -c dev
```

Repeat for other environments:

```bash
sigillo secrets set DATABASE_URL "" -c preview
sigillo secrets set DATABASE_URL "" -c prod
```

For encryption keys or auth secrets, generate a real random value right away:

```bash
sigillo secrets set AUTH_SECRET "$(openssl rand -base64 32)" -c dev
sigillo secrets set AUTH_SECRET "$(openssl rand -base64 32)" -c preview
sigillo secrets set AUTH_SECRET "$(openssl rand -base64 32)" -c prod
```

**Dashboard:** Open your project at `<your-instance>/dash/projects/<PROJECT_ID>/envs/dev` to add or edit secrets from the web UI. You can toggle between environments using the tabs.

### Verify and run

```bash
sigillo secrets -c dev   # list secret names (values hidden)
sigillo run -c dev -- pnpm dev
```

## Features

| Feature | Description |
|---|---|
| **Secret injection** | `sigillo run -- <cmd>` injects secrets as env vars, no files on disk |
| **Output redaction** | High-entropy values automatically replaced with `*` in stdout/stderr |
| **File mount** | `--mount .env` writes secrets to the given file path, deletes it after the process exits |
| **Organizations** | Multi-tenant orgs with admin/member roles and invite links |
| **Projects & environments** | Organize secrets into projects with dev, preview and prod environments |
| **Audit log** | Every secret change, and in protected environments every read of a value, is recorded in hash chains your instance signs; `sigillo audit verify` checks them |
| **Passkeys for production** | Reading or changing a protected environment takes a passkey: in the browser on the spot, for the CLI on an approval page. So do admin actions in an org that has one. A stolen session or CLI login alone can't read or change it |
| **API tokens** | Scoped to a project and optionally some of its environments, expire after 7 to 365 days, last use and IP shown, SHA-256 hashed, shown once. Machine tokens read and change protected environments, for CI |
| **Sign-in allowlist** | Only the email addresses and domains you list can sign up or sign in |
| **Sessions** | See and end every browser and CLI login signed in as you |
| **Device flow** | RFC 8628 login for CLI and agents, no copy-pasting tokens |
| **AES-256-GCM encryption** | Every secret encrypted at rest with a random 12-byte IV |
| **Download formats** | Export as `json`, `env`, `env-no-quotes`, `yaml`, `docker`, `dotnet-json`, `xargs` |
| **Web UI** | Full management dashboard; a value loads only when you reveal it |
| **Self-hostable** | Runs on Cloudflare Workers + D1, deploy your own instance |
| **REST API** | OpenAPI-documented API for building custom integrations |

## CLI reference

### `sigillo login`

Authenticate via device flow or bearer token.

```bash
sigillo login --api-url https://my-instance.dev            # interactive device flow
sigillo login --token sig_xxx                              # save existing API token
sigillo login --api-url https://my-instance.dev --scope .  # scoped to current dir
```

`sigillo login` always starts a new login, also when one is saved, so run it again when the CLI says `not signed in, or the session expired`.

### `sigillo setup`

Save the default project and environment for the current directory. This is stored locally in `~/.sigillo/config.json`, not in the repo, so it needs to be done on each machine after cloning. Run it in the project root, or in each subfolder of a monorepo. You can skip setup entirely by always passing `--project` and `--env` flags to other commands.

```bash
sigillo setup                                    # interactive project/env picker
sigillo setup --project proj_abc --env dev        # non-interactive
```

### `sigillo run`

Execute a command with secrets injected as environment variables.

```bash
sigillo run -- next dev                                          # inject secrets from the configured env
sigillo run -c dev -- next dev                                   # use the dev environment
sigillo run -c preview -- next dev                               # use the preview environment
sigillo run -c prod -- next build                          # use the prod environment
sigillo run -- printenv                                          # verify which vars are injected (values redacted)
sigillo run --command 'echo $MY_SECRET'                          # shell string mode
sigillo run --mount .env -- npm start                            # write to file, clean up after
sigillo run --mount config.json --mount-format json -- next dev  # mount as JSON
sigillo run --disable-redaction -- ./my-script.sh                # opt out of output redaction
sigillo run --allow-env NODE_OPTIONS -- next build               # let a secret set NODE_OPTIONS
```

Use **`--command`** when you need shell features like `&&`, pipes, redirects, or `$VARIABLE` expansion. Wrap the command in single quotes so your parent shell does not expand secret variables before Sigillo injects them.

A secret named like a variable that decides which programs run and what they load, such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD`, `GIT_PAGER` or `npm_config_registry`, is skipped with a warning: anyone who can change the environment's secrets would otherwise run code on your machine. Pass **`--allow-env NAME`** to use one. Names match in any case, as they do on Windows. The list is best effort: no list of such names is complete, so a secret can still change how a program runs through a variable it doesn't know.

```bash
# Wrong: your shell expands $DATABASE_URL before sigillo starts
sigillo run --command "psql $DATABASE_URL -c 'select 1'"

# Right: $DATABASE_URL expands inside sigillo's child shell
sigillo run --command 'psql $DATABASE_URL -c "select 1"'
```

Put **non-secret env vars before** `sigillo run`, especially in package scripts. This keeps regular build flags visible while secrets still come from Sigillo.

```json
{
  "scripts": {
    "deployment": "CLOUDFLARE_ENV=preview sigillo run -c preview --command 'vite build && wrangler deploy --env preview'"
  }
}
```

**Output redaction** is enabled by default. Secret values with high entropy (>=3.5 Shannon bits, >=16 chars) are replaced with `*` in stdout/stderr. This keeps them out of agent context windows and CI logs. Shorter or more predictable values, like a port, a hostname or a word, print as they are.

### Local package binaries

When you run `sigillo run` through a package manager script (`pnpm run`, `bun run`, `npm run`), the package manager adds `node_modules/.bin` to `PATH` before Sigillo starts. Sigillo inherits that `PATH` and passes it to the child process, so local binaries like `vite`, `tsc`, `wrangler` are all available without prefixing with `pnpm exec` or `npx`.

```bash
# in package.json scripts, local bins just work:
sigillo run -- vite build          # vite found via node_modules/.bin
sigillo run -- wrangler deploy     # wrangler found via node_modules/.bin
sigillo run -- tsc --noEmit        # tsc found via node_modules/.bin

# same with --command:
sigillo run --command 'vite build && wrangler deploy'
```

This also works when running `sigillo run` directly with `pnpm exec` or `bunx`:

```bash
pnpm exec sigillo run -- vite dev
bunx @kldzj/sigillo run -- next build
```

If you installed Sigillo globally (via `curl` or `npm i -g`), running `sigillo run` outside a package manager script means `node_modules/.bin` is **not** in `PATH`. In that case, use the full path or prefix with `npx`/`pnpm exec` inside the child command, or run Sigillo from a package script instead.

### `sigillo secrets`

Manage individual secrets.

```bash
sigillo secrets                           # list secret names
sigillo secrets get DATABASE_URL          # get a single value
sigillo secrets get DATABASE_URL --force  # allow value output inside agent shells
sigillo secrets set API_KEY sk-live-xxx   # set a value
echo "multiline\nvalue" | sigillo secrets set CERT  # set from stdin
sigillo secrets delete OLD_KEY            # delete
sigillo secrets download                  # download all (YAML)
sigillo secrets download --format json    # download as JSON
sigillo secrets download --format env     # download as .env
```

Inside AI agent shells, `secrets get` and `secrets download` refuse to print raw values to a terminal unless you pass `--force`. Prefer `sigillo run` or a direct pipe so secret values go straight to the tool that needs them, not into the chat context.

```bash
sigillo run --command 'psql "$DATABASE_URL" -c "select 1"'
sigillo secrets download --format env | fly secrets import --app my-app
```

### `sigillo projects`

```bash
sigillo projects                                    # list all projects
sigillo projects create --org org_abc --name my-app # create project
sigillo projects get proj_abc                       # show project details
sigillo projects update proj_abc --name new-name    # rename
sigillo projects delete proj_abc                    # delete
```

### `sigillo environments`

```bash
sigillo environments                                                         # list environments
sigillo environments create --project proj_abc --name Staging --slug staging  # create
sigillo environments rename env_abc --name Production --slug prod             # rename
sigillo environments delete env_abc                                          # delete
```

### `sigillo audit verify`

Check an environment's secret changes and reads against their signed hash chains. Org admins, signed in with `sigillo login` (API tokens are refused). The newest row of each chain is kept in `~/.sigillo/audit.json`, so the next check also notices rows removed or rewritten since.

```bash
sigillo audit verify -c prod
```

### Protected environments

Reading or changing a protected environment takes your passkey. Any command that reads or changes values asks for an approval and waits for it:

```
$ sigillo run -c prod -- ./deploy.sh
This environment is protected: approve with your passkey.
  Open https://secrets.acme.com/approve and enter BCDF-GHJK
Waiting for your approval...
✔ Approved for 15 minutes
```

Open the page, type the code, and approve with your passkey. The approval covers this login for 15 minutes, so running the command again in that time doesn't ask. Add passkeys under **user menu → Passkeys** in the web UI. API tokens get `only a machine token can use it`: see [CI / GitHub Actions](#ci--github-actions).

### Global flags

Most commands that resolve auth, project, or environment from config accept these overrides:

| Flag | Env var | Description |
|---|---|---|
| `--token <sig_xxx>` | `SIGILLO_TOKEN` | Bearer token for auth |
| | `SIGILLO_OIDC_TOKEN_FILE`, `SIGILLO_OIDC_TOKEN` | Without a token: a workload's JWT to exchange for one ([workload identity](https://sigillo.kldzj.dev/docs/workload-identity)) |
| `--api-url <url>` | `SIGILLO_API_URL` | Your Sigillo instance (no default; saved by `sigillo login --api-url`) |
| `--env <slug>` / `--config <slug>` / `-c <slug>` | `SIGILLO_ENVIRONMENT` | Environment slug (e.g. `dev`, `prod`) |
| `--project <id>` / `-p <id>` | `SIGILLO_PROJECT` | Project ID or name override |

### Download formats

| Format | Flag | Use case |
|---|---|---|
| `json` | `--format json` | Application config files |
| `env` | `--format env` | Shell scripts with quotes |
| `env-no-quotes` | `--format env-no-quotes` | Shell scripts without quotes |
| `yaml` | `--format yaml` | Default CLI output |
| `docker` | `--format docker` | Docker `--env-file` |
| `dotnet-json` | `--format dotnet-json` | .NET `appsettings.json` (uses `__` for nested keys) |
| `xargs` | `--format xargs` | NUL-delimited pairs for shell pipelines |

## Integrations

### Cloudflare Workers

Upload secrets to a Cloudflare Worker using `wrangler secret bulk`:

```bash
sigillo secrets download -c prod --format env |
  wrangler secret bulk --env=""
```

The pipe sends the complete Sigillo environment directly to Wrangler. Secret
values never appear in the terminal and no `.env` file remains on disk. Use an
explicit empty environment for the top-level production Worker; Wrangler warns
when a configuration has named environments but the target is ambiguous.

Add these as `package.json` scripts so you can sync before each deploy:

```json
{
  "scripts": {
    "secrets:preview": "sigillo secrets download -c preview --format env | wrangler secret bulk --env preview",
    "secrets:production": "sigillo secrets download -c prod --format env | wrangler secret bulk --env=\"\""
  }
}
```

This intentionally syncs the entire selected environment. Keep `dev`,
`preview`, and `prod` values separate in Sigillo, then use the matching
Wrangler environment at deployment time.

### Vercel

`vercel env add` only accepts one variable at a time. Use the `xargs` format to pipe them:

```bash
sigillo secrets download -c prod --format xargs | \
  xargs -0 -n2 sh -c 'printf %s "$2" | vercel env add "$1" production --force' sh
```

Add `--sensitive` to mark values as sensitive in Vercel:

```bash
sigillo secrets download -c prod --format xargs | \
  xargs -0 -n2 sh -c 'printf %s "$2" | vercel env add "$1" production --sensitive --force' sh
```

As a `package.json` script:

```json
{
  "scripts": {
    "secrets:vercel": "sigillo secrets download -c prod --format xargs | xargs -0 -n2 sh -c 'printf %s \"$2\" | vercel env add \"$1\" production --sensitive --force' sh"
  }
}
```

### Fly.io

`fly secrets import` reads `NAME=VALUE` pairs from stdin. Pipe `sigillo secrets download` directly, no temp file needed:

```bash
sigillo secrets download -c prod --format env | fly secrets import --app my-app
```

By default `fly secrets import` triggers a machine restart once secrets are staged. Use `--stage` to skip the restart and deploy separately:

```bash
# stage without restarting
sigillo secrets download -c prod --format env | fly secrets import --app my-app --stage
# then deploy when ready
fly deploy --app my-app
```

Add as `package.json` scripts:

```json
{
  "scripts": {
    "secrets:fly:production": "sigillo secrets download -c prod --format env | fly secrets import --app my-app",
    "secrets:fly:preview": "sigillo secrets download -c preview --format env | fly secrets import --app my-app-staging"
  }
}
```

### Docker

Mount secrets as a Docker env file:

```bash
sigillo secrets download --format docker > .env.docker
docker run --env-file .env.docker my-image
```

Or inject at build time:

```bash
sigillo run -- docker compose up
```

### CI / GitHub Actions

With [workload identity](https://sigillo.kldzj.dev/docs/workload-identity), a job stores no token: an org admin adds a trust rule for the repository and its GitHub environment on the project's **Tokens** tab, and the job gets `id-token: write`. With no `SIGILLO_TOKEN` set, the CLI asks GitHub for a JWT and exchanges it for a token of one hour. Kubernetes pods do the same with a projected service account token in `SIGILLO_OIDC_TOKEN_FILE`, and External Secrets Operator through its Doppler provider.

```yaml
permissions:
  id-token: write
steps:
  - run: npx @kldzj/sigillo run -- ./deploy.sh
    env:
      SIGILLO_API_URL: ${{ vars.SIGILLO_API_URL }}
      SIGILLO_PROJECT: ${{ vars.SIGILLO_PROJECT }}   # the project's ID
      SIGILLO_ENVIRONMENT: prod
```

Otherwise, use an API token for non-interactive environments. Create it on the project's **Tokens** tab; it expires after the 7 to 365 days you choose, and an expired one gets `401 API token expired`. To read or change a protected environment, an org admin checks **Machine token** when creating it: that takes their passkey, and the token expires after 90 days at most.

```yaml
- name: Run with secrets
  env:
    SIGILLO_API_URL: ${{ vars.SIGILLO_API_URL }}
    SIGILLO_TOKEN: ${{ secrets.SIGILLO_TOKEN }}
    SIGILLO_PROJECT: ${{ vars.SIGILLO_PROJECT }}
    SIGILLO_ENVIRONMENT: ${{ vars.SIGILLO_ENVIRONMENT }}
  run: |
    npx @kldzj/sigillo run -- next build
```

### .NET

Download secrets as a hierarchical JSON file (keys with `__` become nested objects):

```bash
sigillo secrets download --format dotnet-json > appsettings.Secrets.json
```

`DB__HOST=localhost` becomes `{ "Db": { "Host": "localhost" } }`.

## Self-hosting

Sigillo runs on **Cloudflare Workers + D1**. Every instance is two Workers on your own account: the **App Worker** with your secrets, and its own **Provider Worker** for Google sign-in. Nothing depends on anyone else's servers.

```diagram
Your Cloudflare account
┌──────────────────────┐             ┌──────────────────────┐
│   App Worker         │   OAuth     │  Provider Worker     │
│   (your secrets)     │────────────▶│  (your login)        │
│                      │    PKCE     │                      │
│   <name>             │◀────────────│   <name>-auth        │──▶ Google
└──────────────────────┘             └──────────────────────┘
```

### One command deploy

The fastest way to self-host — no git clone, no build step:

```bash
npx @kldzj/sigillo self-host
```

It logs into Cloudflare (reusing your `wrangler login` when present, or an OAuth browser flow, or a pre-filled API token link that works over SSH), deploys both Workers with their D1 databases, applies migrations, and prints your instance URL. A new deployment needs a **Google OAuth client** for its login provider: the command prints the redirect URI to register at [Google Cloud credentials](https://console.cloud.google.com/apis/credentials) and asks for the client ID and secret. It also asks who may sign in (`--allowed-users`), and for a passphrase that encrypts `~/.sigillo/selfhost.json`, the file with your deployment's keys. **Re-run the same command anytime to update** — only new migrations are applied and no secret is ever rotated.

`self-host --backup` saves both databases in a file encrypted with [age](https://age-encryption.org), and `self-host --restore <file>` brings them back into new databases once their history verifies.

See [Self-hosting](https://sigillo.kldzj.dev/docs/self-hosting) for every option and [Hardening](https://sigillo.kldzj.dev/docs/hardening) for securing your instance.

```bash
# non-interactive (CI/agents)
CLOUDFLARE_API_TOKEN=xxx SIGILLO_SELFHOST_PASSPHRASE=xxx npx @kldzj/sigillo self-host --yes \
  --google-client-id xxx.apps.googleusercontent.com --google-client-secret xxx \
  --allowed-users acme.com

# custom worker name and domain
npx @kldzj/sigillo self-host --name sigillo --domain secrets.acme.com
```

### Deploy from source

1. Clone the repo and install dependencies:

```bash
git clone https://github.com/kldzj/sigillo.git
cd sigillo && pnpm install
```

2. Create `provider/.dev.vars` (requires a Google OAuth client with `<provider-url>/api/auth/callback/google` as redirect URI):

```
BETTER_AUTH_SECRET=<any random string>
GOOGLE_CLIENT_ID=<your Google OAuth client ID>
GOOGLE_CLIENT_SECRET=<your Google OAuth client secret>
```

3. Create `app/.dev.vars`:

```
BETTER_AUTH_SECRET=<any random string>
ENCRYPTION_KEY=<output of: openssl rand -base64 32>
```

To limit who can sign in, set the same `ALLOWED_USERS=acme.com,ops@partner.io` in both files, and as a secret on both Workers when you deploy.

4. Run both locally:

```bash
pnpm --dir provider dev
pnpm --dir app dev
```

5. To deploy, add an environment for your account to `provider/wrangler.jsonc` and `app/wrangler.jsonc` (your D1 databases, `BETTER_AUTH_URL` for the provider and `PROVIDER_URL` for the app, plus the `global_fetch_strictly_public` compatibility flag on the app when both Workers share a workers.dev subdomain), then deploy the provider first and the app second.

The app registers itself with its provider on first request via [RFC 7591](https://tools.ietf.org/html/rfc7591) dynamic client registration.

## How it works

<details>
<summary><b>Architecture</b></summary>

Sigillo is two Cloudflare Workers in a monorepo, each backed by a D1 (SQLite) database:

```diagram
┌─────────────────────────────────────────────────────────────────┐
│                         Your Machine                            │
│                                                                 │
│  sigillo run -- next dev                                        │
│       │                                                         │
│       │  device flow login (RFC 8628)                           │
│       │  or bearer token                                        │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │ Sigillo  │                                                   │
│  │   CLI    │                                                   │
│  └────┬─────┘                                                   │
│       │                                                         │
└───────┼─────────────────────────────────────────────────────────┘
        │ REST API
        ▼
┌──────────────────────┐         ┌──────────────────────┐
│   App Worker         │         │  Provider Worker     │
│   (self-hosted)      │────────▶│  (self-hosted)       │
│                      │  OAuth  │                      │
│  • Secrets CRUD      │  PKCE   │  • Google login      │
│  • AES-256-GCM       │         │  • OAuth2 / OIDC     │
│  • Audit log         │◀────────│  • Dynamic client    │
│  • API tokens        │  token  │    registration      │
│  • Device flow       │         │                      │
│  ┌────────────┐      │         │  ┌────────────┐      │
│  │  D1 (app)  │      │         │  │ D1 (auth)  │      │
│  └────────────┘      │         │  └────────────┘      │
└──────────────────────┘         └──────────────────────┘
```

**App**: the secret manager you self-host. Handles secrets encryption, organizations, projects, environments, and the web UI.

**Provider**: the instance's own OAuth provider, deployed next to the app. The app registers itself automatically via [RFC 7591](https://tools.ietf.org/html/rfc7591) dynamic client registration as a public PKCE client (no client secret needed).

</details>

<details>
<summary><b>Auth flow</b></summary>

```diagram
CLI/Agent                    App (self-hosted)              Provider (self-hosted)
   │                              │                                │
   │  POST /api/auth/device/code  │                                │
   │─────────────────────────────▶│                                │
   │  { user_code, device_code }  │                                │
   │◀─────────────────────────────│                                │
   │                              │                                │
   │  User opens /device          │                                │
   │  and enters user_code        │                                │
   │         ┌────────────────────┼────── redirect ───────────────▶│
   │         │                    │                                │
   │         │                    │              Google sign-in ──▶│ Google
   │         │                    │              ◀── callback ─────│
   │         │                    │                                │
   │         │                    │◀── auth code (PKCE) ───────────│
   │         └────────────────────┼────── approved ───────────────▶│
   │                              │                                │
   │  Poll /api/auth/device/token │                                │
   │─────────────────────────────▶│                                │
   │  { access_token }            │                                │
   │◀─────────────────────────────│                                │
```

</details>

<details>
<summary><b>Local dev vs CI authentication</b></summary>

Two auth paths depending on the environment:

```diagram
  Local development                     CI / GitHub Actions
  ─────────────────                     ───────────────────

  sigillo login                         SIGILLO_TOKEN=sig_xxx
       │                                     │
       ▼                                     │
  Browser opens /device                      │
       │                                     │
       ▼                                     │
  Enter user_code                            │
       │                                     │
       ▼                                     │
  Google sign-in                             │
       │                                     │
       ▼                                     ▼
  Signed session token saved         Bearer token from env
  in ~/.sigillo/config.json           var or GitHub secret
       │                                     │
       ▼                                     ▼
  sigillo run -- next dev             sigillo run -- next build
```

**Local**: interactive device flow (RFC 8628). Run `sigillo login` once, then the session is reused until it expires or you end it on the Sessions page.

**CI**: set `SIGILLO_TOKEN` as a secret in your CI provider. No browser needed, no interactive prompts.

</details>

<details>
<summary><b>Secrets encryption</b></summary>

Every secret value is **AES-256-GCM** encrypted before storage. Each write generates a random 12-byte IV, and binds the value to its environment and name, so a copy elsewhere in the database doesn't decrypt. The encryption key is either:

- `ENCRYPTION_KEY`: 32 random bytes, base64-encoded (`openssl rand -base64 32`)
- Derived from `BETTER_AUTH_SECRET` via SHA-256 (default if `ENCRYPTION_KEY` is not set)

`npx @kldzj/sigillo self-host --rotate-key` gives an instance a new key, re-encrypts every stored value with it and retires the old one. Each value names the key it was encrypted with.

```diagram
  plaintext value ("sk-live-xxx")
        │
        ▼
  ┌─────────────┐     ┌──────────────┐
  │ AES-256-GCM │◀────│  12-byte     │
  │   encrypt   │     │  random IV   │
  └──────┬──────┘     └──────────────┘
         │
         ▼
  ┌──────────────────────────────────┐
  │ secret_event (append-only row)   │
  │                                  │
  │  operation:       "set"          │
  │  name:            "API_KEY"      │
  │  value_encrypted: v2.<key id>.…  │
  │  iv:              <12 bytes>     │
  │  actor:           "user:usr_abc" │
  │  seq, hash,       row in the     │
  │  signature:       signed chain   │
  └──────────────────────────────────┘
```

Secrets are stored as an **append-only event log**. Current values are derived by replaying events. This gives you a full audit trail of every change with user/token attribution, and the signed hash chain makes an edited or removed row visible to `sigillo audit verify`. Org admins can purge an environment's old values, all but each secret's current one: the rows stay, and the chain still verifies.

</details>

<details>
<summary><b>REST API</b></summary>

The app exposes a full REST API with OpenAPI documentation at `/api/v0/openapi.json`.

```bash
# list secrets
curl -H "Authorization: Bearer sig_xxx" \
  https://<your-instance>/api/v0/projects/{projectId}/environments/{environmentId}/secrets

# set a secret
curl -X POST -H "Authorization: Bearer sig_xxx" \
  -H "Content-Type: application/json" \
  -d '{"name": "API_KEY", "value": "sk-live-xxx"}' \
  https://<your-instance>/api/v0/projects/{projectId}/environments/{environmentId}/secrets

# bulk download as JSON
curl -H "Authorization: Bearer sig_xxx" \
  https://<your-instance>/api/v0/projects/{projectId}/environments/{environmentId}/secrets/download?format=json

# bulk set
curl -X PUT -H "Authorization: Bearer sig_xxx" \
  -H "Content-Type: application/json" \
  -d '{"secrets": {"KEY1": "val1", "KEY2": "val2"}}' \
  https://<your-instance>/api/v0/projects/{projectId}/environments/{environmentId}/secrets
```

</details>

## License

MIT
