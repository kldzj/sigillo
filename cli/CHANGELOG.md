# Changelog

## 0.15.0

### Minor Changes

- 677870e: `self-host` encrypts `~/.sigillo/selfhost.json` with a passphrase. The file holds the keys to your deployments, so it can now stay on disk while only the passphrase lives in your password manager.

  - The first run asks for a passphrase, and each run asks for it once. Runs without a terminal read it from `SIGILLO_SELFHOST_PASSPHRASE`.
  - A file from before is encrypted on the next run in a terminal, if you agree.
  - `self-host --change-passphrase` encrypts the file with a new one.

  ```bash
  CLOUDFLARE_API_TOKEN=xxx SIGILLO_SELFHOST_PASSPHRASE=xxx npx @kldzj/sigillo self-host --yes
  ```

- 940d20d: Protected environments and a tamper-evident history.

  - **Protected** (Environments tab, admins) records every read of an environment's values: who, when, which secrets, how (revealed, old value in the event log, listed, downloaded, copied) and from which IP. Admins see it on the new **Read Log** tab. The read is recorded before any value leaves the server, and fails if it can't be. Turning protection off is recorded too.
  - The secrets page and the event log load a value only when you reveal it, download or copy it, so opening a page no longer sends any values to the browser.
  - Each environment's secret changes and reads form hash chains signed by the server, so editing, removing or adding a row in the database shows up.
  - `sigillo audit verify` checks both chains of an environment and remembers their heads in `~/.sigillo/audit.json`, so rows removed since the last check show up too:

  ```bash
  $ sigillo audit verify -c prod
  ✔ changes: 42 rows, intact
  ✔ reads: 7 rows, intact
  ```

- d8fd963: `self-host --allowed-users` limits who can sign in to your instance.

  ```bash
  npx @kldzj/sigillo self-host --allowed-users acme.com,ops@partner.io
  ```

  - A new deployment asks for the list. The app and its login provider both enforce it.
  - Updates keep the saved list. Pass the flag again to change it, or `--allowed-users ''` to let anyone in.
  - `self-host` warns when anyone with a Google account can sign in.

### Patch Changes

- 2793a2d: The npm package has a README: install, deploying your instance and the first commands, with a link to the full documentation.
- 4e76355: The CLI now sends `User-Agent: sigillo-cli/<version>` instead of Zig's default `zig/<version>`, so the server can tell it apart from other clients.
- e39f1a6: `sigillo login` signs in again when a token is already saved. It used to re-save the saved token and stop, so a login that had stopped working could only be replaced after `sigillo logout`. `--token` and `SIGILLO_TOKEN` are still saved as given.
- ad62fac: When sign-in fails or is refused, the login provider's error page now leads back to your instance's sign-in page. Its button used to open the provider's root, which only answers with a health check.

## 0.14.1

### Patch Changes

- d59fe56: `sigillo environments rename` works with only `--name` or only `--slug`. The CLI sent the missing field as `null`, which the API rejects, so the rename failed with `(422): unknown error`.
- bc2d56b: The CLI never sends your saved token to another server, and `run --mount` is safer.

  - If `SIGILLO_API_URL` or `--api-url` points somewhere other than the server the token was saved for, the token is withheld with a warning. `--token` and `SIGILLO_TOKEN` still work as given.
  - Authenticated requests no longer follow redirects. Point `--api-url` at the final URL, for example `https://`.
  - `run --mount` creates the file owner-only (`0600`), refuses to overwrite an existing file or follow a symlink, and deletes it even when sigillo gets `SIGTERM` or `SIGHUP`. These signals are forwarded to the child instead of killing sigillo.

- f363db2: `self-host` can take a new deployment's encryption key from `SIGILLO_ENCRYPTION_KEY`.

  - New deployments still get their own random `ENCRYPTION_KEY`. To choose it yourself, set `SIGILLO_ENCRYPTION_KEY` on the first deploy. It cannot be set on an existing deployment, because a new key would make its stored secrets unreadable.

    ```bash
    SIGILLO_ENCRYPTION_KEY="$(openssl rand -base64 32)" npx @kldzj/sigillo self-host
    ```

  - `self-host` also stops before generating new secrets for a database that `~/.sigillo/selfhost.json` remembers without its secret, not only for one it finds by name. Before, every stored secret in it would have become unreadable.

## 0.14.0

### Minor Changes

- 8de9c27: `--project` now accepts a project name as well as its ID.

  ```bash
  sigillo run --project website --env dev -- npm start
  sigillo setup --project website --env dev
  ```

  Before, a name was sent to the API as if it were an ID, and the command failed with `env dev was not found in project website`. Now a value that isn't a project ID is looked up among the projects you can access. If no project has that name, the error says the project was not found and lists the ones you can use. If several projects share the name, it lists them so you can pick one by ID. `setup` saves the resolved ID, so renaming the project later doesn't break the directory's config.

  An unknown project ID is also reported as a missing project now, instead of as a missing env.

- The CLI is now published as `@kldzj/sigillo` from [kldzj/sigillo](https://github.com/kldzj/sigillo), a maintained fork of Sigillo with no hosted service. The command is still `sigillo`.

  ```bash
  npm i -g @kldzj/sigillo
  npx @kldzj/sigillo self-host
  ```

  `self-host` downloads its release bundles from kldzj/sigillo's GitHub releases, and the install script and docs point there too.

- 8cc4c01: The CLI no longer has a default server. Every Sigillo instance is self-hosted, so run `sigillo login --api-url https://<your-instance>` once; every other command uses the saved URL.

  Without a configured server, commands stop with `no Sigillo server configured` instead of contacting sigillo.dev.

- `npx @kldzj/sigillo self-host` now deploys each instance with its own login provider, instead of signing in through auth.sigillo.dev.

  The provider runs as a second Worker next to the app (`<name>-auth`) with its own D1 database, and people sign in with Google through it. A new deployment needs a Google OAuth client: self-host prints the redirect URI to register at Google Cloud and asks for the client ID and secret, or takes `--google-client-id` and `--google-client-secret`. The provider's secret and the Google client are saved in `~/.sigillo/selfhost.json` and never rotated on updates. The first sign-in to an instance asks once to allow it.

  A deployment that already signs in through another provider, such as one made with upstream Sigillo's self-host, keeps that provider on update, since a new one would give every user a new login.

- 76c9072: `npx @kldzj/sigillo self-host` now gives new deployments their own `ENCRYPTION_KEY`.

  Until now self-host only set `BETTER_AUTH_SECRET`, so the key that encrypts every stored secret was derived from the same secret that signs login sessions. New deployments now get a separate, random 32-byte `ENCRYPTION_KEY`. It is saved next to the auth secret in `~/.sigillo/selfhost.json`, so a worker recreated from that state keeps reading its data.

  Existing deployments are not changed: re-runs still never send or rotate secrets, and deployments made before this keep their derived key. If self-host finds a database that already stores secrets but neither its worker nor the saved state, it now stops and explains how to recover instead of starting over with new keys that would leave those secrets unreadable. The self-hosting docs now say to back up both secrets, since a database backup cannot be decrypted without the key.

  Fixes remorses/sigillo#18

### Patch Changes

- 654dfe4: `sigillo logout` now signs the session out on the server, not only on your machine.

  Before, logout only deleted the local config entry and the session stayed valid until it expired, so any copy of the token (a backup, synced dotfiles) kept working. If the server cannot be reached, logout still removes the local entry and prints a warning. `sig_` API tokens are not affected; revoke those in the dashboard.

- 2b8f7c1: `npx @kldzj/sigillo self-host` now exits with status 1 when the deploy fails. It used to print the error and still exit 0, so a CI job running `CLOUDFLARE_API_TOKEN=xxx npx @kldzj/sigillo self-host --yes` passed even when nothing was deployed.

<!-- https://github.com/remorses/sigillo/releases -->

## 0.13.0

1. **New `npx sigillo self-host`** — deploy Sigillo to your own Cloudflare account with one command. No git clone, no build step, no wrangler config:

   ```bash
   npx sigillo self-host
   ```

   The command provisions everything needed to run Sigillo on your Cloudflare account from a prebuilt release bundle:

   - **Worker + D1 database** created and wired automatically
   - **D1 migrations** applied using wrangler-compatible `d1_migrations` bookkeeping
   - **workers.dev URL** enabled and printed at the end
   - **Custom domain** optionally attached (`--domain secrets.acme.com`)
   - **Auth just works** — the instance registers with the hosted Sigillo auth provider on first load, no OAuth keys to configure

   Cloudflare authentication tries, in order: `CLOUDFLARE_API_TOKEN`, your existing `wrangler login` (refreshed and written back if expired), a previous self-host login, then an interactive choice between an OAuth browser login and a pre-filled API-token creation link that works from any device (useful over SSH).

   Re-running the command is **idempotent** and deploys the latest release: only new migrations are applied, unchanged assets are skipped, and `BETTER_AUTH_SECRET` is never rotated (rotating it would invalidate the encryption key protecting stored secrets). An existing worker with the same name is only updated in place when it is a known Sigillo deployment; an unrelated worker is left alone and you are asked for a different `--name`.

   ```bash
   # non-interactive (CI/agents)
   CLOUDFLARE_API_TOKEN=xxx npx sigillo self-host --yes

   # custom worker name and domain
   npx sigillo self-host --name sigillo --domain secrets.acme.com
   ```

   This command is TypeScript-only and ships in the npm package. The standalone binary prints a pointer to `npx sigillo self-host`.

2. **`sig_` API tokens can now run `setup`** — a project-scoped token used to work on secrets routes but `GET /api/v0/projects/:id` returned **401**, so this failed:

   ```bash
   sigillo login --api-url https://secrets.example.com --token sig_xxxxx
   sigillo setup --project <project-id> --env dev
   ```

   Token login can now call the read routes `setup`, `me`, `orgs`, and `environments get` need. Create, rename, and delete of orgs, projects, and envs still require a user session. Env-scoped tokens only see that environment. Deleting a scoped environment now **revokes** the token instead of widening it to the whole project.

   Hosted sigillo.dev gets this on the website deploy that follows this release. Existing self-hosted instances pick it up by re-running `npx sigillo self-host` (applies migration `0006`).

   Fixes #4

## 0.12.0

1. **Pipe-friendly output across all commands** — when stdout is piped (not a TTY), commands now output minimal machine-readable text instead of verbose YAML. This makes scripting and piping natural without any extra flags:

   ```bash
   # list secret names for grep/xargs
   sigillo secrets | grep DATABASE

   # capture new project ID in a variable
   PROJECT_ID=$(sigillo projects create --org org_123 --name backend)

   # capture new env ID
   ENV_ID=$(sigillo environments create -p $PROJECT_ID --name staging --slug staging)

   # set a secret and capture its ID
   SECRET_ID=$(sigillo secrets set API_KEY my-value -c dev)
   ```

   Affected commands and their piped output:

   - `sigillo secrets` — one secret name per line
   - `sigillo secrets set` — secret ID per environment
   - `sigillo orgs create` — new org ID
   - `sigillo projects create` — new project ID
   - `sigillo environments create` — new environment ID

   TTY output is unchanged (same verbose YAML format as before).

2. **`--raw` flag for `secrets get`** — force raw value output even when stdout is a TTY. When piped, raw mode is enabled automatically so values flow between commands without YAML wrapping:

   ```bash
   # copy a secret between environments (piped stdout auto-enables raw mode)
   sigillo secrets get DATABASE_URL -c dev | sigillo secrets set DATABASE_URL -c preview

   # force raw output in a terminal
   sigillo secrets get DATABASE_URL --raw
   ```

   Previously, piping `secrets get` would store the full YAML output (with `environment_id`, `name`, `value` fields) as the secret value, corrupting it.

## 0.11.0

1. **TTY-aware secret redaction with PTY passthrough** — `sigillo run` now uses pseudo-terminals instead of pipes when stdout/stderr are TTYs. Child processes see `isatty()=true`, so tools like `next dev`, `cargo`, and `pytest` keep their colored output, progress bars, and interactive prompts while secrets are still redacted from the output stream:

   ```bash
   # colored output and progress bars work normally now
   sigillo run -- next dev
   sigillo run -- cargo build --color=always
   ```

   Falls back to pipes automatically when the parent streams are not TTYs or on Windows. PTY slaves have OPOST disabled so `\n` is not transformed to `\r\n`, keeping exact-byte redaction matching for multiline secrets. Terminal window size is propagated from parent to child.

2. **Git worktree config inheritance** — running `sigillo` inside a git worktree now automatically inherits the project, environment, token, and API URL from the main repo if no worktree-specific config exists:

   ```bash
   # set up once in the main repo
   cd my-project && sigillo setup

   # worktrees pick it up automatically
   cd ../my-project-feature-branch
   sigillo secrets   # works without re-running setup
   ```

   Worktree-specific scopes still take priority. Supports relative `gitdir:` paths and Git-for-Windows forward-slash paths. Submodules are correctly excluded.

3. **Empty and missing secrets shown in `sigillo secrets`** — the secrets list now highlights secrets with empty values (`empty: true` in yellow) and shows a separate `missing:` section for secrets that exist in other environments of the same project but not the current one:

   ```bash
   sigillo secrets -c production
   ```

   ```yaml
   secrets:
     - name: DATABASE_URL
       ...
     - name: PLACEHOLDER_KEY
       empty: true          # yellow in terminal
   missing:                 # red in terminal
     - STRIPE_SECRET_KEY    # exists in staging but not production
   ```

   Non-TTY output stays valid YAML for scripting.

4. **Empty values allowed in interactive prompt** — `sigillo secrets set` no longer rejects empty values when prompted interactively. Useful for creating placeholder secrets you fill in later via the dashboard:

   ```bash
   sigillo secrets set FUTURE_KEY -c dev
   ? Value for FUTURE_KEY:
   note: setting empty value (fill in later via dashboard)
   ```

5. **Fixed deadlock on exec failure** — when the child command does not exist, `sigillo run` no longer hangs. The errdefer now kills the child before joining reader threads, and unreapable spawn errors are handled without leaving zombie processes.

6. **Fixed PTY fd leaks causing child hangs** — PTY master and slave file descriptors are now opened with CLOEXEC so backgrounded child subprocesses don't inherit and hold open the slave fd, which previously caused the redaction reader to hang waiting for EOF.

7. **Fixed use-after-free in PTY redaction** — corrected defer/errdefer ordering so redaction plan memory stays alive while reader threads are still running. Also fixed double-close of PTY fds by tracking ownership with nullable variables.

## 0.10.0

1. **Set or delete a secret across many environments at once** — `-c`/`--config` (and `--env`) are now repeatable on `secrets set` and `secrets delete`, so a single command fans out to every environment you list:

   ```bash
   # write the same value to dev, prod, and staging in one shot
   sigillo secrets set DATABASE_URL postgres://... -c dev -c prod -c staging

   # delete a stale key from multiple environments
   sigillo secrets delete OLD_KEY -c dev -c prod
   ```

   Fan-out is continue-on-error: if one environment fails (for example an unknown env slug), it prints `failed to set/delete secret in <env> ...` and keeps going through the rest, then exits non-zero if any failed. The env-not-found hint still lists the available environments. With no `-c`/`--env` flag the behavior is unchanged: it uses the single environment from `sigillo setup`.

2. **Masked prompt when you omit the secret value on a terminal** — leave the value off and Sigillo asks for it interactively, masking each character so the secret never appears on screen:

   ```bash
   sigillo secrets set STRIPE_SECRET_KEY -c prod
   ? Value for STRIPE_SECRET_KEY: *****************
   ```

   The value is read once before any network call, so a multi-environment write only prompts a single time. Backspace works and ctrl-c/ctrl-d cancels. Piped stdin (non-TTY) is unchanged: it still reads the value from stdin and strips a single trailing newline for scripts and CI.

## 0.9.1

1. **Configured subfolders shown in error messages** — when you run `sigillo run` from a directory without a project configured, the error now lists subfolders that _are_ set up with their project names and environments. This helps agents and users discover they need to `cd` into the right directory:

   ```
   error: project not configured for /Users/me/monorepo
     sigillo setup --project <PROJECT_ID> --env <SLUG>

   subfolders configured with sigillo:
     ./app  →  my-website (dev)
     ./api  →  my-api (dev)

   run sigillo from one of these directories instead, or run:
     sigillo setup
   ```

   The same hint appears in `secrets`, `secrets get/set/delete`, `secrets download`, and `environments` commands.

2. **`sigillo me` shows configured subfolders** — the `me` command now lists all subfolders under the current directory that have sigillo set up, so you can quickly see the status of a monorepo:

   ```bash
   sigillo me
   ```

   ```
   Configured subfolders:
     ./app  →  my-website (dev)
     ./api  →  my-api (prod)
   ```

## 0.8.1

1. **Faster project setup and listing**. `sigillo setup` and `sigillo projects` now fetch all accessible projects in one request instead of querying every organization one by one:

   ```bash
   sigillo setup
   sigillo projects
   ```

   This makes interactive setup noticeably quicker for accounts with multiple organizations.

2. **Project names are saved in local setup**. After setup, `sigillo me` shows the configured project name alongside its ID so scoped directories are easier to inspect:

   ```bash
   sigillo setup --project <project-id> --env dev
   sigillo me
   ```

3. **Clearer project lists across organizations**. Project suggestions and `sigillo projects` now include the organization name directly, so duplicated project names are easier to tell apart.

## 0.8.0

1. **New `-p` project flag alias** — pass a project ID with the same short flag Doppler uses. This makes one-off commands and Doppler migrations easier to copy without relying on saved directory setup:

   ```bash
   sigillo run -p <project-id> -c dev -- pnpm dev

   doppler secrets get DATABASE_URL --plain -p <doppler-project> -c dev |
     sigillo secrets set DATABASE_URL -p <sigillo-project-id> -c dev
   ```

   The alias works anywhere `--project` is accepted, including `setup`, `run`, `secrets`, `secrets get`, `secrets set`, `secrets delete`, `secrets download`, `environments`, and `environments create`.

2. **Project overrides now work on secret commands** — secret commands can target a project directly instead of requiring a prior `sigillo setup`:

   ```bash
   sigillo secrets -p <project-id> -c prod
   sigillo secrets download -p <project-id> -c prod --format json
   ```

   This is especially useful for agents and migration steps that should use explicit placeholders instead of storing CLI state first.

## 0.7.0

1. **New `sigillo orgs` and `sigillo orgs create` commands** — manage organizations from the terminal:

   ```bash
   # list your organizations
   sigillo orgs

   # create a new organization
   sigillo orgs create --name "My Team"
   ```

   `orgs` prints a table of org IDs, names, and your role. `orgs create` creates a new org and shows its ID and name. Both work with `--token` and `--api-url` like every other command.

2. **`sigillo me` now shows current project/env setup** — when a project and/or environment is configured for the current directory (via `sigillo setup`), the me command prints a setup section showing the scoped directory, project ID, and env slug.

3. **Cleaner help with shared global options** — `--token` and `--api-url` now appear once in help output instead of repeating on every command. Project-, env-, and config-specific flags stay on the commands that use them. The zeke framework powers this under the hood.

4. **Empty string secrets are now allowed** — `sigillo secrets set KEY ""` no longer errors. Empty string values are valid secrets that get stored and decrypted correctly.

## 0.6.0

1. **Versioned `v0` API with project-scoped environment routes**. The CLI now talks to `/api/v0/...` and includes the project id on every environment-bound request. This makes env slug resolution consistent across `run`, `secrets`, and environment management commands on self-hosted installs:

   ```bash
   sigillo setup --project website --env dev
   sigillo run --env prod -- next start
   sigillo secrets download --format json
   ```

   Self-hosted app deployments now need to expose the new `v0` routes for the updated CLI.

2. **`environments get|rename|delete` now accept env slugs**. Slug support now covers the full environment command set instead of only setup and secrets flows:

   ```bash
   sigillo environments get production
   sigillo environments rename staging --slug preprod
   sigillo environments delete preview
   ```

3. **Local wrapper refresh is automatic after native builds**. Building the host target now refreshes the local `sigillo` wrapper in both `~/.local/bin` and pnpm's global bin directory, so the command in your shell keeps pointing at the current checkout without a separate install step.

## 0.5.0

1. **Environment slugs replace IDs in all CLI commands** — `--env` and `-c` now accept slugs like `dev`, `prod`, `staging` instead of raw ULIDs. `sigillo setup` stores the slug, interactive prompts show `Name (slug)`, and error hints list available slugs. The API accepts both IDs and slugs, so existing configs continue working without changes:

   ```bash
   sigillo setup --project website --env dev
   sigillo run --project website --env prod -- next start
   ```

2. **Pipe secret values via stdin** — `sigillo secrets set` now reads from stdin when the value argument is omitted. A single trailing newline from `echo` is stripped automatically:

   ```bash
   # pipe a value directly
   echo "my-api-key" | sigillo secrets set API_KEY

   # multiline values are preserved as-is
   cat private-key.pem | sigillo secrets set SSH_KEY
   ```

   If stdin is a TTY and no value is given, the CLI prints a usage hint instead of hanging.

## 0.4.0

1. **New file mount mode for `sigillo run`** — write secrets to a temporary file before launching your process, then clean it up automatically when the command exits:

   ```bash
   sigillo run --mount .env -- npm start
   sigillo run --mount config.json --mount-format json -- next dev
   sigillo run --mount secrets.yaml --mount-format yaml -- ./deploy.sh
   ```

   This is useful for tools that expect config files instead of plain environment variables.

2. **More download and mount formats, including Vercel sync support** — `sigillo secrets download` and `sigillo run --mount-format` now support Doppler-style formats like `env-no-quotes`, `docker`, `dotnet-json`, and `xargs`:

   ```bash
   sigillo secrets download --format json
   sigillo secrets download --format xargs | xargs -0 -n2 sh -c 'printf %s "$2" | vercel env add "$1" production --force' sh
   ```

   The new `xargs` mode emits NUL-delimited `KEY VALUE` pairs so spaces, quotes, and multiline secrets survive shell pipelines safely.

3. **`sigillo run` no longer falls over on huge child output** — redaction now streams stdout and stderr incrementally instead of buffering the whole process first, so long-running commands and very large logs keep working while still hiding secrets.

4. **New env aliases for scoped commands** — env-scoped commands now use `--env` as the main flag, with `--config` and `-c` available as aliases:

   ```bash
   sigillo setup --project website --env dev
   sigillo run --project website --env dev -- next dev
   sigillo run --project website -c production -- next dev
   ```

5. **Clearer project and env lookup errors** — when you pass a missing project or env, the CLI now shows the matching list of available projects or envs instead of leaving you with a generic fetch error.

## 0.3.0

1. **New CRUD commands for projects, environments, and secrets** — manage Sigillo resources from the terminal instead of jumping back to the web UI:

   ```bash
   sigillo projects
   sigillo projects create --org org_123 --name backend
   sigillo environments create --project proj_123 --name Production --slug production
   sigillo secrets set DATABASE_URL postgres://localhost:5432/app
   sigillo secrets download > secrets.yaml
   ```

   Adds `projects get|create|update|delete`, `environments get|create|rename|delete`, and `secrets get|set|delete|download`, with script-friendly plain-text output.

2. **Token-based login for CI and agent sessions** — save an existing bearer token without starting the device flow:

   ```bash
   SIGILLO_TOKEN=sig_xxx sigillo login --scope /
   sigillo login --token sig_xxx --scope /Users/me/project
   ```

   This makes it easier to reuse API tokens in automation while still letting `sigillo` resolve them through the normal scoped config.

3. **Interactive scope and setup prompts** — `sigillo login` can now ask whether auth should be saved globally or for the current directory, and `sigillo setup` can guide project/environment selection when you do not want to paste raw IDs.

4. **Safer `sigillo run` logs by default** — likely secret values are redacted from child stdout/stderr unless you explicitly opt out:

   ```bash
   sigillo run -- next dev
   sigillo run --disable-redaction -- next dev
   ```

5. **More reliable Windows behavior** — config now lives under `%APPDATA%\sigillo\config.json`, shell commands use the Windows command shell correctly, and browser launch/process execution are more reliable on Windows.

## 0.2.0

1. **`--api-url` now defaults to `https://sigillo.dev`** — no need to pass it when using the hosted version:

   ```bash
   # Before
   sigillo login --api-url https://sigillo.dev

   # Now
   sigillo login
   ```

   All commands (`login`, `me`, `setup`, `run`) default to `https://sigillo.dev`. Pass `--api-url` only when self-hosting.

2. **Colored terminal output** — error messages, labels, URLs, and success indicators are color-coded when connected to a TTY. Piped/redirected output stays plain text.

3. **`sigillo logout` no longer requires `--yes`** — just run `sigillo logout` directly.

4. **Interactive select picker (foundation)** — arrow-key selection prompt built into the CLI for upcoming interactive `setup` flow. Uses POSIX termios raw mode with no external dependencies; falls back to numbered list on Windows or non-TTY.

## 0.1.0

First real CLI release. Install via npm:

```bash
npm install -g sigillo
```

1. **`sigillo login`** — authenticate with device flow (RFC 8628). Opens a browser automatically and polls until approved:

   ```bash
   sigillo login --api-url https://secrets.example.com
   ```

   Saves credentials scoped to the current directory (or `--scope /path`).

2. **`sigillo run`** — inject secrets as environment variables into any command:

   ```bash
   # Pass command after --
   sigillo run -- node server.js

   # Or as a shell string
   sigillo run --command 'echo $DATABASE_URL'
   ```

   Fetches secrets from the configured project/environment and merges them into the child process environment. The child's exit code is forwarded.

3. **`sigillo setup`** — link the current directory to a project and environment:

   ```bash
   sigillo setup --project proj_123 --environment env_abc
   ```

   Saved in `~/.sigillo/config.json`, scoped by directory. `sigillo run` picks this up automatically.

4. **`sigillo me`** — show the currently logged-in user and their organizations:

   ```bash
   sigillo me
   sigillo me --json   # raw JSON
   ```

5. **`sigillo logout`** — remove saved auth for a scope:

   ```bash
   sigillo logout --yes
   sigillo logout --scope /Users/me/project --yes
   ```

**Platforms:** macOS arm64/x64, Linux arm64/x64 (musl — works on glibc and Alpine), Windows arm64/x64.
