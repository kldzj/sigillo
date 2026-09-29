<div align='center' class='hidden'>
    <br/>
    <br/>
    <h3>sigillo</h3>
    <p>Self-hostable secrets manager for humans & agents</p>
    <br/>
    <br/>
</div>

Sigillo replaces `.env` files with a **secrets manager you self-host** on Cloudflare, an open source alternative to [Doppler](https://doppler.com) and [Infisical](https://infisical.com). Prefix your commands with `sigillo run` and secrets are injected as environment variables, never written to disk.

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

Values that look random are **redacted** from the command's output, so keys and tokens stay out of terminals, CI logs and AI agents' context windows.

> **This is [kldzj/sigillo](https://github.com/kldzj/sigillo)**, a fork of [Sigillo](https://github.com/remorses/sigillo) by [Tommy D. Rossi](https://github.com/remorses), for teams who want tighter control over their secrets. There is no hosted service: every instance runs on your own Cloudflare account with its own Google sign-in. The CLI is [`@kldzj/sigillo`](https://www.npmjs.com/package/@kldzj/sigillo), and the docs are at [sigillo.kldzj.dev](https://sigillo.kldzj.dev).

## Features

**Secrets in your commands**
- [`sigillo run`](https://sigillo.kldzj.dev/docs/run) injects an environment's secrets as environment variables, and redacts them from the output
- `--mount` writes a file only you can read and deletes it when the command exits
- [Downloads](https://sigillo.kldzj.dev/docs/secrets#download-all-secrets) as `json`, `env`, `yaml`, `docker`, `dotnet-json` and more, and [pipes](https://sigillo.kldzj.dev/docs/integrations) into Cloudflare Workers, Vercel, Fly.io and Docker

**Teams**
- [Organizations](https://sigillo.kldzj.dev/docs/access) with admins and members, invite links, auto-join by email domain, and access per project
- Projects with `dev`, `preview` and `prod` environments, and [admin-only environments](https://sigillo.kldzj.dev/docs/access#admin-only-environments)
- A [sign-in allowlist](https://sigillo.kldzj.dev/docs/self-hosting#who-can-sign-in), and a sessions page to end your logins

**Production**
- [Protected environments](https://sigillo.kldzj.dev/docs/protected-environments): reading or changing them takes a passkey, in the browser or from the CLI
- A [signed history](https://sigillo.kldzj.dev/docs/history) of every change and every read of a protected value, checked with `sigillo audit verify`

**Machines**
- [API tokens and machine tokens](https://sigillo.kldzj.dev/docs/ci) that expire, scoped to a project and its environments
- [Workload identity](https://sigillo.kldzj.dev/docs/workload-identity): GitHub Actions jobs and Kubernetes pods read secrets without a stored token, and External Secrets Operator works through its Doppler provider

**Your own infrastructure**
- [One command](https://sigillo.kldzj.dev/docs/self-hosting) deploys it to Cloudflare Workers and D1, on the free plan
- Values encrypted with AES-256-GCM, [key rotation](https://sigillo.kldzj.dev/docs/rotate-key), and [encrypted backups](https://sigillo.kldzj.dev/docs/backups)
- A [REST API](https://sigillo.kldzj.dev/docs/api) with an OpenAPI description

## Get started

```bash
npx @kldzj/sigillo self-host                                       # deploy your instance
sigillo login --api-url https://sigillo.<your-subdomain>.workers.dev
sigillo setup                                                      # link this directory to a project
sigillo run -- next dev
```

The [quick start](https://sigillo.kldzj.dev/docs/quick-start) walks through it, including creating a project and adding secrets. Coming from Doppler? See the [migration guide](https://sigillo.kldzj.dev/docs/doppler-migration).

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

**AI agents**: install the skill for Claude Code, Cursor, Windsurf and others:

```bash
npx -y skills add kldzj/sigillo
```

## Documentation

- **[Get started](https://sigillo.kldzj.dev/docs/self-hosting)**: self-host your instance, the quick start, migrating from Doppler
- **[Use Sigillo](https://sigillo.kldzj.dev/docs/secrets)**: secrets and environments, running commands, teams, CI, workload identity, syncing to other platforms
- **[Security](https://sigillo.kldzj.dev/docs/security)**: how Sigillo protects your secrets, protected environments, the signed history, the hardening checklist
- **[Run your instance](https://sigillo.kldzj.dev/docs/updating)**: updates, backups, key rotation, deploying from source
- **[Reference](https://sigillo.kldzj.dev/docs/configuration)**: configuration, the [CLI](https://sigillo.kldzj.dev/docs/cli) and the [REST API](https://sigillo.kldzj.dev/api)

## Contributing

Sigillo is two Cloudflare Workers, the app and its login provider, and a Zig CLI, in one pnpm workspace. [Deploy from source](https://sigillo.kldzj.dev/docs/from-source) explains running them locally. Fixes that suit both go to [upstream](https://github.com/remorses/sigillo) as pull requests too.

## License

MIT, see [LICENSE](LICENSE). Sigillo was created by [Tommy D. Rossi](https://github.com/remorses) and the Sigillo contributors at [remorses/sigillo](https://github.com/remorses/sigillo); this fork is maintained by Nikolai Kolodziej.
