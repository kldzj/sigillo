# @kldzj/sigillo

The CLI for [Sigillo](https://github.com/kldzj/sigillo), a secrets manager you self-host on Cloudflare. Instead of `.env` files, `sigillo run` passes secrets to your command as environment variables and redacts them from its output.

This is the CLI of [kldzj/sigillo](https://github.com/kldzj/sigillo), a maintained fork of [Sigillo](https://github.com/remorses/sigillo) by [Tommy D. Rossi](https://github.com/remorses), with no hosted service: every instance runs on your own Cloudflare account.

## Install

```bash
npm i -g @kldzj/sigillo
```

## Deploy your instance

```bash
npx @kldzj/sigillo self-host
```

This deploys Sigillo and its own Google login to your Cloudflare account (Workers and D1). It asks who may sign in (`--allowed-users acme.com`) and for a passphrase that encrypts `~/.sigillo/selfhost.json`, the file with your deployment's keys; runs without a terminal read it from `SIGILLO_SELFHOST_PASSPHRASE`. Run it again to update. See [Self-host your instance](https://sigillo.kldzj.dev/docs/self-hosting).

## Use it

```bash
sigillo login --api-url https://sigillo.<your-subdomain>.workers.dev
sigillo setup --project website --env dev   # link this directory
sigillo secrets set DATABASE_URL            # asks for the value
sigillo run -- npm start                    # start with the secrets as env vars
```

The [quick start](https://sigillo.kldzj.dev/docs/quick-start), the [CLI reference](https://sigillo.kldzj.dev/docs/cli), CI and workload identity, integrations (Cloudflare Workers, Vercel, Docker) and how Sigillo protects your secrets are in the [docs](https://sigillo.kldzj.dev).

## License

MIT, see [LICENSE](https://github.com/kldzj/sigillo/blob/main/LICENSE).
