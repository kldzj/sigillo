# @kldzj/sigillo

The CLI for [Sigillo](https://github.com/kldzj/sigillo), a secrets manager you self-host on Cloudflare. Instead of `.env` files, `sigillo run` passes secrets to your command as environment variables and redacts them from its output.

This is the CLI of [kldzj/sigillo](https://github.com/kldzj/sigillo), a maintained fork of [remorses/sigillo](https://github.com/remorses/sigillo) with no hosted service: every instance runs on your own Cloudflare account.

## Install

```bash
npm i -g @kldzj/sigillo
```

## Deploy your instance

```bash
npx @kldzj/sigillo self-host
```

This deploys Sigillo and its own Google login to your Cloudflare account (Workers and D1). It asks who may sign in (`--allowed-users acme.com`) and for a passphrase that encrypts `~/.sigillo/selfhost.json`, the file with your deployment's keys; runs without a terminal read it from `SIGILLO_SELFHOST_PASSPHRASE`. Run it again to update. See [Self-hosting](https://github.com/kldzj/sigillo#self-hosting).

## Use it

```bash
sigillo login --api-url https://sigillo.<your-subdomain>.workers.dev
sigillo setup --project website --env dev   # link this directory
sigillo secrets set DATABASE_URL            # asks for the value
sigillo run -- npm start                    # start with the secrets as env vars
```

The CLI reference, integrations (Cloudflare Workers, Vercel, Docker, GitHub Actions) and how encryption works are in the [README on GitHub](https://github.com/kldzj/sigillo#readme).

## License

MIT
