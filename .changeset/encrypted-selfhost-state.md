---
'@kldzj/sigillo': minor
---

`self-host` encrypts `~/.sigillo/selfhost.json` with a passphrase. The file holds the keys to your deployments, so it can now stay on disk while only the passphrase lives in your password manager.

- The first run asks for a passphrase, and each run asks for it once. Runs without a terminal read it from `SIGILLO_SELFHOST_PASSPHRASE`.
- A file from before is encrypted on the next run in a terminal, if you agree.
- `self-host --change-passphrase` encrypts the file with a new one.

```bash
CLOUDFLARE_API_TOKEN=xxx SIGILLO_SELFHOST_PASSPHRASE=xxx npx @kldzj/sigillo self-host --yes
```
