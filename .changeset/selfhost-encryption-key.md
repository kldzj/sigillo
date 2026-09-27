---
'@kldzj/sigillo': patch
---

`self-host` can take a new deployment's encryption key from `SIGILLO_ENCRYPTION_KEY`.

- New deployments still get their own random `ENCRYPTION_KEY`. To choose it yourself, set `SIGILLO_ENCRYPTION_KEY` on the first deploy. It cannot be set on an existing deployment, because a new key would make its stored secrets unreadable.

  ```bash
  SIGILLO_ENCRYPTION_KEY="$(openssl rand -base64 32)" npx @kldzj/sigillo self-host
  ```

- `self-host` also stops before generating new secrets for a database that `~/.sigillo/selfhost.json` remembers without its secret, not only for one it finds by name. Before, every stored secret in it would have become unreadable.

Fixes remorses/sigillo#18
