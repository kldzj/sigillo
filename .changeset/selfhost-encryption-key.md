---
'sigillo': patch
---

`self-host` can bind a separate encryption key, and never adopts a database it cannot decrypt.

- Set `SIGILLO_ENCRYPTION_KEY` on the first deploy to use a separate AES key instead of the one derived from `BETTER_AUTH_SECRET`. The default is unchanged.

  ```bash
  SIGILLO_ENCRYPTION_KEY="$(openssl rand -base64 32)" npx sigillo self-host
  ```

- If the worker and `~/.sigillo/selfhost.json` are gone but the D1 database still stores secrets, `self-host` now stops instead of deploying with a new secret that would make them all unreadable.

Fixes #18
