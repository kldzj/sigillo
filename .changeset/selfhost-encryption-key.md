---
'sigillo': patch
---

`self-host` can bind a separate encryption key, and never adopts a database it cannot decrypt.

- Set `SIGILLO_ENCRYPTION_KEY` on the first deploy to use a separate AES key instead of the one derived from `BETTER_AUTH_SECRET`. The default is unchanged.

  ```bash
  SIGILLO_ENCRYPTION_KEY="$(openssl rand -base64 32)" npx sigillo self-host
  ```

- If a deploy would generate a new `BETTER_AUTH_SECRET` for a D1 database that already stores secrets (worker gone, and no saved secret in `~/.sigillo/selfhost.json`), `self-host` now stops. Before, it deployed anyway and every stored secret became unreadable.

Fixes #18
