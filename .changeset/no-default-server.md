---
'@kldzj/sigillo': minor
---

The CLI no longer has a default server. Every Sigillo instance is self-hosted, so run `sigillo login --api-url https://<your-instance>` once; every other command uses the saved URL.

Without a configured server, commands stop with `no Sigillo server configured` instead of contacting sigillo.dev.
