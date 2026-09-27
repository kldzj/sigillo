---
'sigillo': minor
'sigillo-app': patch
---

`npx sigillo self-host` now gives new deployments their own `ENCRYPTION_KEY`.

Until now self-host only set `BETTER_AUTH_SECRET`, so the key that encrypts every stored secret was derived from the same secret that signs login sessions. New deployments now get a separate, random 32-byte `ENCRYPTION_KEY`. It is saved next to the auth secret in `~/.sigillo/selfhost.json`, so a worker recreated from that state keeps reading its data.

Existing deployments are not changed: re-runs still never send or rotate secrets, and deployments made before this keep their derived key. If self-host finds a database that already stores secrets but neither its worker nor the saved state, it now stops and explains how to recover instead of starting over with new keys that would leave those secrets unreadable. The self-hosting docs now say to back up both secrets, since a database backup cannot be decrypted without the key.

Fixes #18
