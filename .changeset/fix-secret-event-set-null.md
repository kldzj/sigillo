---
'sigillo-app': patch
---

Stop deleting secrets when the API token or user that wrote them is deleted.

Every secret value is stored as an event that records who wrote it, and those events were deleted together with their author. Revoking a CI token removed every secret it had set, and rolled secrets it had overwritten back to an older value, without any error. Deleting a user did the same.

Revoking a token or deleting a user now keeps their secrets. The event log shows `—` as the author once the author is gone.

Migration `0007` rebuilds the `secret_event` table. Self-hosted instances pick it up by re-running `npx sigillo self-host`.

Fixes #10
