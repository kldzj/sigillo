---
'sigillo': patch
---

`sigillo logout` now signs the session out on the server, not only on your machine.

Before, logout only deleted the local config entry and the session stayed valid until it expired, so any copy of the token (a backup, synced dotfiles) kept working. If the server cannot be reached, logout still removes the local entry and prints a warning. `sig_` API tokens are not affected; revoke those in the dashboard.
