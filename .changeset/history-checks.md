---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

Stricter history checks and safer self-hosting:

- A value removed from the database without a purge now breaks the history: `sigillo audit verify` and a restore report it, and the **History** tab shows it as "value removed without a purge". Before, a value erased with its digest kept looked like a purged one.
- Exporting a protected environment's history, as `sigillo audit verify` does, takes a passkey approval and shows in its read log, since the export shows whether a value was set back to an earlier one.
- Environment pages no longer tell someone who can't open the project the slug of its first environment.
- The Worker refuses an `ENCRYPTION_KEY` that isn't 32 bytes. Keys made by `self-host` always are; a shorter key set by hand in the dashboard stops the instance until it is replaced.
- `self-host --rotate-key` gives the Worker its key ring again when it finishes an unfinished rotation, and the check before recreating a worker tries a value under every key in use.
- `self-host --restore` needs `--yes` without a terminal, says exactly what it checked, compares the history with what `sigillo audit verify` saw on your machine, and stays unfinished until both workers use the restored databases: `--backup`, `--rotate-key` and `--reset-passkeys` wait for it. Backups no longer hold sign-in ID tokens, and `self-host` no longer drops the backup key when it updates a deployment.
