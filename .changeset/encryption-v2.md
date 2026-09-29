---
'sigillo-app': minor
---

Encryption v2, and purging old values:

- Every stored value is bound to its environment and name, and names the key it was encrypted with. A value copied elsewhere in the database no longer decrypts. Values from before stay readable, and a key rotation moves them to the new format.
- Org admins can purge an environment's old values on its **History** tab, with their passkey: every value but each secret's current one, including those of deleted secrets. The rows keep who changed what and when, and `sigillo audit verify` still finds the history intact.
