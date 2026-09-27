---
'sigillo-app': patch
---

Deleting an API token or a user no longer deletes the secrets they wrote.

Secret history used `ON DELETE CASCADE` on its author columns. A secret's value is a replay of its history, so deleting a token deleted every secret it wrote and reverted the ones it had overwritten. Authors are now set to null instead, and the event log shows `—`.

Fixes #10
