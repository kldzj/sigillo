---
'sigillo-app': minor
'@kldzj/sigillo': minor
---

Protected environments and a tamper-evident history.

- **Protected** (Environments tab, admins) records every read of an environment's values: who, when, which secrets, how (revealed, old value in the event log, listed, downloaded, copied) and from which IP. Admins see it on the new **Read Log** tab. The read is recorded before any value leaves the server, and fails if it can't be. Turning protection off is recorded too.
- The secrets page and the event log load a value only when you reveal it, download or copy it, so opening a page no longer sends any values to the browser.
- Each environment's secret changes and reads form hash chains signed by the server, so editing, removing or adding a row in the database shows up.
- `sigillo audit verify` checks both chains of an environment and remembers their heads in `~/.sigillo/audit.json`, so rows removed since the last check show up too:

```bash
$ sigillo audit verify -c prod
✔ changes: 42 rows, intact
✔ reads: 7 rows, intact
```
