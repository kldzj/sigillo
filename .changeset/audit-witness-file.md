---
'@kldzj/sigillo': patch
---

`sigillo audit verify` writes `~/.sigillo/audit.json` to a new file and renames it into place, so a crash or two checks at once can't leave it half written.
