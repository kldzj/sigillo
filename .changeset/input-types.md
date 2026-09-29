---
'@kldzj/sigillo': patch
'sigillo-app': patch
---

Check the types of every server action's and API handler's arguments before they reach a database query, so a client value can only ever be looked up by its exact id. This release fixes a security issue: update your instance with `npx @kldzj/sigillo@latest self-host`.
