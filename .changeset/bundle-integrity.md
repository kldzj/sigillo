---
'@kldzj/sigillo': minor
---

`self-host` deploys the release of its own version, and only the exact bundle that version was released with: CI records the bundle's SHA-256 in the npm package, and `self-host` refuses anything else, from GitHub, `--release-url` or `--bundle` alike. It also refuses to deploy a version older than the one the instance runs, unless you pass `--allow-downgrade`. Run `npx @kldzj/sigillo@latest self-host` to update to the newest release, as before.
