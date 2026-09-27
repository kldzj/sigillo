---
'sigillo': patch
---

`npx sigillo self-host` now exits with status 1 when the deploy fails. It used to print the error and still exit 0, so a CI job running `CLOUDFLARE_API_TOKEN=xxx npx sigillo self-host --yes` passed even when nothing was deployed.
