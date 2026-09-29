# Security policy

Report vulnerabilities **privately**, never in a public issue.

1. Open https://github.com/kldzj/sigillo/security/advisories/new
2. Describe the issue, the affected component (`app`, `provider`, `cli` or `self-host`) and how to reproduce it

This repository is a fork of [remorses/sigillo](https://github.com/remorses/sigillo) with no hosted service: every instance runs on its owner's Cloudflare account. In scope are the code here, the `@kldzj/sigillo` package, and instances deployed with it. Fixes ship in a new release, and self-hosters get them by running `npx @kldzj/sigillo self-host` again. Only the latest release gets fixes.

If the issue is in upstream's code too, say so in your report: fixes that suit both go upstream as well.

What Sigillo protects against, and what it doesn't, is in the [hardening guide](https://sigillo.kldzj.dev/docs/hardening).
