---
'@kldzj/sigillo': patch
'sigillo-app': patch
---

This release fixes security issues. Update your instance with `npx @kldzj/sigillo@latest self-host`, and the CLI with `npm i -g @kldzj/sigillo@latest` where you installed it.

- The web UI's actions, and making or regenerating a token, take a browser you signed in to with Google. A CLI login can't call them; the CLI keeps using the REST API. A browser login from before sign-ins were told apart needs signing in again.
- An approval with your passkey for an admin action covers that one action, which uses it up. The browser now asks for your passkey for each admin action, each token you make or regenerate once you have a passkey, and each CLI login you approve. Access to a protected environment still lasts 15 minutes.
- Adding a further passkey takes an approval to add one: the Passkeys page shows a code to enter on `/approve` in a browser with one of your passkeys, this one or another device. An approval for anything else no longer adds a passkey.
- `sigillo run` never sets `SIGILLO_*` variables from secrets, not even with `--allow-env`, and skips secrets whose names aren't variable names. It also skips `CC`, `CXX`, `CPP`, `LD`, `MAKEFLAGS`, `MAKEFILES`, `RUSTC_WRAPPER`, `GRADLE_OPTS`, `JAVA_OPTS`, `MAVEN_OPTS` and names ending in `PAGER`, unless `--allow-env` names them.
- When `SIGILLO_API_URL` or `--api-url` names another server than the one a saved login is for, the CLI doesn't exchange a workload's JWT with it either.
- The CLI names this fork's package when it says how to run `self-host`: `npx @kldzj/sigillo self-host`.
