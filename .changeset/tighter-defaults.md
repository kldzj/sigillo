---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

- No page of an instance or its login provider can be embedded in another site, so nobody can frame `/device` or `/approve` and have you click through them unseen. Responses are never cached, so values and names don't stay in the browser's cache.
- The API refuses a change sent with your browser's session from a page on another origin. The CLI and scripts are unaffected.
- better-auth endpoints the app never uses are off, so nobody can rename themselves to appear under someone else's name in the logs, and a member's picture no longer tells its host who looked at the **Access** tab.
- An API token acts with its creator's current access: it stops working when they're taken off the sign-in list, or can no longer open its project.
- Someone removed from an organization that auto-joins their email domain stays removed: auto-join used to add them back on their next page load. An invitation still brings them back.
- A demoted admin's invite links stop working, as a removed member's already did.
- A secret whose value starts with a byte order mark keeps it, and no longer breaks the environment's history for good. Values and names that aren't valid text are refused.
- Pages name who made a change as its history row does, and the event log marks a change that isn't part of the signed history.
- Changes from before the signed history joined it as "adopted" rows, and `sigillo audit verify` counts them. Someone with the database could clear a chain's row numbers and have the next write sign it again, with a row of their own inside; the head `audit verify` saved now no longer matches then. The Hardening page says what the history can't prove: rows no check has seen yet.
- One approval to add a passkey adds exactly one, even when two registrations race.
- The event log and read log links of a project no longer name its environments to someone who can't open it.
- `sigillo run` skips a secret named like a variable that controls how programs run, such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD` or `BASH_ENV`, and says so: anyone who can change the environment's secrets could otherwise run code on your machine. Pass `--allow-env NAME` to use one.
- `sigillo run` masks a secret that contains another one, such as a database URL with its password, even when the program's output arrives in pieces between them.
- `sigillo login` no longer replaces the server saved for a scope with one that came from `SIGILLO_API_URL` (which a repository's `.envrc` can set): that takes `--api-url`. Saving makes `~/.sigillo/config.json` readable only by you, also when an older copy wasn't.
- `sigillo login` opens only a plain web address from the server, and on Windows no longer through `cmd.exe`. Names and codes from the server print without terminal control characters.
- `sigillo audit verify` remembers what it saw by the project and environment you asked for, not by the id the server answers with.
