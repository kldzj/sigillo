# Changelog

## 0.4.1

### Patch Changes

- 0e3998e: Check the types of every server action's and API handler's arguments before they reach a database query, so a client value can only ever be looked up by its exact id. This release fixes security issues: update your instance with `npx @kldzj/sigillo@latest self-host`.
- da53509: More checks on sign-out, deletes and approvals:

  - The login provider's sign-out sends the browser only back to its own app, never to an address a registered client names.
  - Deleting a secret takes only a name the set routes accept, or the name of a secret that already has one from before names had rules.
  - Only a login from signing in with Google approves or denies a CLI login: a CLI login can no longer approve the next one. A browser login from before sign-ins were told apart needs signing in again for it.
  - A passkey approval looks a passkey up only by an id that is a string.

## 0.4.0

### Minor Changes

- 1aeca5c: Encryption v2, and purging old values:

  - Every stored value is bound to its environment and name, and names the key it was encrypted with. A value copied elsewhere in the database no longer decrypts. Values from before stay readable, and a key rotation moves them to the new format.
  - Org admins can purge an environment's old values on its **History** tab, with their passkey: every value but each secret's current one, including those of deleted secrets. The rows keep who changed what and when, and `sigillo audit verify` still finds the history intact.

- 3832cb3: A project's tabs are now Secrets, Environments, Machines, History and Settings:

  - **Members**, the organization's list of people with their roles, project access and passkeys, leaves every project's tabs for the sidebar, at `/dash/orgs/<org>/members`. It always was the whole organization's list.
  - **Machines**, formerly Tokens, holds API tokens, machine tokens and workload identities.
  - **History** replaces Event Log and Read Log, with a Changes | Reads switch, at `…/envs/<environment>/history`. The old `/event-log` URL matched EasyPrivacy's rule `/event-log?`, on by default in uBlock Origin Lite and other blockers, which broke switching to the tab, revealing old values and purging them.

- 8c79bf0: Tokens and trust rules are renewed in place, and warn before they expire:

  - **Regenerate a token** on a project's **Machines** tab: a new value and a new expiry for the same token, so its name, scope and history stay. Its creator or an org admin does it, with a passkey once they have one; a machine token takes an org admin with their passkey and lasts 90 days at most. The previous value keeps working for 0, 1 or 7 days, never past its own expiry, and the tab shows until when and whether it is still used, with a **Stop** link to end it early. A token that never expired gets an expiry this way.
  - **Renew a trust rule** on the same tab: a new expiry for the same rule, so External Secrets Operator and CI keep its ID. The renewal dialog first shows how the rule was used, which workloads got its tokens, and what looks stale. The admin who renews it owns it from then on, an expired rule can be renewed too, and keys from its issuer are fetched again.
  - **Warnings** start when a quarter of a token's or rule's lifetime is left, 14 days at most: an Expires badge on the Machines tab, a banner on every dashboard page (dismissed for a day), and on API answers the headers `Sigillo-Token-Expires` and `Sigillo-Warning`. `sigillo` prints that warning once per command, on stderr, so it shows in CI logs without touching a download:

    ```
    warning: this API token expires on 2026-10-13 (in 3 days). Regenerate it on the project's Machines tab; the old value then keeps working for up to 7 days.
    ```

  - The workload token exchange answers with its rule's `ruleId` and `ruleExpiresAt` too.
  - Token names can't contain control characters, like other names.
  - Each change to tokens, trust rules, protection, members and passkeys is written to a security log in the same database batch, for notifications in a later release.

- 54af465: Workload identity: GitHub Actions jobs and Kubernetes pods read secrets without a stored token. An org admin adds a trust rule on a project's **Machines** tab, with their passkey: the issuer, the audience, the exact subject and claims, and the environments it grants. A workload exchanges the JWT its platform issues at `POST /api/v0/workload/token` for a token of one hour. `sigillo` does that on its own when no token is set, from `SIGILLO_OIDC_TOKEN_FILE`, `SIGILLO_OIDC_TOKEN` or GitHub Actions' ID token, with the project named by its ID. External Secrets Operator's Doppler provider works against Sigillo too, with its controller's `DOPPLER_BASE_URL` set to the instance. Rules for protected environments follow the rules of machine tokens, and the read log names the job or pod behind each read.

### Patch Changes

- bf57037: Stricter history checks and safer self-hosting:

  - A value removed from the database without a purge now breaks the history: `sigillo audit verify` and a restore report it, and the **History** tab shows it as "value removed without a purge". Before, a value erased with its digest kept looked like a purged one.
  - Exporting a protected environment's history, as `sigillo audit verify` does, takes a passkey approval and shows in its read log, since the export shows whether a value was set back to an earlier one.
  - Environment pages no longer tell someone who can't open the project the slug of its first environment.
  - The Worker refuses an `ENCRYPTION_KEY` that isn't 32 bytes. Keys made by `self-host` always are; a shorter key set by hand in the dashboard stops the instance until it is replaced.
  - `self-host --rotate-key` gives the Worker its key ring again when it finishes an unfinished rotation, and the check before recreating a worker tries a value under every key in use.
  - `self-host --restore` needs `--yes` without a terminal, says exactly what it checked, compares the history with what `sigillo audit verify` saw on your machine, and stays unfinished until both workers use the restored databases: `--backup`, `--rotate-key` and `--reset-passkeys` wait for it. Backups no longer hold sign-in ID tokens, and `self-host` no longer drops the backup key when it updates a deployment.

- 53657f3: Safer worker recreation in `self-host`, and two dashboard fixes.

  - When `self-host` creates a new worker for a database that already stores secrets, it now checks that the keys decrypt a stored value first, with the key ring after a rotation. Before, a hand-added `ENCRYPTION_KEY` missing from `~/.sigillo/selfhost.json` made every stored secret unreadable. If you set your own key, pass it again to recover:

    ```bash
    SIGILLO_ENCRYPTION_KEY='<original key>' npx @kldzj/sigillo self-host
    ```

  - The **Manage access** dialog could open with **Full access** checked for a restricted member, so saving without changes removed the restriction.
  - The device login page returns to code entry when Approve or Deny fails, so you can enter the new code.

- e5eba03: The docs no longer promise that Sigillo fits Cloudflare's free plan without a hitch: a dashboard page often takes 10 to 40 ms of CPU, more than the free plan's 10 ms, so on the free plan a page fails now and then with error 1102. Workers Paid, $5 a month, avoids that. `self-host` says so at the end of a new deployment.

## 0.3.0

### Minor Changes

- b2f7a51: Instances no longer serve the landing page and docs: `/` opens the dashboard, or the sign-in page when you're signed out. The docs moved to [sigillo.kldzj.dev](https://sigillo.kldzj.dev), and the navbar links there. Every page of an instance now asks search engines not to list it.
- 78c1955: Reading or changing a protected environment now takes a passkey, and so do admin actions in an organization that has one. A stolen browser session or CLI login alone can no longer read production, change it, or invite someone.

  - **Passkeys.** Add them under **user menu → Passkeys**. The first one needs a Google sign-in from the last 5 minutes. Once your organization has an admin with a passkey, an admin also approves it on the **Access** tab, and a member of several organizations with protected environments needs an approval from each. Adding or removing one after that needs an approval with a passkey you already have: in the same browser, or for a new device such as your phone, with a code you type on `/approve` where you have one. Org admins see on the **Access** tab how many passkeys each member has and every passkey added or removed, and can reset a member's passkeys, which signs them out.
  - **In the browser**, revealing, copying, downloading, saving or deleting a value of a protected environment asks for your passkey on the spot. One approval covers that browser for 15 minutes.
  - **In the CLI**, reads such as `sigillo run` and `secrets get`, and changes such as `secrets set`, print a link and a code, and wait while you approve on `/approve` with your passkey:

    ```
    This environment is protected: approve with your passkey.
      Open https://secrets.acme.com/approve and enter BCDF-GHJK
    Waiting for your approval...
    ✔ Approved for 15 minutes
    ```

  - Deleting or renaming a protected environment, or its project, is up to an org admin with their passkey.
  - Once you have a passkey, approving a CLI login on `/device` and creating an API token take it too, since both outlive the session that makes them.
  - `sigillo login` opens the login page without the code, and you type the code it shows; the page no longer takes a code from a link.
  - **Admin actions** in an organization with a protected environment take a passkey, covering 5 minutes: invites, roles, a member's projects, removing members, auto-join, an environment's min role or protection, resetting passkeys, machine tokens and deleting the organization.
  - **Machine tokens** read and change protected environments without a passkey, for CI and servers. Only an org admin creates one, with their passkey. It expires after 90 days at most, and it stops working when its creator is no longer an admin. Other API tokens can't use protected environments.
  - The **Tokens** tab shows the IP each token was last used from, to the hour.
  - `npx @kldzj/sigillo self-host --reset-passkeys <email>` removes a user's passkeys and signs them out, for a sole admin who lost theirs.

### Patch Changes

- 3277c43: The CLI banner on the secrets page now shows `npm install -g @kldzj/sigillo` and `sigillo login --api-url` with your instance's URL. It used to show upstream's package and a `sigillo login` without an instance, which fails.
- 1610a22: Login and approval codes read `XXXX-XXXX` everywhere. `sigillo login` prints its code with the dash, and the code fields on `/device` and `/approve` add it while you type or paste, so a code works with or without it.
- f5ef6f3: Anyone can now leave an organization under **Organization settings** in the sidebar. Auto-join doesn't add them back, and neither does an invite link made before they left: only a new one does. The last admin can't leave. Someone who left or was removed still needs that organization's approval for a first passkey, and its admins see the request on the **Access** tab.

- 851705b: Errors, machine tokens and https:

  - A page or button that fails in the database no longer shows the query's SQL, its parameters or a stack trace: it says something went wrong, or that the thing already exists.
  - Making a machine token always takes the admin's passkey, also before the organization has a protected environment. Otherwise a stolen admin session could leave one behind that reads environments protected later.
  - The instance and its login provider tell browsers to use https only.

- f5ef6f3: Tighter sign-ins, slugs and tokens:

  - Sign-in and login endpoints of the app and its login provider are rate limited per IP, counted in D1. Looking up CLI login codes allows 30 tries per 10 minutes from one address, registering new clients with the provider 10 an hour.
  - A browser or CLI login ends 30 days after its sign-in, however often it's used. It used to renew itself for as long as it was used, so a stolen one in daily use never ended.
  - A link to `/logout` on another site no longer signs you out on its own: it shows a page that asks first.
  - A new or renamed environment's slug is lowercase letters, digits and dashes. Existing slugs keep working.
  - Only a token's creator or an org admin can delete it; the **Tokens** tab shows the delete button only to them. Any member could delete a colleague's CI token before.

- 8b36d4d: On a phone, the organization and user menus in the navigation drawer work again: tapping Sessions, Passkeys or Add organization used to close the menu without going there.
- 0267b89: The login provider shows its consent screen the first time an app asks. It used to skip it for any client whose redirect address was on a host derived from its own, and anyone can register a client. Its error page links back only to your instance's login, and none of its pages are indexed or cached.
- 31e37e3: Each project remembers the environment you last opened. The Secrets, Event Log and Read Log tabs and the project links in the sidebar return to it instead of the first environment, so checking a protected environment's log no longer lands you in `dev` by accident.
- f622044: Members who can open only some projects, names and CLI logins:

  - A member who can open only some projects no longer ends up in a redirect loop when their newest organization has none of theirs: the dashboard opens the newest project they can open, or says to ask an admin for access.
  - Such a member no longer learns the names of projects they can't open, on the organization's settings or on the **Access** tab.
  - Names of organizations, projects and environments can't contain control characters, which could rewrite a terminal that shows them.
  - A CLI login's device code is stored as a hash, so one read out of the database during a login can't be exchanged for the session.

- 40f217a: The **Sessions** page no longer fails for logins older than a day. better-auth 1.7.6 only lists sessions for a login from the last day, so the page now asks you to sign in again and brings you back to it. **End all other sessions** works right away, without signing in again. Run `npx @kldzj/sigillo self-host` to update your instance.
- e2e0aa4: Tables fit their columns again: IPv6 addresses on the Sessions page and in the Read Log are written short (`2a01:4f8:c17:6611::`, the full value on hover), and the Min Role and Protected selects on the Environments tab no longer overlap the next column. Select lists are readable in dark mode.
- 20f6b6a: Security fixes and tighter defaults:

  - No page of an instance or its login provider can be embedded in another site, so nobody can frame `/device` or `/approve` and have you click through them unseen. Responses are never cached, so values and names don't stay in the browser's cache.
  - The API refuses a change sent with your browser's session from a page on another origin. The CLI and scripts are unaffected.
  - better-auth endpoints the app never uses are off, so nobody can rename themselves to appear under someone else's name in the logs, and a member's picture no longer tells its host who looked at the **Access** tab.
  - An API token acts with its creator's current access: it stops working when they're taken off the sign-in list, or can no longer open its project.
  - Someone removed from an organization that auto-joins their email domain stays removed: auto-join used to add them back on their next page load. An invitation still brings them back.
  - A demoted admin's invite links stop working, as a removed member's already did.
  - A secret whose value starts with a byte order mark keeps it, and no longer breaks the environment's history for good. Values and names that aren't valid text are refused.
  - Pages name who made a change as its history row does, and the event log marks a change that isn't part of the signed history.
  - Changes from before the signed history joined it as "adopted" rows, and `sigillo audit verify` counts them. Someone with the database could clear a chain's row numbers and have the next write sign it again, with a row of their own inside; the head `audit verify` saved now no longer matches then. The Hardening page says what the history can't prove: rows no check has seen yet.
  - The event log and read log links of a project no longer name its environments to someone who can't open it.
  - `sigillo run` skips a secret named like a variable that controls how programs run, such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD` or `BASH_ENV`, and says so: anyone who can change the environment's secrets could otherwise run code on your machine. Pass `--allow-env NAME` to use one.
  - `sigillo run` masks a secret that contains another one, such as a database URL with its password, even when the program's output arrives in pieces between them.
  - `sigillo login` no longer replaces the server saved for a scope with one that came from `SIGILLO_API_URL` (which a repository's `.envrc` can set): that takes `--api-url`. Saving makes `~/.sigillo/config.json` readable only by you, also when an older copy wasn't.
  - `sigillo login` opens only a plain web address from the server, and on Windows no longer through `cmd.exe`. Names and codes from the server print without terminal control characters.
  - `sigillo audit verify` remembers what it saw by the project and environment you asked for, not by the id the server answers with.

- be49508: Deleting something that can't come back now takes its name, typed out:

  - **An organization's settings** moved out of the project tabs into the sidebar, under **Organization settings**: auto-join, leaving it and deleting it. The project's **Settings** tab now renames or deletes that project.
  - **Deleting an organization** lists its projects and how many environments and secrets go with them, and asks for the organization's name. **Deleting a project** asks for its name the same way.
  - **Deleting an environment** with secrets asks for its slug and says how many secrets go with it. An empty one only asks.
  - `sigillo projects delete` and `sigillo environments delete` ask you to type the project's name or the environment's slug. Without a terminal they take `--yes`.

- 0166456: The docs site has a new home page with an ASCII video hero and a compact layout. Selects in the dashboard size to their content.

## 0.2.0

### Minor Changes

- 037d5ce: API tokens expire, and the token list shows when each one was last used.

  - A new token lasts 7, 30, 90 or 365 days, 90 by default. An expired token gets `401 API token expired`.
  - Tokens made before this never expire. The token list marks them as **Never**, so they can be replaced.
  - Last use is recorded at most once an hour, so a busy CI token does not cost a database write per request.

- 940d20d: Protected environments and a tamper-evident history.

  - **Protected** (Environments tab, admins) records every read of an environment's values: who, when, which secrets, how (revealed, old value in the event log, listed, downloaded, copied) and from which IP. Admins see it on the new **Read Log** tab. The read is recorded before any value leaves the server, and fails if it can't be. Turning protection off is recorded too.
  - The secrets page and the event log load a value only when you reveal it, download or copy it, so opening a page no longer sends any values to the browser.
  - Each environment's secret changes and reads form hash chains signed by the server, so editing, removing or adding a row in the database shows up.
  - `sigillo audit verify` checks both chains of an environment and remembers their heads in `~/.sigillo/audit.json`, so rows removed since the last check show up too:

  ```bash
  $ sigillo audit verify -c prod
  ✔ changes: 42 rows, intact
  ✔ reads: 7 rows, intact
  ```

- e27d1e5: New **Sessions** page (user menu → Sessions) that lists every browser and CLI login signed in as you, with its device, IP address and sign-in time. End one you don't recognize, or all but the current one.

  An ended session stops working on its next request. The session cookie cache is off for that, so each request checks the session in D1. New sessions record the client IP from `cf-connecting-ip`. CLI logins show as **Sigillo CLI** with their version; ones from older CLIs show as `zig/0.15.2`.

- 4105d93: Limit who can sign in with `ALLOWED_USERS`, a comma-separated list of email addresses and domains.

  - Nobody else can sign up or sign in, in the browser or with the CLI. A signed-in user taken off the list is signed out on their next request.
  - Only verified emails match, and a domain matches exactly, not its subdomains. Without `ALLOWED_USERS`, anyone can sign in as before.
  - A refused sign-in lands on the login page with an explanation. Other sign-in errors land there too, instead of on a bare error page.

### Patch Changes

- 6c44802: The app and its login provider run on the stable `better-auth` 1.7.6 instead of `1.7.0-beta.4`. The provider gets migration `0003` for the new columns and tables of `@better-auth/oauth-provider` 1.7.6, and local development registers its `http://localhost` callback as a native OAuth client, which 1.7.6 requires.
- 10b4428: New docs page **Hardening**: who can reach the secrets on a self-hosted instance, and the steps that narrow it, from a dedicated Cloudflare account and the deploy file to sign-in, access inside the app, the read log and `sigillo audit verify`, and what to do when someone leaves.
- 6b425ce: A session token copied out of the database no longer signs anyone in.

  - Bearer tokens must carry the signature that only the Worker's `BETTER_AUTH_SECRET` can make, as the session cookie already does, and `sigillo login` now receives such a signed token. **CLI logins from before this update stop working: run `sigillo login` once.**
  - The OAuth tokens that the app and its login provider store are encrypted in D1.
  - Neither the app nor the provider signs anyone in with a raw `id_token` any more. Both stored the last one in D1 as is, so it could be replayed while still valid. Signing in always goes through the redirect.
  - A request without a valid session gets `not signed in, or the session expired: run sigillo login` instead of `unauthorized`.

## 0.1.0

### Minor Changes

- 7b96c4f: API tokens can now cover more than one environment.

  Create a token for **dev** and **preview** without also granting **prod**. Project-wide tokens still mean every environment. The CLI setup picker only lists the environments the token can use.

  Fixes remorses/sigillo#7

### Patch Changes

- 904fad4: An API token used on an admin-only environment now needs its creator to still be an org admin, so demoting someone also stops their tokens from reading admin-only environments.
- dbd5d25: Device login needs an explicit **Approve**.

  `/device?user_code=…` used to approve the code in one click, so a link sent by someone else could sign them in as you. The page now checks the code, then shows a warning with **Approve** and **Deny** buttons.

- 9a975e3: Deleting a project no longer unlocks every project for members limited to it, and secret names from other environments no longer leak.

  - A member limited to some projects used to get access to **every** project when their last allowed project was deleted. Restriction is now stored on the membership, so it stays in place, with access to no projects.
  - The secrets list returned `allNames` from every environment in the project. A member now only gets names from environments they can read, and an environment-scoped token only gets names from its own environments.

- 904fad4: `.env` downloads can no longer run shell commands, and secret names are validated.

  Values are now single-quoted, so `source .env` does not expand `$(…)`, backticks or `$VAR`:

  ```sh
  SUBSHELL='$(touch /tmp/pwned)'
  QUOTE="it's"
  ```

  New and renamed secrets must match `^[A-Za-z_][A-Za-z0-9_]*$`. Names that could inject extra lines are dropped from env, docker and yaml downloads. The web **Download .env** button uses the same safe format.

## 0.0.3

### Patch Changes

- 8de9c27: `--project` now accepts a project name as well as its ID.

  ```bash
  sigillo run --project website --env dev -- npm start
  sigillo setup --project website --env dev
  ```

  Before, a name was sent to the API as if it were an ID, and the command failed with `env dev was not found in project website`. Now a value that isn't a project ID is looked up among the projects you can access. If no project has that name, the error says the project was not found and lists the ones you can use. If several projects share the name, it lists them so you can pick one by ID. `setup` saves the resolved ID, so renaming the project later doesn't break the directory's config.

  An unknown project ID is also reported as a missing project now, instead of as a missing env.

- 5e0582e: Enforce project access and admin-only environments everywhere, not only on the secrets API.

  Project scoping and admin-only environments were only checked by the REST secrets routes. Everything else only checked that you belong to the organization, so a member limited to one project, or a member who is not an admin, could:

  - list, rename or delete another project's environments, including an admin-only production environment and all of its secrets
  - read and change admin-only secrets in the web UI (secrets page, event log, save to several environments, sync missing secrets)
  - create an API token for an admin-only environment, or a project-wide one, and read production secrets with it

  All of these now follow the same rule as the secrets API: you need access to the project, and admin rights for an admin-only environment. Creating or revoking an API token needs access to every environment the token can read. Deleting a project that contains an admin-only environment needs an admin.

  This also fixes two ways a restricted member silently became unrestricted. Accepting a project-scoped invitation whose projects were deleted is now refused. An error while changing a member's project access now keeps the old rules instead of removing them.

  Fixes remorses/sigillo#12

- 9d62dad: Allow only one organization per auto-join email domain.

  Anyone with a verified company email could create a second organization with auto-join turned on for the same domain. Everyone from that company who opened the dashboard next was silently added to it, and the dashboard showed that organization first because it was the newest.

  The first organization to claim a domain now keeps it, and claiming a domain another organization already uses fails with an error. Migration `0007` clears duplicate claims, keeping the oldest organization's, and adds a unique index.

- 654dfe4: Removing a member now also revokes the API tokens and invite links they created in that organization.

  Tokens and invite links used to outlive the person who created them. A departed member's CI token kept reading secrets, and their invite links kept letting people join, until someone noticed and deleted them by hand.

  Secrets written with those tokens stay. If CI uses a token created by someone who is leaving, create a replacement token before removing them.

- abc32d6: Make removing a member or restricting an environment take effect immediately.

  On instances with a custom domain, organization membership and environment settings were cached for up to 15 minutes. A removed member could keep using the organization, and members could keep reading an environment an admin had just made admin-only, until the cache expired. These lookups are no longer cached.

  Fixes remorses/sigillo#14

- a7f0195: Fix changing a member role in the access table. Selecting Admin or Member now saves the new role instead of doing nothing.

  The same bug also blocked removing a member from the table.

  Fixes remorses/sigillo#5

- 72bae32: Stop deleting secrets when the API token or user that wrote them is deleted.

  Every secret value is stored as an event that records who wrote it, and those events were deleted together with their author. Revoking a CI token removed every secret it had set, and rolled secrets it had overwritten back to an older value, without any error. Deleting a user did the same.

  Revoking a token or deleting a user now keeps their secrets. The event log shows `—` as the author once the author is gone.

  Migration `0007` rebuilds the `secret_event` table. Self-hosted instances pick it up by re-running `npx @kldzj/sigillo self-host`.

  Fixes remorses/sigillo#10

- The CLI is now published as `@kldzj/sigillo` from [kldzj/sigillo](https://github.com/kldzj/sigillo), a maintained fork of Sigillo with no hosted service. The command is still `sigillo`.

  ```bash
  npm i -g @kldzj/sigillo
  npx @kldzj/sigillo self-host
  ```

  `self-host` downloads its release bundles from kldzj/sigillo's GitHub releases, and the install script and docs point there too.

- `npx @kldzj/sigillo self-host` now deploys each instance with its own login provider, instead of signing in through auth.sigillo.dev.

  The provider runs as a second Worker next to the app (`<name>-auth`) with its own D1 database, and people sign in with Google through it. A new deployment needs a Google OAuth client: self-host prints the redirect URI to register at Google Cloud and asks for the client ID and secret, or takes `--google-client-id` and `--google-client-secret`. The provider's secret and the Google client are saved in `~/.sigillo/selfhost.json` and never rotated on updates. The first sign-in to an instance asks once to allow it.

  A deployment that already signs in through another provider, such as one made with upstream Sigillo's self-host, keeps that provider on update, since a new one would give every user a new login.

- 76c9072: `npx @kldzj/sigillo self-host` now gives new deployments their own `ENCRYPTION_KEY`.

  Until now self-host only set `BETTER_AUTH_SECRET`, so the key that encrypts every stored secret was derived from the same secret that signs login sessions. New deployments now get a separate, random 32-byte `ENCRYPTION_KEY`. It is saved next to the auth secret in `~/.sigillo/selfhost.json`, so a worker recreated from that state keeps reading its data.

  Existing deployments are not changed: re-runs still never send or rotate secrets, and deployments made before this keep their derived key. If self-host finds a database that already stores secrets but neither its worker nor the saved state, it now stops and explains how to recover instead of starting over with new keys that would leave those secrets unreadable. The self-hosting docs now say to back up both secrets, since a database backup cannot be decrypted without the key.

  Fixes remorses/sigillo#18

## 0.0.2

1. **Let `sig_` API tokens read their own project metadata** so CLI token login can run `setup`.

   Before this, a token worked on secrets routes but `sigillo setup --project X --env dev` called `GET /api/v0/projects/X` and got **401**. User (device-flow) login was fine. Token login was not.

   A project-scoped token can now call the read routes the CLI uses after `sigillo login --token`:

   ```bash
   sigillo login --api-url https://secrets.example.com --token sig_xxxxx
   sigillo setup --project <project-id> --env dev
   sigillo me
   sigillo orgs
   sigillo environments get dev
   ```

   | Route                                         | Token can                                       |
   | --------------------------------------------- | ----------------------------------------------- |
   | `GET /api/v0/me`                              | yes. returns the token creator and that one org |
   | `GET /api/v0/orgs`                            | yes. that one org, role `member`                |
   | `GET /api/v0/projects`                        | yes. only the token project                     |
   | `GET /api/v0/projects/:id`                    | yes. **403** if a different project             |
   | `GET /api/v0/projects/:id/environments`       | yes                                             |
   | `GET /api/v0/projects/:id/environments/:id`   | yes. **403** if env-scoped to a different env   |
   | secrets routes                                | already worked                                  |
   | create / rename / delete orgs, projects, envs | still **401**                                   |

   Env-scoped tokens only see that environment in project payloads, so `setup --env prod` with a `dev` token fails early.

   Deleting a scoped environment now **revokes** the token (`ON DELETE CASCADE`). It used to `SET NULL`, which widened the token to every environment in the project. Self-hosted instances need migration `0006`.

   README curl examples now use `/api/v0/projects/{projectId}/environments/{environmentId}/secrets`. The old `/api/environments/{envId}/secrets` path does not exist.

   Fixes #4
