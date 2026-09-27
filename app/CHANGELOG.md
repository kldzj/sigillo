# Changelog

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
