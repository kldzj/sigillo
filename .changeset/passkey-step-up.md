---
'sigillo-app': minor
'@kldzj/sigillo': minor
---

Reading or changing a protected environment now takes a passkey, and so do admin actions in an organization that has one. A stolen browser session or CLI login alone can no longer read production, change it, or invite someone.

- **Passkeys.** Add them under **user menu → Passkeys**. The first one needs a Google sign-in from the last 5 minutes; adding or removing one after that needs an approval with a passkey you already have. Org admins see on the **Access** tab how many passkeys each member has and every passkey added or removed, and can reset a member's passkeys, which signs them out.
- **In the browser**, revealing, copying, downloading, saving or deleting a value of a protected environment asks for your passkey on the spot. One approval covers that browser for 15 minutes.
- **In the CLI**, reads such as `sigillo run` and `secrets get`, and changes such as `secrets set`, print a link and a code, and wait while you approve on `/approve` with your passkey:

  ```
  This environment is protected: approve with your passkey.
    Open https://secrets.acme.com/approve and enter BCDF-GHJK
  Waiting for your approval...
  ✔ Approved for 15 minutes
  ```

- Deleting or renaming a protected environment, or its project, takes a passkey too.
- **Admin actions** in an organization with a protected environment take a passkey, covering 5 minutes: invites, roles, a member's projects, removing members, auto-join, an environment's min role or protection, resetting passkeys, machine tokens and deleting the organization.
- **Machine tokens** read and change protected environments without a passkey, for CI and servers. Only an org admin creates one, it expires after 90 days at most, and it stops working when its creator is no longer an admin. Other API tokens can't use protected environments.
- The **Tokens** tab shows the IP each token was last used from, to the hour.
- `npx @kldzj/sigillo self-host --reset-passkeys <email>` removes a user's passkeys and signs them out, for a sole admin who lost theirs.
