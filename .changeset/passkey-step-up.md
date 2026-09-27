---
'sigillo-app': minor
'@kldzj/sigillo': minor
---

Reading a protected environment now takes a passkey. A stolen browser session or CLI login alone can no longer read production.

- **Passkeys.** Add them under **user menu → Passkeys**. The first one needs a sign-in from the last 5 minutes, and every further one an approval with a passkey you already have. Org admins see on the **Access** tab how many passkeys each member has and every passkey added or removed, and can reset a member's passkeys.
- **In the browser**, revealing, copying or downloading a value of a protected environment asks for your passkey on the spot. One approval covers that browser for 15 minutes.
- **In the CLI**, `sigillo run`, `secrets`, `secrets get` and `secrets download` print a link and a code, and wait while you approve on `/approve` with your passkey:

  ```
  This environment is protected: approve the read with your passkey.
    Open https://secrets.acme.com/approve and enter BCDF-GHJK
  Waiting for your approval...
  ✔ Approved for 15 minutes
  ```

- Turning protection off takes a passkey too, so a stolen admin session can't switch it off and read.
- **Machine tokens** read protected environments without a passkey, for CI and servers. Only an org admin creates one, with their passkey, and it expires after 90 days at most. Other API tokens can't read protected environments.
- The **Tokens** tab shows the IP each token was last used from.
- `npx @kldzj/sigillo self-host --reset-passkeys <email>` removes a user's passkeys, for a sole admin who lost theirs.
