---
'@kldzj/sigillo': patch
'sigillo-app': patch
---

Safer worker recreation in `self-host`, and two dashboard fixes.

- When `self-host` creates a new worker for a database that already stores secrets, it now checks that the keys decrypt a stored value first, with the key ring after a rotation. Before, a hand-added `ENCRYPTION_KEY` missing from `~/.sigillo/selfhost.json` made every stored secret unreadable. If you set your own key, pass it again to recover:

  ```bash
  SIGILLO_ENCRYPTION_KEY='<original key>' npx @kldzj/sigillo self-host
  ```

- The **Manage access** dialog could open with **Full access** checked for a restricted member, so saving without changes removed the restriction.
- The device login page returns to code entry when Approve or Deny fails, so you can enter the new code.
