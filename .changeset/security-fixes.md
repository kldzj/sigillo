---
'sigillo-app': patch
---

More checks on sign-out, deletes and approvals:

- The login provider's sign-out sends the browser only back to its own app, never to an address a registered client names.
- Deleting a secret takes only a name the set routes accept, or the name of a secret that already has one from before names had rules.
- Only a login from signing in with Google approves or denies a CLI login: a CLI login can no longer approve the next one. A browser login from before sign-ins were told apart needs signing in again for it.
- A passkey approval looks a passkey up only by an id that is a string.
