---
'sigillo-app': patch
---

Deleting a project no longer unlocks every project for members limited to it, and secret names from other environments no longer leak.

- A member limited to some projects used to get access to **every** project when their last allowed project was deleted. Restriction is now stored on the membership, so it stays in place, with access to no projects.
- The secrets list returned `allNames` from every environment in the project. A member now only gets names from environments they can read, and an environment-scoped token only gets names from its own environments.
