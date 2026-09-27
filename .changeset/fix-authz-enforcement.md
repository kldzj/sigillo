---
'sigillo-app': patch
---

Enforce project access and admin-only environments everywhere, not only on the secrets API.

Project scoping and admin-only environments were only checked by the REST secrets routes. Everything else only checked that you belong to the organization, so a member limited to one project, or a member who is not an admin, could:

- list, rename or delete another project's environments, including an admin-only production environment and all of its secrets
- read and change admin-only secrets in the web UI (secrets page, event log, save to several environments, sync missing secrets)
- create an API token for an admin-only environment, or a project-wide one, and read production secrets with it

All of these now follow the same rule as the secrets API: you need access to the project, and admin rights for an admin-only environment. Creating or revoking an API token needs access to every environment the token can read. Deleting a project that contains an admin-only environment needs an admin.

This also fixes two ways a restricted member silently became unrestricted. Accepting a project-scoped invitation whose projects were deleted is now refused. An error while changing a member's project access now keeps the old rules instead of removing them.

Fixes #12
