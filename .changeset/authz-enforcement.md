---
'sigillo-app': patch
---

Project access and admin-only environments are enforced everywhere, and take effect immediately.

Before, only the REST secrets routes checked them. Now these check them too:

- the secrets page and the event log (a member sees a locked page for an admin-only environment, no values)
- saving to several environments, deleting secrets, and syncing missing secrets
- creating, renaming and deleting environments, and deleting a project that holds an admin-only environment
- creating and revoking API tokens (you need access to every environment the token covers)
- using an API token on an admin-only environment (its creator must still be an org admin)

Membership and environment lookups are no longer cached, so removing a member or making an environment admin-only applies on the next request, not up to 15 minutes later.

Accepting a project-scoped invitation whose projects were deleted is now refused, and a failed project-access update keeps the old rules. Both used to leave the member with access to every project.

Fixes #12
Fixes #14
