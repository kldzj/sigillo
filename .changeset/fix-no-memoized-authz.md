---
'sigillo-app': patch
---

Make removing a member or restricting an environment take effect immediately.

On instances with a custom domain, organization membership and environment settings were cached for up to 15 minutes. A removed member could keep using the organization, and members could keep reading an environment an admin had just made admin-only, until the cache expired. These lookups are no longer cached.

Fixes #14
