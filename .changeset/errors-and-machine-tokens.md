---
'sigillo-app': patch
---

- A page or button that fails in the database no longer shows the query's SQL, its parameters or a stack trace: it says something went wrong, or that the thing already exists.
- Making a machine token always takes the admin's passkey, also before the organization has a protected environment. Otherwise a stolen admin session could leave one behind that reads environments protected later.
- The instance and its login provider tell browsers to use https only.
