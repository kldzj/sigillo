---
'sigillo-app': minor
---

Limit who can sign in with `ALLOWED_USERS`, a comma-separated list of email addresses and domains.

- Nobody else can sign up or sign in, in the browser or with the CLI. A signed-in user taken off the list is signed out on their next request.
- Only verified emails match, and a domain matches exactly, not its subdomains. Without `ALLOWED_USERS`, anyone can sign in as before.
- A refused sign-in lands on the login page with an explanation. Other sign-in errors land there too, instead of on a bare error page.
