---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

The **Sessions** page no longer fails for logins older than a day. better-auth 1.7.6 only lists sessions for a login from the last day, so the page now asks you to sign in again and brings you back to it. **End all other sessions** works right away, without signing in again. Run `npx @kldzj/sigillo self-host` to update your instance.
