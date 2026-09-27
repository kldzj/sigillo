---
'sigillo-app': minor
---

API tokens expire, and the token list shows when each one was last used.

- A new token lasts 7, 30, 90 or 365 days, 90 by default. An expired token gets `401 API token expired`.
- Tokens made before this never expire. The token list marks them as **Never**, so they can be replaced.
- Last use is recorded at most once an hour, so a busy CI token does not cost a database write per request.
