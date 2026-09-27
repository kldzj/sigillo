---
'sigillo': patch
---

The CLI never sends your saved token to another server, and `run --mount` is safer.

- If `SIGILLO_API_URL` or `--api-url` points somewhere other than the server the token was saved for, the token is withheld with a warning. `--token` and `SIGILLO_TOKEN` still work as given.
- Authenticated requests no longer follow redirects. Point `--api-url` at the final URL, for example `https://`.
- `run --mount` creates the file owner-only (`0600`), refuses to overwrite an existing file or follow a symlink, and deletes it even when sigillo gets `SIGTERM` or `SIGHUP`. These signals are forwarded to the child instead of killing sigillo.
