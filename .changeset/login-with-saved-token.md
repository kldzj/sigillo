---
'@kldzj/sigillo': patch
---

`sigillo login` signs in again when a token is already saved. It used to re-save the saved token and stop, so a login that had stopped working could only be replaced after `sigillo logout`. `--token` and `SIGILLO_TOKEN` are still saved as given.
