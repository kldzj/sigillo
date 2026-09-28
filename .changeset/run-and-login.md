---
'@kldzj/sigillo': patch
---

- `sigillo run` matches the names it skips in any case, as Windows does, so a secret named `node_options` or `Path` is skipped too. It also skips `PS4`, pagers and editors such as `GIT_PAGER` and `EDITOR`, `GIT_EXTERNAL_DIFF`, `LESSOPEN`, every `npm_config_*` setting, package sources such as `PIP_INDEX_URL`, `GOPROXY` or `YARN_NPM_REGISTRY_SERVER`, and `NODE_TLS_REJECT_UNAUTHORIZED`. No such list is complete: it catches the names known to change how programs run.
- `sigillo login` says which account it logged in as, and how to log out if that isn't you: whoever enters a login code first approves it.
- Error messages and names from the server print without terminal control characters, including the project name `sigillo setup` saves.
