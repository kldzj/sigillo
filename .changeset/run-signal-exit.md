---
'@kldzj/sigillo': patch
---

`sigillo run` exits with `128 + N` when its command is killed by signal N. Before, a command stopped by `SIGTERM` or Ctrl+C made sigillo exit `1`, so Docker, turbo and make reported a failure. Now it exits `143` for `SIGTERM` and `130` for Ctrl+C.
