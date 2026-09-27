---
'sigillo-app': patch
---

`.env` downloads can no longer run shell commands, and secret names are validated.

Values are now single-quoted, so `source .env` does not expand `$(…)`, backticks or `$VAR`:

```sh
SUBSHELL='$(touch /tmp/pwned)'
QUOTE="it's"
```

New and renamed secrets must match `^[A-Za-z_][A-Za-z0-9_]*$`. Names that could inject extra lines are dropped from env, docker and yaml downloads. The web **Download .env** button uses the same safe format.
