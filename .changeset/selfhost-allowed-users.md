---
'@kldzj/sigillo': minor
---

`self-host --allowed-users` limits who can sign in to your instance.

```bash
npx @kldzj/sigillo self-host --allowed-users acme.com,ops@partner.io
```

- A new deployment asks for the list. The app and its login provider both enforce it.
- Updates keep the saved list. Pass the flag again to change it, or `--allowed-users ''` to let anyone in.
- `self-host` warns when anyone with a Google account can sign in.
