---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

Deleting something that can't come back now takes its name, typed out:

- **Deleting an organization** says that it's the whole organization, not only the project you're on, lists its projects, how many environments and secrets go with them, and asks for the organization's name.
- **Deleting an environment** with secrets asks for its slug and says how many secrets go with it. An empty one only asks.
- `sigillo projects delete` and `sigillo environments delete` ask you to type the project's name or the environment's slug. Without a terminal they take `--yes`.
