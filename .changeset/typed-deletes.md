---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

Deleting something that can't come back now takes its name, typed out:

- **An organization's settings** moved out of the project tabs into the sidebar, under **Organization settings**: auto-join, leaving it and deleting it. The project's **Settings** tab now renames or deletes that project.
- **Deleting an organization** lists its projects and how many environments and secrets go with them, and asks for the organization's name. **Deleting a project** asks for its name the same way.
- **Deleting an environment** with secrets asks for its slug and says how many secrets go with it. An empty one only asks.
- `sigillo projects delete` and `sigillo environments delete` ask you to type the project's name or the environment's slug. Without a terminal they take `--yes`.
