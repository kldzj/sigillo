---
'sigillo': patch
'sigillo-app': patch
---

Git worktrees now pick up the right project and env, including in monorepo subfolders.

- A worktree inherits the main checkout's setup **at the same relative path**. Before, `sigillo run` in `<worktree>/app` used the repo root setup and ignored the one saved for `<main>/app`.
- A setup saved inside a worktree now always overrides the main checkout. Before, it could lose when the worktree path was shorter than the main checkout path (for example `/tmp/feature` vs `~/Documents/GitHub/repo`).
- New `sigillo setup --scope <dir>` saves the setup for another directory. From a worktree, run it with the main checkout path so every worktree gets it:

  ```bash
  sigillo setup --scope ~/Documents/GitHub/repo --project proj_abc --env dev
  ```

- Interactive `sigillo setup` inside a worktree asks whether to save for the main checkout and all worktrees, or for this worktree only.
- When a worktree has no setup, the error shows the `--scope` command for the main checkout and lists subfolders configured there. `sigillo me` shows which checkout a worktree belongs to.
