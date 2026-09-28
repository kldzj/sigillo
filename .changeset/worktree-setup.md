---
'@kldzj/sigillo': patch
---

Git worktrees pick up the right project and env, also in subfolders. A worktree uses the main checkout's setup at the same relative path: before, `sigillo run` in `<worktree>/app` used the repo root's setup and ignored the one for `<main>/app`. A setup saved inside a worktree now always wins over the main checkout's. Inside a worktree, `sigillo setup` asks whether to save for the main checkout and all its worktrees or for this worktree only, `--scope <dir>` picks the directory to save for, and `sigillo me` names the main checkout.
