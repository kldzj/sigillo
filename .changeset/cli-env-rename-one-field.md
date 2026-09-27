---
'sigillo': patch
---

`sigillo environments rename` works with only `--name` or only `--slug`. The CLI sent the missing field as `null`, which the API rejects, so the rename failed with `(422): unknown error`.
