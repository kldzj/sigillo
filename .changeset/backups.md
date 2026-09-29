---
'@kldzj/sigillo': minor
---

`npx @kldzj/sigillo self-host --backup` saves both databases of an instance in one file, encrypted with age to a backup key kept in `~/.sigillo/selfhost.json`. Sessions and sign-in codes are left out, and no encryption key goes in the file. `--restore <file>` imports a backup into new databases, checks every row of their history, and only then switches both workers to them. The databases from before stay on the account. A key rotation replaces the backup key, since older backups need the retired key.
