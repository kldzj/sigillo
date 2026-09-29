---
'@kldzj/sigillo': minor
---

`npx @kldzj/sigillo self-host --rotate-key` gives an instance a new encryption key. It re-encrypts every stored value with it on your machine, through the D1 API, and then removes the old key from the worker and `~/.sigillo/selfhost.json`. Stopped halfway, the next run finishes the same rotation. Deploys keep the key ring in `selfhost.json`, and a recreated worker gets it back.
