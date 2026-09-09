---
'sigillo-app': minor
---

API tokens can now cover more than one environment.

Create a token for **dev** and **preview** without also granting **prod**. Project-wide tokens still mean every environment. The CLI setup picker only lists the environments the token can use.

Fixes #7
