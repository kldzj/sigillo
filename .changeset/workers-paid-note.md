---
'@kldzj/sigillo': patch
'sigillo-app': patch
---

The docs no longer promise that Sigillo fits Cloudflare's free plan without a hitch: a dashboard page often takes 10 to 40 ms of CPU, more than the free plan's 10 ms, so on the free plan a page fails now and then with error 1102. Workers Paid, $5 a month, avoids that. `self-host` says so at the end of a new deployment.
