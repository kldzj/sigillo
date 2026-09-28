---
'sigillo-app': patch
'@kldzj/sigillo': patch
---

Login and approval codes read `XXXX-XXXX` everywhere. `sigillo login` prints its code with the dash, and the code fields on `/device` and `/approve` add it while you type or paste, so a code works with or without it. `/approve` used to refuse a code typed without the dash.
