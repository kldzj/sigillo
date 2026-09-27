---
'sigillo-app': patch
---

Device login needs an explicit **Approve**.

`/device?user_code=…` used to approve the code in one click, so a link sent by someone else could sign them in as you. The page now checks the code, then shows a warning with **Approve** and **Deny** buttons.
