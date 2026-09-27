---
'sigillo-app': patch
---

Allow only one organization per auto-join email domain.

Anyone with a verified company email could create a second organization with auto-join turned on for the same domain. Everyone from that company who opened the dashboard next was silently added to it, and the dashboard showed that organization first because it was the newest.

The first organization to claim a domain now keeps it, and claiming a domain another organization already uses fails with an error. Migration `0009` clears duplicate claims, keeping the oldest organization's, and adds a unique index.
