---
'sigillo-app': patch
---

Removing a member now also revokes the API tokens and invite links they created in that organization.

Tokens and invite links used to outlive the person who created them. A departed member's CI token kept reading secrets, and their invite links kept letting people join, until someone noticed and deleted them by hand.

Secrets written with those tokens stay. If CI uses a token created by someone who is leaving, create a replacement token before removing them.
