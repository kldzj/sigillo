---
'sigillo-app': patch
---

- Sign-in and login endpoints of the app and its login provider are rate limited per IP, counted in D1. Looking up CLI login codes allows 30 tries per 10 minutes from one address, registering new clients with the provider 10 an hour.
- A browser or CLI login ends 30 days after its sign-in, however often it's used. It used to renew itself for as long as it was used, so a stolen one in daily use never ended.
- A link to `/logout` on another site no longer signs you out on its own: it shows a page that asks first.
- A new or renamed environment's slug is lowercase letters, digits and dashes. Existing slugs keep working.
- Only a token's creator or an org admin can delete it; the **Tokens** tab shows the delete button only to them. Any member could delete a colleague's CI token before.
