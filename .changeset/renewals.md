---
'sigillo-app': minor
'@kldzj/sigillo': minor
---

Tokens and trust rules are renewed in place, and warn before they expire:

- **Regenerate a token** on a project's **Machines** tab: a new value and a new expiry for the same token, so its name, scope and history stay. Its creator or an org admin does it, with a passkey once they have one; a machine token takes an org admin with their passkey and lasts 90 days at most. The previous value keeps working for 0, 1 or 7 days, never past its own expiry, and the tab shows until when and whether it is still used, with a **Stop** link to end it early. A token that never expired gets an expiry this way.
- **Renew a trust rule** on the same tab: a new expiry for the same rule, so External Secrets Operator and CI keep its ID. The renewal dialog first shows how the rule was used, which workloads got its tokens, and what looks stale. The admin who renews it owns it from then on, an expired rule can be renewed too, and keys from its issuer are fetched again.
- **Warnings** start when a quarter of a token's or rule's lifetime is left, 14 days at most: an Expires badge on the Machines tab, a banner on every dashboard page (dismissed for a day), and on API answers the headers `Sigillo-Token-Expires` and `Sigillo-Warning`. `sigillo` prints that warning once per command, on stderr, so it shows in CI logs without touching a download:

  ```
  warning: this API token expires on 2026-10-13 (in 3 days). Regenerate it on the project's Machines tab; the old value then keeps working for up to 7 days.
  ```

- The workload token exchange answers with its rule's `ruleId` and `ruleExpiresAt` too.
- Token names can't contain control characters, like other names.
- Each change to tokens, trust rules, protection, members and passkeys is written to a security log in the same database batch, for notifications in a later release.
