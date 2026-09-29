---
'sigillo-app': minor
---

A project's tabs are now Secrets, Environments, Machines, History and Settings:

- **Members**, the organization's list of people with their roles, project access and passkeys, leaves every project's tabs for the sidebar, at `/dash/orgs/<org>/members`. It always was the whole organization's list.
- **Machines**, formerly Tokens, holds API tokens, machine tokens and workload identities.
- **History** replaces Event Log and Read Log, with a Changes | Reads switch, at `…/envs/<environment>/history`. The old `/event-log` URL matched EasyPrivacy's rule `/event-log?`, on by default in uBlock Origin Lite and other blockers, which broke switching to the tab, revealing old values and purging them.
