---
'sigillo-app': patch
---

- A member who can open only some projects no longer ends up in a redirect loop when their newest organization has none of theirs: the dashboard opens the newest project they can open, or says to ask an admin for access.
- Such a member no longer learns the names of projects they can't open, on the organization's settings or on the **Access** tab.
- Names of organizations, projects and environments can't contain control characters, which could rewrite a terminal that shows them.
- A CLI login's device code is stored as a hash, so one read out of the database during a login can't be exchanged for the session.
