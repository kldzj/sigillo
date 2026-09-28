---
'sigillo-app': patch
---

The login provider shows its consent screen the first time an app asks. It used to skip it for any client whose redirect address was on a host derived from its own, and anyone can register a client. Its error page links back only to your instance's login, and none of its pages are indexed or cached.
