---
'sigillo-app': minor
'@kldzj/sigillo': minor
---

Workload identity: GitHub Actions jobs and Kubernetes pods read secrets without a stored token. An org admin adds a trust rule on a project's **Tokens** tab, with their passkey: the issuer, the audience, the exact subject and claims, and the environments it grants. A workload exchanges the JWT its platform issues at `POST /api/v0/workload/token` for a token of one hour. `sigillo` does that on its own when no token is set, from `SIGILLO_OIDC_TOKEN_FILE`, `SIGILLO_OIDC_TOKEN` or GitHub Actions' ID token, with the project named by its ID. External Secrets Operator's Doppler provider works against Sigillo too, with its controller's `DOPPLER_BASE_URL` set to the instance. Rules for protected environments follow the rules of machine tokens, and the read log names the job or pod behind each read.
