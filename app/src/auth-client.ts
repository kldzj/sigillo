// Type-safe BetterAuth client for the self-hosted app.
// Used by client components (login button, device flow) to call auth endpoints.

import { createAuthClient } from 'better-auth/client'
import { deviceAuthorizationClient } from 'better-auth/client/plugins'
import { passkeyClient } from '@better-auth/passkey/client'

export const authClient = createAuthClient({
  plugins: [
    deviceAuthorizationClient(),
    passkeyClient(),
  ],
})
