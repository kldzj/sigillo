// Applies the provider's D1 migrations before the tests run (see vitest.config.ts).
import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'

await applyD1Migrations((env as unknown as { DB: D1Database }).DB, (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS)
