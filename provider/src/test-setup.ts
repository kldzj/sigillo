// Applies the provider's D1 migrations before the tests run (see vitest.config.ts)
import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'

const { DB, TEST_MIGRATIONS } = env as unknown as { DB: D1Database; TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1] }
await applyD1Migrations(DB, TEST_MIGRATIONS)
