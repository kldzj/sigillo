/// <reference types="vitest/config" />
// Tests for the provider: run its Spiceflow app inside
// workerd against a migrated in-memory D1, like app/vite.config.ts does.
import path from 'node:path'
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers'
import react from '@vitejs/plugin-react'
import { spiceflowPlugin } from 'spiceflow/vite'
import { defineConfig } from 'vite'

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, 'drizzle'))
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.test.jsonc' },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            BETTER_AUTH_SECRET: 'test-secret-at-least-32-characters-long!!',
          },
          // Nothing under test may reach the network
          outboundService: (request: Request) => Response.json({ error: 'unexpected_outbound_request', url: request.url }, { status: 501 }),
        },
      }),
      react(),
      spiceflowPlugin({ entry: './src/app.tsx' }),
    ],
    resolve: {
      dedupe: ['spiceflow', 'spiceflow/react', 'react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime'],
    },
    test: {
      setupFiles: ['./src/test-setup.ts'],
    },
  }
})
