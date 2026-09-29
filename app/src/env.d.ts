// Type augmentation for the test-only bindings injected via miniflare config
// in vite.config.ts: the migrations, and the private keys of the fake OIDC
// issuer the workload identity tests sign JWTs with.

declare namespace Cloudflare {
  interface Env {
    TEST_MIGRATIONS: D1Migration[]
    TEST_ISSUER_KEYS: { rsa: JsonWebKey & { kid: string; alg: string }; ec: JsonWebKey & { kid: string; alg: string } }
  }
}

interface D1Migration {
  name: string
  queries: string[]
}

// nodejs_compat exposes process.env at runtime in Cloudflare Workers.
// Only the subset we actually use is declared to avoid pulling in @types/node.
declare var process: { env: Record<string, string | undefined> }
