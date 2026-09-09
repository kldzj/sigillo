// Prove 0007 upgrades live api_token + secret_event rows with foreign_keys ON.
// D1 remote /query ignores PRAGMA foreign_keys=OFF across split statements,
// so this script never turns FKs off. Failures here mean hosted/self-host
// deploys would lose audit rows or widen env-scoped tokens to all envs.

import { Database } from 'bun:sqlite'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = dirname(fileURLToPath(import.meta.url))
const migrationPath = join(dir, '../drizzle-app/0007_token-environments.sql')

function execStatements(db: Database, sql: string) {
  const parts = sql
    .split('--> statement-breakpoint')
    .map((part) => part.trim())
    .filter(Boolean)
  for (const [i, part] of parts.entries()) {
    console.log(`  statement ${i + 1}/${parts.length}`)
    db.exec(part)
  }
}

function must(n: number, label: string) {
  if (n !== 1) throw new Error(`${label}: expected 1, got ${n}`)
}

const db = new Database(':memory:')
db.exec('PRAGMA foreign_keys = ON')

console.log('Creating pre-0007 schema (0006 end state)...')
db.exec(`
  CREATE TABLE user (
    id text PRIMARY KEY,
    name text NOT NULL,
    email text NOT NULL,
    email_verified integer NOT NULL,
    image text,
    created_at integer NOT NULL,
    updated_at integer NOT NULL
  );
  CREATE TABLE org (
    id text PRIMARY KEY,
    name text NOT NULL,
    created_at integer NOT NULL,
    updated_at integer NOT NULL
  );
  CREATE TABLE project (
    id text PRIMARY KEY,
    name text NOT NULL,
    org_id text NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    created_at integer NOT NULL,
    updated_at integer NOT NULL
  );
  CREATE TABLE environment (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    name text NOT NULL,
    slug text NOT NULL,
    access_role text NOT NULL DEFAULT 'member',
    created_at integer NOT NULL,
    updated_at integer NOT NULL
  );
  CREATE TABLE api_token (
    id text PRIMARY KEY,
    name text NOT NULL,
    project_id text NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    environment_id text REFERENCES environment(id) ON DELETE CASCADE,
    prefix text NOT NULL,
    hashed_key text NOT NULL,
    created_by text NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    created_at integer NOT NULL
  );
  CREATE TABLE secret_event (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environment(id) ON DELETE CASCADE,
    name text NOT NULL,
    operation text NOT NULL,
    value_encrypted text,
    iv text,
    user_id text REFERENCES user(id) ON DELETE CASCADE,
    api_token_id text REFERENCES api_token(id) ON DELETE CASCADE,
    created_at integer NOT NULL
  );
`)

const now = Date.now()
db.exec(`
  INSERT INTO user (id, name, email, email_verified, created_at, updated_at)
  VALUES ('user_1', 'Ada', 'ada@example.com', 1, ${now}, ${now});
  INSERT INTO org (id, name, created_at, updated_at)
  VALUES ('org_1', 'Acme', ${now}, ${now});
  INSERT INTO project (id, name, org_id, created_at, updated_at)
  VALUES ('proj_1', 'Website', 'org_1', ${now}, ${now});
  INSERT INTO environment (id, project_id, name, slug, created_at, updated_at) VALUES
    ('env_dev', 'proj_1', 'Dev', 'dev', ${now}, ${now}),
    ('env_prod', 'proj_1', 'Prod', 'prod', ${now}, ${now});
  INSERT INTO api_token (id, name, project_id, environment_id, prefix, hashed_key, created_by, created_at) VALUES
    ('tok_all', 'ci-all', 'proj_1', NULL, 'aaaaaaaaaaaa', 'hash_all', 'user_1', ${now}),
    ('tok_dev', 'ci-dev', 'proj_1', 'env_dev', 'bbbbbbbbbbbb', 'hash_dev', 'user_1', ${now});
  INSERT INTO secret_event (id, environment_id, name, operation, value_encrypted, iv, user_id, api_token_id, created_at) VALUES
    ('evt_token', 'env_dev', 'API_KEY', 'set', 'enc', 'iv', NULL, 'tok_dev', ${now}),
    ('evt_user', 'env_prod', 'API_KEY', 'set', 'enc', 'iv', 'user_1', NULL, ${now});
`)

const beforeTokens = db.query('SELECT COUNT(*) AS n FROM api_token').get() as { n: number }
const beforeScoped = db.query('SELECT COUNT(*) AS n FROM api_token WHERE environment_id IS NOT NULL').get() as { n: number }
const beforeEvents = db.query('SELECT COUNT(*) AS n FROM secret_event').get() as { n: number }
const beforeTokenEvents = db.query('SELECT COUNT(*) AS n FROM secret_event WHERE api_token_id IS NOT NULL').get() as { n: number }
console.log(`Before: tokens=${beforeTokens.n} scoped=${beforeScoped.n} events=${beforeEvents.n} token-events=${beforeTokenEvents.n}`)

console.log('Applying 0007 with foreign_keys ON...')
execStatements(db, readFileSync(migrationPath, 'utf8'))

const fk = db.query('PRAGMA foreign_keys').get() as { foreign_keys: number }
if (fk.foreign_keys !== 1) throw new Error(`foreign_keys ended up ${fk.foreign_keys}`)

const afterTokens = db.query('SELECT COUNT(*) AS n FROM api_token').get() as { n: number }
const afterJunction = db.query('SELECT COUNT(*) AS n FROM api_token_environment').get() as { n: number }
const afterEvents = db.query('SELECT COUNT(*) AS n FROM secret_event').get() as { n: number }
const afterTokenEvents = db.query('SELECT COUNT(*) AS n FROM secret_event WHERE api_token_id IS NOT NULL').get() as { n: number }
console.log(`After: tokens=${afterTokens.n} junction=${afterJunction.n} events=${afterEvents.n} token-events=${afterTokenEvents.n}`)

if (afterTokens.n !== beforeTokens.n) throw new Error('lost api_token rows')
if (afterJunction.n !== beforeScoped.n) throw new Error('junction count != pre-migration env-scoped tokens')
if (afterEvents.n !== beforeEvents.n) throw new Error('lost secret_event rows')
if (afterTokenEvents.n !== beforeTokenEvents.n) throw new Error('lost token-authored secret_event rows')

must((db.query("SELECT COUNT(*) AS n FROM api_token WHERE id = 'tok_all' AND hashed_key = 'hash_all'").get() as { n: number }).n, 'project-wide token')
must((db.query("SELECT COUNT(*) AS n FROM api_token_environment WHERE token_id = 'tok_all'").get() as { n: number }).n === 0 ? 1 : 0, 'project-wide token has 0 junction rows')
must((db.query("SELECT COUNT(*) AS n FROM api_token_environment WHERE token_id = 'tok_dev' AND environment_id = 'env_dev'").get() as { n: number }).n, 'dev-scoped junction row')
must((db.query("SELECT COUNT(*) AS n FROM secret_event WHERE id = 'evt_token' AND api_token_id = 'tok_dev'").get() as { n: number }).n, 'token-authored event')
must((db.query("SELECT COUNT(*) AS n FROM secret_event WHERE id = 'evt_user' AND user_id = 'user_1'").get() as { n: number }).n, 'user-authored event')

const cols = db.query('PRAGMA table_info(api_token)').all() as Array<{ name: string }>
if (cols.some((c) => c.name === 'environment_id')) throw new Error('environment_id still on api_token')

console.log('Deleting last scoped env (should revoke tok_dev, keep tok_all and events for other tokens)...')
db.exec("DELETE FROM environment WHERE id = 'env_dev'")
must((db.query("SELECT COUNT(*) AS n FROM api_token WHERE id = 'tok_dev'").get() as { n: number }).n === 0 ? 1 : 0, 'tok_dev revoked')
must((db.query("SELECT COUNT(*) AS n FROM api_token WHERE id = 'tok_all'").get() as { n: number }).n, 'tok_all kept')

console.log('0007 upgrade preserved tokens, hashes, and audit rows')
