// Tests for the npm launcher (src/bin.ts), which hands `self-host` to the
// TypeScript command and everything else to the native Zig binary.

import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, test } from 'vitest'

const cliDir = dirname(dirname(fileURLToPath(import.meta.url)))

describe('bin', () => {
  test('self-host exits non-zero when it fails', () => {
    // An empty home, no token and no TTY: self-host fails at the credential
    // step before touching the network.
    const home = mkdtempSync(join(tmpdir(), 'sigillo-bin-'))
    try {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        HOME: home,
        XDG_CONFIG_HOME: join(home, '.config'),
        APPDATA: home,
        LOCALAPPDATA: home,
      }
      delete env.CLOUDFLARE_API_TOKEN
      const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/bin.ts', 'self-host', '--yes'], {
        cwd: cliDir,
        env,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      expect(result.stdout + result.stderr).toContain('No Cloudflare credentials found')
      expect(result.status).toBe(1)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  }, 60_000)
})
