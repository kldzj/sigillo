// Tests for the npm launcher (src/bin.ts), which hands `self-host` to the
// TypeScript command and everything else to the native Zig binary.

import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, test } from 'vitest'

const cliDir = dirname(dirname(fileURLToPath(import.meta.url)))

describe('bin', () => {
  test('self-host exits non-zero when it fails', () => {
    // An empty home, no token and no TTY: self-host fails at the credential
    // step before touching the network (the passphrase lets it get there).
    const home = mkdtempSync(join(tmpdir(), 'sigillo-bin-'))
    try {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        SIGILLO_SELFHOST_PASSPHRASE: 'bin test passphrase',
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

  test.skipIf(process.platform === 'win32')('a binary killed by a signal says so, and exits as a shell would', () => {
    // bin.ts next to a "binary" that dies of SIGILL, as the linux-x64 build
    // did on CPUs without AVX-512
    const dir = mkdtempSync(join(tmpdir(), 'sigillo-bin-'))
    try {
      copyFileSync(join(cliDir, 'src/bin.ts'), join(dir, 'bin.ts'))
      writeFileSync(join(dir, 'package.json'), '{"type":"module"}')
      mkdirSync(join(dir, `${process.platform}-${process.arch}`))
      writeFileSync(join(dir, `${process.platform}-${process.arch}`, 'sigillo'), '#!/bin/sh\nkill -ILL $$\n', { mode: 0o755 })
      const result = spawnSync(process.execPath, ['--import', 'tsx', join(dir, 'bin.ts'), '--version'], {
        cwd: cliDir,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      expect({ stderr: result.stderr, status: result.status }).toEqual({ stderr: 'error: sigillo was killed by SIGILL\n', status: 132 })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 60_000)
})
