#!/usr/bin/env node
// Cross-platform launcher for sigillo — runs the native Zig binary for the current platform.

import { spawnSync } from 'node:child_process'
import { existsSync, chmodSync } from 'node:fs'
import { constants } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// `self-host` is TypeScript-only (goke + clack) and lives exclusively in the
// npm package — it is not part of the Zig binary. Intercept it before exec'ing
// the native CLI.
if (process.argv[2] === 'self-host' || process.argv[2] === 'selfhost') {
  const { run } = await import('./selfhost/cli.js')
  await run()
  // No explicit code: a failed deploy sets process.exitCode = 1
  process.exit()
}

// Targets that ship prebuilt binaries (must match scripts/build.ts)
const supportedTargets = new Set([
  'darwin-arm64', 'darwin-x64',
  'linux-arm64', 'linux-x64',
  'win32-arm64', 'win32-x64',
])

const target = `${process.platform}-${process.arch}`

if (!supportedTargets.has(target)) {
  process.stderr.write(`error: unsupported platform: ${target}\n`)
  process.stderr.write(`supported: ${[...supportedTargets].join(', ')}\n`)
  process.exit(1)
}

const binaryName = process.platform === 'win32' ? 'sigillo.exe' : 'sigillo'
const binaryPath = join(__dirname, target, binaryName)

if (!existsSync(binaryPath)) {
  process.stderr.write(`error: native binary not found at ${binaryPath}\n`)
  process.stderr.write(`hint: run 'zig build' or install from npm to get prebuilt binaries\n`)
  process.exit(1)
}

// Ensure the binary is executable (npm tarballs may strip the +x bit)
if (process.platform !== 'win32') {
  try {
    chmodSync(binaryPath, 0o755)
  } catch {}
}

const result = spawnSync(binaryPath, process.argv.slice(2), { stdio: 'inherit' })

if (result.error) {
  process.stderr.write(`error: failed to run ${binaryPath}: ${result.error.message}\n`)
  process.exit(1)
}

// Killed by a signal: exit as a shell does, 128 + its number, and name a
// crash, such as SIGILL on a CPU the binary wasn't built for. Ctrl+C and a
// closed pipe aren't crashes.
if (result.signal) {
  if (!['SIGINT', 'SIGTERM', 'SIGPIPE', 'SIGHUP'].includes(result.signal)) {
    process.stderr.write(`error: sigillo was killed by ${result.signal}\n`)
  }
  process.exit(128 + (constants.signals[result.signal] ?? 0))
}

process.exit(result.status ?? 1)
