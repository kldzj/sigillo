// Generate CLI reference docs by running `sigillo --help` and parsing the output.
// Produces one .mdx page per command + an index page in app/src/docs/cli/.
//
// Run: pnpm generate:cli-docs

import { execSync } from 'node:child_process'
import { writeFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = resolve(__dirname, '..', 'src', 'docs', 'cli')
const binary = resolve(__dirname, '..', '..', 'cli', 'zig-out', 'bin', 'sigillo')

// ── Run sigillo --help and strip ANSI codes ──

const raw = execSync(`${binary} --help 2>&1`, { encoding: 'utf-8' })
const help = raw.replace(/\x1b\[[0-9;]*m/g, '')

// ── Parse help output ──

interface Command {
  name: string
  usage: string
  description: string
  options: { flag: string; description: string }[]
}

function parseHelp(text: string): { commands: Command[]; globalOptions: { flag: string; description: string }[] } {
  const commands: Command[] = []
  const globalOptions: { flag: string; description: string }[] = []

  // Split into sections by the bold headers
  const commandsSection = text.match(/Commands:\n([\s\S]*?)(?:\nOptions:|$)/)?.[1] ?? ''
  const optionsSection = text.match(/Options:\n([\s\S]*?)$/)?.[1] ?? ''

  // Parse commands section. Each command starts with 2-space indent + command name,
  // followed by 0+ option lines with deeper indent.
  const lines = commandsSection.split('\n')
  let current: Command | null = null

  for (const line of lines) {
    // Command line: "  login                       Authenticate to Sigillo..."
    // or "  run <...cmd>                Run a command..."
    const cmdMatch = line.match(/^ {2}(\S.*?)\s{2,}(.+)$/)
    if (cmdMatch && !line.match(/^ {4}/)) {
      const usage = cmdMatch[1].trim()
      const name = usage.replace(/ <[^>]*>| \[.*$/g, '').trim()
      if (current) commands.push(current)
      current = { name, usage, description: cmdMatch[2].trim(), options: [] }
      continue
    }

    // Option line: "    --scope [scope]           Scope for saved auth..."
    const optMatch = line.match(/^ {4}(-\S.*?)\s{2,}(.+)$/)
    if (optMatch && current) {
      current.options.push({ flag: optMatch[1].trim(), description: optMatch[2].trim() })
    }
  }
  if (current) commands.push(current)

  // Parse global options
  for (const line of optionsSection.split('\n')) {
    const optMatch = line.match(/^ {2}(-\S.*?)\s{2,}(.+)$/)
    if (optMatch) {
      globalOptions.push({ flag: optMatch[1].trim(), description: optMatch[2].trim() })
    }
  }

  return { commands, globalOptions }
}

const { commands, globalOptions } = parseHelp(help)
console.log(`parsed ${commands.length} commands, ${globalOptions.length} global options`)

// ── Icon mapping ──

const iconMap: Record<string, string> = {
  login: 'lucide:log-in',
  logout: 'lucide:log-out',
  me: 'lucide:user',
  setup: 'lucide:settings',
  run: 'lucide:play',
  secrets: 'lucide:lock',
  'secrets get': 'lucide:key',
  'secrets set': 'lucide:pencil',
  'secrets delete': 'lucide:trash-2',
  'secrets download': 'lucide:download',
  orgs: 'lucide:building-2',
  'orgs create': 'lucide:plus',
  projects: 'lucide:folder',
  'projects create': 'lucide:folder-plus',
  'projects get': 'lucide:folder-search',
  'projects update': 'lucide:folder-pen',
  'projects delete': 'lucide:folder-x',
  environments: 'lucide:layers',
  'environments create': 'lucide:plus',
  'environments get': 'lucide:search',
  'environments rename': 'lucide:pencil',
  'environments delete': 'lucide:trash-2',
}

// ── Generate .mdx files ──

mkdirSync(outDir, { recursive: true })
for (const file of readdirSync(outDir)) {
  if (file.endsWith('.mdx')) rmSync(join(outDir, file))
}

function slug(name: string): string {
  return name.replace(/\s+/g, '-')
}

function optionsTable(opts: { flag: string; description: string }[]): string {
  const lines = ['| Option | Description |', '|--------|-------------|']
  for (const opt of opts) {
    lines.push(`| \`${opt.flag}\` | ${opt.description} |`)
  }
  return lines.join('\n')
}

function writePage(filename: string, frontmatter: Record<string, string>, body: string) {
  const fm = ['---', ...Object.entries(frontmatter).map(([k, v]) => `${k}: ${v}`), '---'].join('\n')
  const filePath = join(outDir, filename)
  writeFileSync(filePath, `${fm}\n\n${body}\n`)
  console.log(`wrote ${filePath}`)
}

// Index page
const indexBody = [
  '## Commands',
  '',
  '| Command | Description |',
  '|---------|-------------|',
  ...commands.map((c) => `| [\`${c.name}\`](/docs/cli/${slug(c.name)}) | ${c.description} |`),
  '',
  '## Global Options',
  '',
  optionsTable(globalOptions),
].join('\n')

writePage('index.mdx', {
  '$schema': 'https://holocron.so/frontmatter.json',
  title: '"CLI Reference"',
  description: '"All sigillo CLI commands and options"',
  icon: 'lucide:terminal',
}, indexBody)

// self-host runs from the npm package (TypeScript), not the native binary,
// whose help only has a stub for it: its page points to the real options.
const npmOnly: Record<string, string> = {
  'self-host': 'Its options, environment variables and the encrypted deploy file are described on [Self-hosting](/docs/self-hosting#options).',
}

// Per-command pages
for (const cmd of commands) {
  const icon = iconMap[cmd.name] ?? 'lucide:terminal'
  const parts: string[] = []

  parts.push(cmd.description, '')
  if (npmOnly[cmd.name]) {
    parts.push('## Usage', '', '```sh', `npx @kldzj/sigillo ${cmd.usage}`, '```', '', npmOnly[cmd.name]!)
    writePage(`${slug(cmd.name)}.mdx`, {
      '$schema': 'https://holocron.so/frontmatter.json',
      title: `"${cmd.name}"`,
      description: `"${cmd.description}"`,
      icon,
    }, parts.join('\n'))
    continue
  }
  parts.push('## Usage', '', '```sh', `sigillo ${cmd.usage}`, '```', '')

  if (cmd.options.length > 0) {
    parts.push('## Options', '', optionsTable(cmd.options), '')
  }

  parts.push('## Global Options', '', optionsTable(globalOptions))

  writePage(`${slug(cmd.name)}.mdx`, {
    '$schema': 'https://holocron.so/frontmatter.json',
    title: `"${cmd.name}"`,
    description: `"${cmd.description}"`,
    icon,
  }, parts.join('\n'))
}

console.log(`\ngenerated ${commands.length + 1} pages in ${outDir}`)
