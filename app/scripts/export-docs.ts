// Renders the docs site to static files in dist-docs/site: each page as HTML,
// the RSC data the browser loads when you navigate to it, and its markdown,
// plus the sitemap and the files holocron serves for agents. Rendering a page
// takes 20 to 200 ms of CPU, more than the Workers free plan allows per
// request, so the site is served as files: wrangler.docs.jsonc deploys them
// as static assets without a Worker, and any web server can serve them too.

import fs from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { createBuilder, preview } from 'vite'
import { DOCS_URL } from '../vite.docs.config.ts'

const root = path.join(import.meta.dirname, '..')
const configFile = path.join(root, 'vite.docs.config.ts')
const outDir = path.join(root, 'dist-docs')
const siteDir = path.join(outDir, 'site')

type Fetched = { status: number; headers: http.IncomingHttpHeaders; body: Buffer }

// Asks as the docs site's host, so the links in a page point there
function get(port: number, pathname: string): Promise<Fetched> {
  return new Promise((resolve, reject) => {
    http.get({
      host: '127.0.0.1',
      port,
      path: pathname,
      headers: { host: DOCS_URL.host, 'x-forwarded-proto': DOCS_URL.protocol.slice(0, -1) },
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }))
    }).on('error', reject)
  })
}

async function save(file: string, body: Buffer | string) {
  const target = path.join(siteDir, file)
  await fs.mkdir(path.dirname(target), { recursive: true })
  await fs.writeFile(target, body)
}

await fs.rm(outDir, { recursive: true, force: true })
const builder = await createBuilder({ configFile, root })
await builder.buildApp()
await fs.cp(path.join(outDir, 'client'), siteDir, { recursive: true })
await fs.rm(path.join(siteDir, '__prerender.json'), { force: true })

const server = await preview({ configFile, root, preview: { host: '127.0.0.1', port: 4174 } })
try {
  const port = (server.httpServer.address() as { port: number }).port
  const sitemap = await get(port, '/sitemap.xml')
  if (sitemap.status !== 200) throw new Error(`sitemap.xml: ${sitemap.status}`)
  const pages = [...sitemap.body.toString().matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => new URL(m[1]!).pathname)

  let deploymentId = ''
  // Files the pages load from holocron's own routes, such as the logo
  const referenced = new Set<string>()
  for (const page of pages) {
    const base = page === '/' ? '/index' : page
    const html = await get(port, page)
    const rsc = await get(port, `${base}.rsc?__rsc=`)
    const markdown = await get(port, `${base}.md`)
    for (const [name, res] of [['page', html], ['RSC data', rsc], ['markdown', markdown]] as const) {
      if (res.status !== 200) throw new Error(`${page}: ${name} answered ${res.status}`)
    }
    deploymentId ||= String(rsc.headers['x-spiceflow-deployment-id'] ?? '')
    for (const m of html.body.toString().matchAll(/(?:src|href)="(\/holocron-api\/[^"]+)"/g)) referenced.add(m[1]!)
    await save(`${base}.html`, html.body)
    await save(`${base}.rsc`, rsc.body)
    await save(`${base}.md`, markdown.body)
  }

  const files = ['/sitemap.xml', '/llms.txt', '/llms-full.txt', '/docs.zip', '/.well-known/agent-skills/index.json', '/.well-known/skills/index.json', ...referenced]
  const skills = JSON.parse((await get(port, '/.well-known/skills/index.json')).body.toString()) as { skills: { name: string; files: string[] }[] }
  for (const skill of skills.skills) {
    for (const file of skill.files) {
      files.push(`/.well-known/skills/${skill.name}/${file}`, `/.well-known/agent-skills/${skill.name}/${file}`)
    }
  }
  for (const file of files) {
    const res = await get(port, file)
    if (res.status !== 200) throw new Error(`${file}: ${res.status}`)
    await save(file, res.body)
  }

  // A static host sends no headers of its own for RSC data. The deployment
  // id makes an open tab reload after a deploy instead of loading scripts
  // that no longer exist.
  await save('_headers', [
    '/*.rsc',
    '  Content-Type: text/x-component; charset=utf-8',
    ...(deploymentId ? [`  X-Spiceflow-Deployment-Id: ${deploymentId}`] : []),
    '',
  ].join('\n'))
  await save('404.html', `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found · Sigillo</title>
<style>
  body { margin: 0; min-height: 90vh; display: grid; place-items: center; font: 16px system-ui, sans-serif; color: #171717; background: #fdfcfb; }
  a { color: #16a34a; }
  @media (prefers-color-scheme: dark) { body { color: #f5f5f5; background: #0a0a0a; } }
</style>
<p>This page doesn't exist. <a href="/">Go to the docs</a></p>
</html>
`)
  console.log(`Exported ${pages.length} pages and ${files.length} files for ${DOCS_URL.origin} to ${path.relative(root, siteDir)}`)
} finally {
  await server.close()
}
