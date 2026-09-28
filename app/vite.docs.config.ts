// Builds the docs site (src/docs-site.tsx) for Node into dist-docs/, where
// scripts/export-docs.ts renders every page of it to static files.
import { holocron } from '@holocron.so/vite'
import { defineConfig } from 'vite'
import { DOCS_URL as SITE_URL } from './src/lib/utils.ts'

// Copying node_modules next to the server build is only needed to run it
// elsewhere; the export runs it right here. Spiceflow also looks for that
// build in dist/ only.
process.env.SPICEFLOW_SKIP_STANDALONE_TRACE = '1'

export const DOCS_URL = new URL(process.env.DOCS_URL ?? SITE_URL)

export default defineConfig({
  clearScreen: false,
  plugins: [holocron({ entry: './src/docs-site.tsx', pagesDir: './src' })],
  environments: {
    client: { build: { outDir: 'dist-docs/client' } },
    ssr: { build: { outDir: 'dist-docs/ssr' } },
    rsc: { build: { outDir: 'dist-docs/rsc' } },
  },
  // The export asks for pages as the docs site's host, so links in them
  // point there
  preview: { allowedHosts: [DOCS_URL.hostname] },
})
