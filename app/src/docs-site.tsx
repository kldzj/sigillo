// Entry for the docs site: the landing page and docs only, without login,
// API or database. scripts/export-docs.ts renders every page of it to static
// files, so the site needs no Worker. Instances don't serve these pages.

import './globals.css'
import './docs-site.css'
import { Spiceflow } from 'spiceflow'
import { app as holocronApp } from '@holocron.so/vite/app'

export const app = new Spiceflow().use(holocronApp)

export default {
  fetch: (request: Request) => app.handle(request),
}
