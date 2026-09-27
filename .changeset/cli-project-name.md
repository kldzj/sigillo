---
'@kldzj/sigillo': minor
'sigillo-app': patch
---

`--project` now accepts a project name as well as its ID.

```bash
sigillo run --project website --env dev -- npm start
sigillo setup --project website --env dev
```

Before, a name was sent to the API as if it were an ID, and the command failed with `env dev was not found in project website`. Now a value that isn't a project ID is looked up among the projects you can access. If no project has that name, the error says the project was not found and lists the ones you can use. If several projects share the name, it lists them so you can pick one by ID. `setup` saves the resolved ID, so renaming the project later doesn't break the directory's config.

An unknown project ID is also reported as a missing project now, instead of as a missing env.
