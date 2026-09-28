// A project's settings, its Settings tab: renaming the project and, in the
// "Danger Zone", deleting it with its environments and secrets. Deleting
// takes the project's name, typed out, and the server checks it too. The
// organization's own settings are linked from the sidebar.

'use client'

import { useState, useTransition } from 'react'
import { AlertTriangleIcon } from 'lucide-react'
import { useLoaderData } from 'spiceflow/react'
import { Button } from 'sigillo-app/src/components/ui/button'
import { Input } from 'sigillo-app/src/components/ui/input'
import {
  Dialog,
  DialogPopup,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from 'sigillo-app/src/components/ui/dialog'
import { deleteProjectAction, renameProjectAction } from '../actions.ts'
import { withStepUp } from './step-up.ts'

function RenameSection() {
  const { projectId, projectName } = useLoaderData('/dash/projects/:projectId/settings')
  const [name, setName] = useState(projectName)
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleRename() {
    setError(null)
    startTransition(async () => {
      try {
        await withStepUp(() => renameProjectAction({ projectId, name }))
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Renaming failed')
      }
    })
  }

  return (
    <div className="rounded-lg border border-border p-5 flex flex-col gap-3">
      <div>
        <h2 className="text-lg font-semibold">Project name</h2>
        <p className="text-muted-foreground text-sm mt-1">
          The CLI finds a project by its name, with <code className="mono-sm">--project</code> or <code className="mono-sm">SIGILLO_PROJECT</code>.
        </p>
      </div>
      <div className="flex gap-2 max-w-md">
        <Input value={name} onChange={(e) => setName(e.target.value)} className="flex-1" />
        <Button onClick={handleRename} disabled={isPending || !name.trim() || name.trim() === projectName}>
          {isPending ? 'Saving...' : 'Rename'}
        </Button>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  )
}

export function ProjectSettingsPage() {
  const { projectId, projectName, environmentCount, secretCount } = useLoaderData('/dash/projects/:projectId/settings')
  const [open, setOpen] = useState(false)
  const [typedName, setTypedName] = useState('')
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleDelete() {
    setDeleteError(null)
    startTransition(async () => {
      try {
        await withStepUp(() => deleteProjectAction({ projectId, typedName }))
      } catch (e) {
        setDeleteError(e instanceof Error ? e.message : 'Deleting failed')
      }
    })
  }

  return (
    <div className="flex flex-col gap-8 w-full max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Project settings</h1>
        <p className="text-muted-foreground text-sm mt-1">
          {projectName}. The organization's settings are in the sidebar.
        </p>
      </div>

      <RenameSection />

      <div className="rounded-lg border border-destructive/40">
        <div className="p-5">
          <h2 className="text-lg font-semibold text-destructive flex items-center gap-2">
            <AlertTriangleIcon className="size-5" />
            Danger Zone
          </h2>
        </div>
        <div className="border-t border-destructive/40 px-5 py-4 bg-destructive/5 rounded-b-lg flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium">Delete this project</p>
            <p className="text-xs text-muted-foreground">
              Deletes {projectName} with its environments and secrets. It can't be undone.
            </p>
          </div>
          <Dialog open={open} onOpenChange={(next) => { setOpen(next); setTypedName(''); setDeleteError(null) }}>
            <Button variant="destructive" onClick={() => setOpen(true)}>
              Delete project
            </Button>
            <DialogPopup>
              <DialogHeader>
                <DialogTitle>Delete the project {projectName}?</DialogTitle>
                <DialogDescription>
                  This can't be undone.
                </DialogDescription>
              </DialogHeader>
              <div className="px-6 pb-4">
                <p className="text-sm text-muted-foreground">
                  With it go {environmentCount} {environmentCount === 1 ? 'environment' : 'environments'} and{' '}
                  <strong className="text-foreground">{secretCount} {secretCount === 1 ? 'secret' : 'secrets'}</strong>,
                  their history, and the project's API tokens.
                </p>
                <label className="flex flex-col gap-1.5 mt-4 text-sm">
                  <span>Type <strong className="mono-sm">{projectName}</strong> to confirm</span>
                  <Input value={typedName} onChange={(e) => setTypedName(e.target.value)} autoComplete="off" spellCheck={false} />
                </label>
                {deleteError && <p className="text-sm text-destructive mt-2">{deleteError}</p>}
              </div>
              <DialogFooter>
                <DialogClose render={<Button variant="outline" />}>
                  Cancel
                </DialogClose>
                <Button variant="destructive" onClick={handleDelete} disabled={isPending || typedName !== projectName}>
                  {isPending ? 'Deleting...' : 'Delete project'}
                </Button>
              </DialogFooter>
            </DialogPopup>
          </Dialog>
        </div>
      </div>
    </div>
  )
}
