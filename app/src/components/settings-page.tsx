// Settings page for org-level configuration.
// Contains auto-join domain toggle and "Danger Zone" org deletion.
// The confirm dialog shows the list of projects that will be deleted
// so the user knows exactly what they are losing.

'use client'

import { useState, useTransition } from 'react'
import { AlertTriangleIcon, UsersIcon } from 'lucide-react'
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
import { deleteOrgAction, leaveOrgAction, updateAutoJoinDomainAction } from '../actions.ts'
import { withStepUp } from './step-up.ts'
import { COMMON_EMAIL_DOMAINS, getEmailDomain } from '../lib/utils.ts'

function AutoJoinSection() {
  const { orgId, autoJoinDomain } = useLoaderData('/dash/projects/:projectId/settings')
  const { user } = useLoaderData('/dash/*')
  const [isPending, startTransition] = useTransition()
  const [currentDomain, setCurrentDomain] = useState(autoJoinDomain)

  const userDomain = getEmailDomain(user.email)
  const isPublicDomain = !userDomain || COMMON_EMAIL_DOMAINS.has(userDomain)

  // Hide the section entirely for users with public email domains
  // who also don't have auto-join already enabled (legacy data)
  if (isPublicDomain && !currentDomain) return null

  const isEnabled = !!currentDomain

  function handleToggle() {
    const newEnabled = !isEnabled
    startTransition(async () => {
      const result = await withStepUp(() => updateAutoJoinDomainAction({ orgId, enabled: newEnabled }))
      if (result) setCurrentDomain(result.autoJoinDomain)
    })
  }

  return (
    <div className="rounded-lg border border-border">
      <div className="p-5">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <UsersIcon className="size-5" />
          Auto-join by email domain
        </h2>
        <p className="text-muted-foreground text-sm mt-2">
          {isEnabled ? (
            <>Users with a verified <span className="font-mono text-foreground">@{currentDomain}</span> email are automatically added to this organization.</>
          ) : (
            'Automatically add users to this organization based on their email domain.'
          )}
        </p>
      </div>
      <div className="border-t border-border px-5 py-4 bg-muted/30 rounded-b-lg flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">
            {isEnabled ? 'Auto-join is enabled' : 'Auto-join is disabled'}
          </p>
          {!isEnabled && userDomain && !isPublicDomain && (
            <p className="text-xs text-muted-foreground">
              Will use your email domain: <span className="font-mono">@{userDomain}</span>
            </p>
          )}
          {isPublicDomain && isEnabled && (
            <p className="text-xs text-muted-foreground">
              You can disable auto-join but cannot re-enable it with a public email domain.
            </p>
          )}
        </div>
        <Button
          variant={isEnabled ? 'outline' : 'default'}
          onClick={handleToggle}
          disabled={isPending || (!isEnabled && isPublicDomain)}
        >
          {isPending ? 'Saving...' : isEnabled ? 'Disable' : 'Enable'}
        </Button>
      </div>
    </div>
  )
}

export function SettingsPage() {
  const { orgId, orgName, projectNames, environmentCount, secretCount } = useLoaderData('/dash/projects/:projectId/settings')
  const [open, setOpen] = useState(false)
  // Deleting takes the organization's name, typed out: it can't be undone
  const [typedName, setTypedName] = useState('')
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleDelete() {
    setDeleteError(null)
    startTransition(async () => {
      try {
        await withStepUp(() => deleteOrgAction({ orgId, typedName }))
      } catch (e) {
        setDeleteError(e instanceof Error ? e.message : 'Deleting failed')
      }
    })
  }

  const [leaveError, setLeaveError] = useState<string | null>(null)
  function handleLeave() {
    if (!confirm(`Leave ${orgName}? You lose access to its projects, and your API tokens for them stop working. Only an invitation brings you back.`)) return
    setLeaveError(null)
    startTransition(async () => {
      const result = await leaveOrgAction({ orgId })
      if (result?.error) setLeaveError(result.error)
    })
  }

  return (
    <div className="flex flex-col gap-8 w-full max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Manage your organization settings.
        </p>
      </div>

      <AutoJoinSection />

      <div className="rounded-lg border border-destructive/40">
        <div className="p-5">
          <h2 className="text-lg font-semibold text-destructive flex items-center gap-2">
            <AlertTriangleIcon className="size-5" />
            Danger Zone
          </h2>
          <p className="text-muted-foreground text-sm mt-2">
            Deleting this organization is permanent. All projects, environments,
            secrets, tokens, and member access will be removed immediately.
          </p>
        </div>
        <div className="border-t border-destructive/40 px-5 py-4 flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium">Leave organization</p>
            <p className="text-xs text-muted-foreground">
              {leaveError ?? 'Only an invitation brings you back. The last admin can\'t leave.'}
            </p>
          </div>
          <Button variant="outline" disabled={isPending} onClick={handleLeave}>
            Leave organization
          </Button>
        </div>
        <div className="border-t border-destructive/40 px-5 py-4 bg-destructive/5 rounded-b-lg flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Delete this organization</p>
            <p className="text-xs text-muted-foreground">
              Deletes {orgName} with all its projects, not only this one. It can't be undone.
            </p>
          </div>
          <Dialog open={open} onOpenChange={(next) => { setOpen(next); setTypedName(''); setDeleteError(null) }}>
            <Button
              variant="destructive"
              onClick={() => setOpen(true)}
            >
              Delete organization
            </Button>
            <DialogPopup>
              <DialogHeader>
                <DialogTitle>Delete the organization {orgName}?</DialogTitle>
                <DialogDescription>
                  This deletes the whole organization, not only this project, and it can't be undone.
                </DialogDescription>
              </DialogHeader>
              <div className="px-6 pb-4">
                {projectNames.length > 0 ? (
                  <div>
                    <p className="text-sm font-medium mb-2">
                      The following {projectNames.length === 1 ? 'project' : `${projectNames.length} projects`} will be deleted:
                    </p>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      {projectNames.map((name) => (
                        <li key={name} className="flex items-center gap-2">
                          <span className="size-1.5 rounded-full bg-destructive shrink-0" />
                          {name}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    This organization has no projects.
                  </p>
                )}
                <p className="text-sm text-muted-foreground mt-3">
                  With them go {environmentCount} {environmentCount === 1 ? 'environment' : 'environments'} and{' '}
                  <strong className="text-foreground">{secretCount} {secretCount === 1 ? 'secret' : 'secrets'}</strong>,
                  their history, every member's access, invitations and API tokens.
                </p>
                <label className="flex flex-col gap-1.5 mt-4 text-sm">
                  <span>Type <strong className="mono-sm">{orgName}</strong> to confirm</span>
                  <Input value={typedName} onChange={(e) => setTypedName(e.target.value)} autoComplete="off" spellCheck={false} />
                </label>
                {deleteError && <p className="text-sm text-destructive mt-2">{deleteError}</p>}
              </div>
              <DialogFooter>
                <DialogClose
                  render={<Button variant="outline" />}
                >
                  Cancel
                </DialogClose>
                <Button
                  variant="destructive"
                  onClick={handleDelete}
                  disabled={isPending || typedName !== orgName}
                >
                  {isPending ? 'Deleting...' : 'Delete organization'}
                </Button>
              </DialogFooter>
            </DialogPopup>
          </Dialog>
        </div>
      </div>
    </div>
  )
}
