// The Machines tab: API tokens with create/regenerate/delete, and workload
// identities. Each token is scoped to a project and optionally to an env
// allowlist (zero rows = all envs), and expires after a lifetime picked at
// creation. The full key is only shown once (never stored), so the create
// and regenerate dialogs have a "copy key" step before closing. Regenerating
// keeps the token and gives it a new value and expiry; its value before keeps
// working for a grace period, shown under its key with its last use.
// Admins can make a machine token, which uses protected environments without
// a passkey: it takes their own passkey approval for those environments
// first, and expires after 90 days at most. Below, admins manage workload
// identities (trust-rules.tsx).

"use client"

import { useState } from "react"
import { z } from "zod"
import { parseFormData } from "spiceflow"
import { useLoaderData } from "spiceflow/react"
import type * as React from "react"
import { KeyIcon, TrashIcon, PlusIcon, CopyIcon, CheckIcon, RotateCwIcon } from "lucide-react"
import { EmptyState } from "sigillo-app/src/components/ui/empty-state"
import { Button } from "sigillo-app/src/components/ui/button"
import { Badge } from "sigillo-app/src/components/ui/badge"
import { Frame } from "sigillo-app/src/components/ui/frame"
import { Input } from "sigillo-app/src/components/ui/input"
import {
  Dialog, DialogPopup, DialogHeader, DialogTitle,
  DialogDescription, DialogFooter, DialogClose,
} from "sigillo-app/src/components/ui/dialog"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "sigillo-app/src/components/ui/table"
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago"
import {
  cn, DOCS_URL, DEFAULT_GRACE_DAYS, DEFAULT_TOKEN_EXPIRY_DAYS, GRACE_DAYS, TOKEN_EXPIRY_DAYS, MACHINE_TOKEN_MAX_DAYS, formatAbsoluteDate, formatIp,
} from "sigillo-app/src/lib/utils"
import { createTokenAction, deleteTokenAction, regenerateTokenAction, stopPreviousValueAction } from "../actions.ts"
import { withStepUp } from "./step-up.ts"
import { ExpiryBadge, utcDate } from "./expiry.tsx"
import { WorkloadIdentities } from "./trust-rules.tsx"


export function TokensPage() {
  const { projectName, projectId, environments, tokens, isAdmin } = useLoaderData('/dash/projects/:projectId/machines')
  const [createOpen, setCreateOpen] = useState(false)

  return (
    <>
      <h1 className="text-2xl font-bold tracking-tight">{projectName}</h1>
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold tracking-tight">Tokens</h2>
          <p className="text-sm text-muted-foreground">
            For CI, servers and scripts: a token reads and changes this project's secrets through the API and the CLI.{" "}
            <a className="underline" href={`${DOCS_URL}/docs/ci`}>How to use one</a>
          </p>
        </div>
        <Button variant="outline" onClick={() => setCreateOpen(true)}>
          <PlusIcon className="size-4" />
          Create token
        </Button>
      </div>

      {tokens.length === 0 ? (
        <EmptyState
          icon={<KeyIcon className="size-6 text-muted-foreground" />}
          title="No API tokens yet"
          description="Create a token to access secrets programmatically via the API."
        >
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <PlusIcon className="size-4" />
            Create token
          </Button>
        </EmptyState>
      ) : (
        <TokensTable />
      )}

      <CreateTokenDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        projectId={projectId}
        environments={environments}
        isAdmin={isAdmin}
      />

      {isAdmin && <WorkloadIdentities />}
    </>
  )
}

function tokenScopeLabel(environmentNames: string[]) {
  if (environmentNames.length === 0) return "All environments"
  return environmentNames.join(", ")
}

type Token = ReturnType<typeof useTokens>[number]

function useTokens() {
  return useLoaderData('/dash/projects/:projectId/machines').tokens
}

// Who made it, and who regenerated it last
function tokenTitle(token: Token) {
  const regenerated = token.regeneratedAt === null ? "" : `, regenerated ${utcDate(token.regeneratedAt)} by ${token.regeneratedBy ?? "a former member"}`
  return `Made by ${token.createdBy}${regenerated}`
}

function TokensTable() {
  const tokens = useTokens()
  const [regenerating, setRegenerating] = useState<Token | null>(null)
  return (
    <Frame className="w-full">
      <Table className="table-fixed min-w-3xl">
        <colgroup>
          <col className="w-1/5" />
          <col className="w-1/4" />
          <col className="w-1/6" />
          <col className="w-24" />
          <col className="w-28" />
          <col className="w-28" />
          <col className="w-16" />
        </colgroup>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>Name</TableHead>
            <TableHead>Key</TableHead>
            <TableHead>Scope</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Last used</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {tokens.map((token) => (
            <TableRow key={token.id}>
              <TableCell>
                <span className="flex items-center gap-2 text-sm font-medium">
                  <span className="truncate" title={tokenTitle(token)}>{token.name}</span>
                  {token.protectedAccess && (
                    <Badge variant="secondary" title="Reads and changes protected environments without a passkey">Machine</Badge>
                  )}
                </span>
              </TableCell>
              <TableCell>
                <code className="text-xs text-muted-foreground mono-sm">
                  sig_{token.prefix}••••
                </code>
                {token.previous && <PreviousValue token={token} previous={token.previous} />}
              </TableCell>
              <TableCell>
                <span className="text-sm text-muted-foreground">
                  {tokenScopeLabel(token.environmentNames)}
                </span>
              </TableCell>
              <TableCell>
                <TimeAgo
                  ts={token.createdAt}
                  className="text-muted-foreground text-xs tabular-nums"
                />
              </TableCell>
              <TableCell>
                <ExpiryBadge expiresAt={token.expiresAt} expiry={token.expiry} />
              </TableCell>
              <TableCell>
                {token.lastUsedAt === null ? (
                  <span className="text-muted-foreground text-xs">Never</span>
                ) : (
                  <span className="flex flex-col">
                    <TimeAgo
                      ts={token.lastUsedAt}
                      className="text-muted-foreground text-xs tabular-nums"
                    />
                    {token.lastUsedIp && (
                      <span className="text-muted-foreground text-xs mono-sm truncate" title={token.lastUsedIp}>
                        {formatIp(token.lastUsedIp)}
                      </span>
                    )}
                  </span>
                )}
              </TableCell>
              <TableCell className="p-0">
                {token.deletable && (
                  <span className="flex items-center gap-2.5">
                    <button
                      onClick={() => setRegenerating(token)}
                      className="text-muted-foreground hover:text-foreground cursor-pointer"
                      title="Regenerate: a new value and expiry for the same token"
                    >
                      <RotateCwIcon className="size-3.5" />
                    </button>
                    <button
                      onClick={async () => {
                        if (confirm(`Delete token "${token.name}"? This cannot be undone.`)) {
                          try {
                            await withStepUp(() => deleteTokenAction({ tokenId: token.id }))
                          } catch (e: any) {
                            alert(e?.message || "Failed to delete token")
                          }
                        }
                      }}
                      className="text-muted-foreground hover:text-destructive cursor-pointer"
                      title="Delete token"
                    >
                      <TrashIcon className="size-3.5" />
                    </button>
                  </span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <RegenerateTokenDialog token={regenerating} onClose={() => setRegenerating(null)} />
    </Frame>
  )
}

// A regenerated token's value before, while it still works: its last use
// tells whether CI has switched over
function PreviousValue({ token, previous }: { token: Token; previous: NonNullable<Token["previous"]> }) {
  return (
    <span className="mt-1 block text-xs leading-snug whitespace-normal text-muted-foreground">
      previous value until <TimeAgo ts={previous.expiresAt} className="tabular-nums" />
      {" · "}
      {previous.lastUsedAt === null ? "never used" : (
        <>
          last used <TimeAgo ts={previous.lastUsedAt} className="tabular-nums" />
          {previous.lastUsedIp && <> from <span className="mono-sm" title={previous.lastUsedIp}>{formatIp(previous.lastUsedIp)}</span></>}
        </>
      )}
      {token.deletable && (
        <>
          {" · "}
          <button
            className="underline underline-offset-2 cursor-pointer hover:text-foreground"
            title="Stop the previous value now"
            onClick={async () => {
              if (!confirm(`Stop the previous value of "${token.name}" now? Whatever still uses it is refused from then on.`)) return
              try {
                await withStepUp(() => stopPreviousValueAction({ tokenId: token.id }))
              } catch (e: any) {
                alert(e?.message || "Failed to stop the previous value")
              }
            }}
          >
            Stop
          </button>
        </>
      )}
    </span>
  )
}

function localDate(ts: number) {
  return formatAbsoluteDate({ ts, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone })
}

// The expiry closest to the token's own lifetime, as far as it may have one
function nearestExpiry(days: number | null, machine: boolean): number {
  if (days === null) return DEFAULT_TOKEN_EXPIRY_DAYS
  const options = TOKEN_EXPIRY_DAYS.filter((option) => !machine || option <= MACHINE_TOKEN_MAX_DAYS)
  return options.reduce((best, option) => Math.abs(option - days) < Math.abs(best - days) ? option : best)
}

// Only open after a click, so reading the clock here is safe for hydration
function RegenerateTokenDialog({ token, onClose }: { token: Token | null; onClose: () => void }) {
  const [expiresInDays, setExpiresInDays] = useState<number | null>(null)
  const [graceDays, setGraceDays] = useState<number>(DEFAULT_GRACE_DAYS)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [created, setCreated] = useState<{ key: string; previousExpiresAt: number | null } | null>(null)

  function close() {
    setExpiresInDays(null)
    setGraceDays(DEFAULT_GRACE_DAYS)
    setError(null)
    setCreated(null)
    onClose()
  }

  // Only Done closes it, as after making a token
  if (token && created) {
    return (
      <Dialog open onOpenChange={() => {}}>
        <DialogPopup showCloseButton={false}>
          <NewKey title="Token regenerated" keyValue={created.key} onDone={close}>
            <p>
              {created.previousExpiresAt === null || created.previousExpiresAt <= Date.now()
                ? "Its previous value has stopped working."
                : `The previous value keeps working until ${localDate(created.previousExpiresAt)}: put the new one where the token is used before then.`}
            </p>
          </NewKey>
        </DialogPopup>
      </Dialog>
    )
  }

  const days = token ? expiresInDays ?? nearestExpiry(token.lifetimeDays, token.protectedAccess) : DEFAULT_TOKEN_EXPIRY_DAYS
  const now = Date.now()
  // When the current value stops: after the grace, never past its own expiry
  const currentEnds = !token || (token.expiresAt !== null && token.expiresAt <= now) ? null : Math.min(now + graceDays * 86_400_000, token.expiresAt ?? Infinity)
  const currentValue = currentEnds === null ? "Its current value has expired, so it stays stopped."
    : graceDays === 0 ? "Its current value stops working at once."
    : currentEnds === token?.expiresAt ? `Its current value keeps working until it expires on ${localDate(currentEnds)}.`
    : `Its current value keeps working until ${localDate(currentEnds)}.`

  return (
    <Dialog open={token !== null} onOpenChange={(open) => { if (!open) close() }}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle className="break-words">Regenerate {token?.name}</DialogTitle>
          <DialogDescription>
            A new value and expiry for the same token: its name, scope and history stay.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2 flex flex-col gap-3"
          action={async () => {
            if (!token) return
            setSaving(true)
            setError(null)
            try {
              const result = await withStepUp(() => regenerateTokenAction({ tokenId: token.id, prefix: token.prefix, expiresInDays: days, graceDays }))
              if (result) setCreated({ key: result.key, previousExpiresAt: result.previousExpiresAt })
            } catch (e: any) {
              setError(e?.message || "Failed to regenerate the token")
            } finally {
              setSaving(false)
            }
          }}
        >
          {error && <p className="text-sm text-destructive">{error}</p>}
          <div>
            <p className="text-sm font-medium mb-2">The new value expires in</p>
            <div className="grid grid-cols-4 gap-1.5">
              {TOKEN_EXPIRY_DAYS.map((option) => {
                const disabled = !!token?.protectedAccess && option > MACHINE_TOKEN_MAX_DAYS
                return (
                  <label
                    key={option}
                    className={cn(
                      "flex items-center justify-center gap-2 rounded-md px-2 py-2 cursor-pointer transition-colors text-sm font-medium whitespace-nowrap",
                      days === option ? "bg-primary/5" : "hover:bg-muted/50",
                      disabled && "opacity-50 cursor-not-allowed",
                    )}
                  >
                    <input type="radio" name="regenerate-expiry" checked={days === option} disabled={disabled} onChange={() => setExpiresInDays(option)} className="accent-primary" />
                    {option === 365 ? "1 year" : `${option} days`}
                  </label>
                )
              })}
            </div>
          </div>
          <div>
            <p className="text-sm font-medium mb-2">The current value keeps working for</p>
            <div className="grid grid-cols-3 gap-1.5">
              {GRACE_DAYS.map((option) => (
                <label
                  key={option}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-md px-2 py-2 cursor-pointer transition-colors text-sm font-medium whitespace-nowrap",
                    graceDays === option ? "bg-primary/5" : "hover:bg-muted/50",
                  )}
                >
                  <input type="radio" name="regenerate-grace" checked={graceDays === option} onChange={() => setGraceDays(option)} className="accent-primary" />
                  {option === 0 ? "No time" : option === 1 ? "1 day" : `${option} days`}
                </label>
              ))}
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              {currentValue}
              {token?.previous && " The value before its last regeneration stops at once."}
            </p>
          </div>
          {token?.protectedAccess && (
            <p className="text-xs text-muted-foreground">A machine token takes your passkey, and expires after {MACHINE_TOKEN_MAX_DAYS} days at most.</p>
          )}
          <DialogFooter variant="bare" className="mt-1">
            <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
            <Button type="submit" disabled={saving}>Regenerate</Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  )
}

// A new key, shown once, in the popup that made it: the same popup stays
// mounted, so closing it animates out. Only Done closes it, so the one copy
// isn't lost to a stray click or Escape.
function NewKey({ title, keyValue, onDone, children }: { title: string; keyValue: string; onDone: () => void; children: React.ReactNode }) {
  const [copied, setCopied] = useState(false)
  return (
    <>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>
          Copy this token now — you won't be able to see it again.
        </DialogDescription>
      </DialogHeader>
      <div className="px-6 pb-2">
        <div className="flex gap-2">
          <Input
            readOnly
            value={keyValue}
            className="w-full mono-sm text-xs"
            onClick={(e) => e.currentTarget.select()}
          />
          <Button
            variant="outline"
            size="icon"
            onClick={async () => {
              await navigator.clipboard.writeText(keyValue)
              setCopied(true)
              setTimeout(() => setCopied(false), 2000)
            }}
          >
            {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
          </Button>
        </div>
        <div className="text-xs text-muted-foreground mt-2 flex flex-col gap-1">{children}</div>
        <DialogFooter variant="bare" className="mt-4">
          <Button variant="outline" onClick={onDone}>
            Done
          </Button>
        </DialogFooter>
      </div>
    </>
  )
}

const tokenSchema = z.object({ name: z.string().min(1, "Name is required") })
const tokenFields = tokenSchema.keyof().enum

function CreateTokenDialog({
  open,
  onOpenChange,
  projectId,
  environments,
  isAdmin,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  projectId: string
  environments: { id: string; name: string; slug: string }[]
  isAdmin: boolean
}) {
  const [creating, setCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [scope, setScope] = useState<"all" | "selected">("all")
  const [checked, setChecked] = useState<Record<string, boolean>>({})
  const [expiresInDays, setExpiresInDays] = useState<number>(DEFAULT_TOKEN_EXPIRY_DAYS)
  const [machine, setMachine] = useState(false)

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) {
      setCreatedKey(null)
      setError(null)
      setScope("all")
      setChecked({})
      setExpiresInDays(DEFAULT_TOKEN_EXPIRY_DAYS)
      setMachine(false)
    }
    onOpenChange(nextOpen)
  }

  // After key is created, show the "copy key" step.
  // Ignore close requests from backdrop click / Escape so the only visible
  // copy of the token is not lost accidentally.
  if (createdKey) {
    return (
      <Dialog
        open={open}
        onOpenChange={(nextOpen) => {
          if (nextOpen) handleOpenChange(true)
        }}
      >
        <DialogPopup showCloseButton={false}>
          <NewKey title="Token created" keyValue={createdKey} onDone={() => handleOpenChange(false)}>
            <p>
              {machine
                ? "Store this key securely. It reads and changes this project's protected environments without a passkey."
                : "Store this key securely. It grants access to secrets in this project."}
            </p>
          </NewKey>
        </DialogPopup>
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Create API token</DialogTitle>
          <DialogDescription>
            Generate a token for programmatic access to secrets in this project.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2"
          action={async (formData: FormData) => {
            const { name } = parseFormData(tokenSchema, formData)
            const environmentIds = scope === "all"
              ? []
              : environments.filter((env) => checked[env.id]).map((env) => env.id)
            if (scope === "selected" && environmentIds.length === 0) {
              setError("Select at least one environment")
              return
            }
            setCreating(true)
            setError(null)
            try {
              // A machine token asks for your passkey
              const result = await withStepUp(() => createTokenAction({
                name: name.trim(),
                projectId,
                environmentIds,
                expiresInDays,
                protectedAccess: machine,
              }))
              if (result) setCreatedKey(result.key)
            } catch (e: any) {
              setError(e?.message || "Failed to create token")
            } finally {
              setCreating(false)
            }
          }}
        >
          {error && (
            <p className="text-sm text-destructive mb-3">{error}</p>
          )}
          <div className="flex flex-col gap-3">
            <div>
              <label htmlFor="token-name" className="text-sm font-medium mb-1 block">Name</label>
              <Input
                id="token-name"
                name={tokenFields.name}
                placeholder="e.g. CI/CD pipeline"
                required
                autoFocus
              />
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Environment scope</p>
              <div className="flex flex-col gap-1.5">
                <label className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors",
                  scope === "all" ? "bg-primary/5" : "hover:bg-muted/50",
                )}>
                  <input
                    type="radio"
                    name="token-scope"
                    checked={scope === "all"}
                    onChange={() => setScope("all")}
                    className="accent-primary"
                  />
                  <span className="text-sm font-medium">All environments</span>
                </label>
                <label className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors",
                  scope === "selected" ? "bg-primary/5" : "hover:bg-muted/50",
                )}>
                  <input
                    type="radio"
                    name="token-scope"
                    checked={scope === "selected"}
                    onChange={() => setScope("selected")}
                    className="accent-primary"
                  />
                  <span className="text-sm font-medium">Specific environments</span>
                </label>
              </div>
              {scope === "selected" && (
                <div className="mt-2 flex flex-col gap-1.5">
                  {environments.map((env) => {
                    const isChecked = checked[env.id] ?? false
                    return (
                      <label
                        key={env.id}
                        className={cn(
                          "flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors",
                          isChecked ? "bg-primary/5" : "hover:bg-muted/50",
                        )}
                      >
                        <span
                          className={cn(
                            "flex items-center justify-center size-4 rounded border transition-colors",
                            isChecked ? "bg-primary border-primary text-primary-foreground" : "border-input",
                          )}
                          aria-hidden
                        >
                          {isChecked && <CheckIcon className="size-3" />}
                        </span>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => setChecked((prev) => ({ ...prev, [env.id]: !prev[env.id] }))}
                          className="sr-only"
                        />
                        <span className="text-sm font-medium">{env.name}</span>
                      </label>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
          <div className="mt-3">
            <p className="text-sm font-medium mb-2">Expires in</p>
            <div className="grid grid-cols-4 gap-1.5">
              {TOKEN_EXPIRY_DAYS.map((days) => (
                <label
                  key={days}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-md px-3 py-2 cursor-pointer transition-colors text-sm font-medium",
                    expiresInDays === days ? "bg-primary/5" : "hover:bg-muted/50",
                    machine && days > MACHINE_TOKEN_MAX_DAYS && "opacity-50 cursor-not-allowed",
                  )}
                >
                  <input
                    type="radio"
                    name="token-expiry"
                    checked={expiresInDays === days}
                    disabled={machine && days > MACHINE_TOKEN_MAX_DAYS}
                    onChange={() => setExpiresInDays(days)}
                    className="accent-primary"
                  />
                  {days === 365 ? "1 year" : `${days} days`}
                </label>
              ))}
            </div>
          </div>
          {isAdmin && (
            <label className="mt-3 flex items-start gap-3 rounded-md px-3 py-2 cursor-pointer hover:bg-muted/50 transition-colors">
              <input
                type="checkbox"
                checked={machine}
                onChange={(e) => {
                  setMachine(e.target.checked)
                  if (e.target.checked && expiresInDays > MACHINE_TOKEN_MAX_DAYS) setExpiresInDays(MACHINE_TOKEN_MAX_DAYS)
                }}
                className="accent-primary mt-0.5"
              />
              <span className="flex flex-col gap-0.5">
                <span className="text-sm font-medium">Machine token</span>
                <span className="text-xs text-muted-foreground">
                  Reads and changes protected environments without a passkey, for CI and servers. Takes your
                  passkey, and expires after {MACHINE_TOKEN_MAX_DAYS} days at most.
                </span>
              </span>
            </label>
          )}
          <DialogFooter variant="bare" className="mt-4">
            <DialogClose render={<Button variant="outline" />}>
              Cancel
            </DialogClose>
            <Button type="submit" disabled={creating}>
              Create token
            </Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  )
}
