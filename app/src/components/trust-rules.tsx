// Workload identities on the Machines tab: trust rules that let a GitHub
// Actions job or a Kubernetes pod exchange the JWT its platform issues for a
// token of one hour (app/src/workload.ts), so no token is stored anywhere.
// Org admins only, and every change takes their passkey. Presets fill the
// issuer, subject and claims for GitHub and Kubernetes. A rule is renewed in
// place, keeping its id, after the renewal dialog has shown how it was used.

"use client"

import { useState } from "react"
import type * as React from "react"
import { useLoaderData } from "spiceflow/react"
import { PlusIcon, TrashIcon, CopyIcon, CheckIcon, HistoryIcon, KeyRoundIcon, CalendarPlusIcon } from "lucide-react"
import { Button } from "sigillo-app/src/components/ui/button"
import { Badge } from "sigillo-app/src/components/ui/badge"
import { Frame } from "sigillo-app/src/components/ui/frame"
import { Input, Textarea } from "sigillo-app/src/components/ui/input"
import {
  Dialog, DialogPopup, DialogHeader, DialogTitle,
  DialogDescription, DialogFooter, DialogClose, DialogPanel,
} from "sigillo-app/src/components/ui/dialog"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "sigillo-app/src/components/ui/table"
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago"
import { cn, DOCS_URL, GITHUB_ISSUER, TOKEN_EXPIRY_DAYS, MACHINE_TOKEN_MAX_DAYS, formatIp } from "sigillo-app/src/lib/utils"
import { createTrustRuleAction, deleteTrustRuleAction, renewTrustRuleAction, replaceTrustRuleKeysAction, trustRuleEvidenceAction } from "../actions.ts"
import { withStepUp } from "./step-up.ts"
import { ExpiryBadge, utcDate } from "./expiry.tsx"

const CLUSTER_ISSUER = "https://kubernetes.default.svc.cluster.local"

type Rule = ReturnType<typeof useRules>[number]

function useRules() {
  return useLoaderData("/dash/projects/:projectId/machines").rules
}

export function WorkloadIdentities() {
  const rules = useRules()
  const [createOpen, setCreateOpen] = useState(false)
  return (
    <section className="flex flex-col gap-3 mt-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold tracking-tight">Workload identities</h2>
          <p className="text-sm text-muted-foreground">
            A GitHub Actions job or a Kubernetes pod gets a token of one hour for the JWT its platform issues, so
            no token is stored anywhere. <a className="underline" href={`${DOCS_URL}/docs/workload-identity`}>How it works</a>
          </p>
        </div>
        <Button variant="outline" onClick={() => setCreateOpen(true)}>
          <PlusIcon className="size-4" />
          Add trust rule
        </Button>
      </div>
      {rules.length > 0 && <RulesTable rules={rules} />}
      <CreateRuleDialog open={createOpen} onOpenChange={setCreateOpen} />
    </section>
  )
}

function issuerLabel(rule: Rule) {
  if (rule.issuer === GITHUB_ISSUER) return "GitHub Actions"
  if (!rule.discovered) return `${rule.issuer.replace(/^https:\/\//, "")} (pasted keys${rule.keyIds.length ? `: ${rule.keyIds.join(", ")}` : ""})`
  return rule.issuer.replace(/^https:\/\//, "")
}

function RulesTable({ rules }: { rules: Rule[] }) {
  const { environments } = useLoaderData("/dash/projects/:projectId/machines")
  const [history, setHistory] = useState<Rule | null>(null)
  const [keysFor, setKeysFor] = useState<Rule | null>(null)
  const [renewing, setRenewing] = useState<Renewal | null>(null)
  // The renewal dialog opens at once, and shows the rule's use once looked up
  async function renew(rule: Rule) {
    setRenewing({ rule, evidence: null, error: null })
    try {
      const evidence = await trustRuleEvidenceAction({ ruleId: rule.id })
      setRenewing((current) => current && current.rule.id === rule.id ? { ...current, evidence } : current)
    } catch (e: any) {
      setRenewing((current) => current && current.rule.id === rule.id ? { ...current, error: e?.message || "Failed to look up how it was used" } : current)
    }
  }
  const [copied, setCopied] = useState<string | null>(null)
  const scope = (rule: Rule) => rule.environmentIds.length === 0
    ? "All environments"
    : rule.environmentIds.map((id) => environments.find((env) => env.id === id)?.name ?? "Deleted").join(", ")
  return (
    <Frame className="w-full">
      <Table className="table-fixed min-w-3xl">
        <colgroup>
          <col className="w-1/5" />
          <col className="w-1/6" />
          <col className="w-1/5" />
          <col className="w-1/8" />
          <col className="w-28" />
          <col className="w-24" />
          <col className="w-32" />
        </colgroup>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>Name</TableHead>
            <TableHead>Issuer</TableHead>
            <TableHead>Subject</TableHead>
            <TableHead>Scope</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Last used</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <span className="flex items-center gap-2 text-sm font-medium">
                  <span className="truncate" title={ruleTitle(rule)}>{rule.name}</span>
                  {rule.protectedAccess && (
                    <Badge variant="secondary" title="Its tokens read and change protected environments">Protected</Badge>
                  )}
                </span>
              </TableCell>
              <TableCell>
                <span className="block truncate text-sm text-muted-foreground" title={`${rule.issuer}, audience ${rule.audience}`}>{issuerLabel(rule)}</span>
              </TableCell>
              <TableCell>
                <code
                  className="block truncate text-xs text-muted-foreground mono-sm"
                  title={[rule.subject, ...Object.entries(rule.claims).map(([name, value]) => `${name} = ${value}`)].join("\n")}
                >
                  {rule.subject}{Object.keys(rule.claims).length > 0 && ` +${Object.keys(rule.claims).length}`}
                </code>
              </TableCell>
              <TableCell>
                <span className="text-sm text-muted-foreground">{scope(rule)}</span>
              </TableCell>
              <TableCell>
                <ExpiryBadge expiresAt={rule.expiresAt} expiry={rule.expiry} />
              </TableCell>
              <TableCell>
                {rule.lastUsedAt === null
                  ? <span className="text-muted-foreground text-xs">Never</span>
                  : <TimeAgo ts={rule.lastUsedAt} className="text-muted-foreground text-xs tabular-nums" />}
              </TableCell>
              <TableCell className="p-0">
                <span className="flex items-center gap-2.5">
                  <button
                    onClick={async () => {
                      await navigator.clipboard.writeText(rule.id)
                      setCopied(rule.id)
                      setTimeout(() => setCopied(null), 2000)
                    }}
                    className="text-muted-foreground hover:text-foreground cursor-pointer"
                    title="Copy its ID, the identity External Secrets Operator names"
                  >
                    {copied === rule.id ? <CheckIcon className="size-3.5" /> : <CopyIcon className="size-3.5" />}
                  </button>
                  <button onClick={() => setHistory(rule)} className="text-muted-foreground hover:text-foreground cursor-pointer" title="Recent tokens">
                    <HistoryIcon className="size-3.5" />
                  </button>
                  <button onClick={() => renew(rule)} className="text-muted-foreground hover:text-foreground cursor-pointer" title="Renew: a new expiry for the same rule">
                    <CalendarPlusIcon className="size-3.5" />
                  </button>
                  {!rule.discovered && (
                    <button onClick={() => setKeysFor(rule)} className="text-muted-foreground hover:text-foreground cursor-pointer" title="Paste new keys">
                      <KeyRoundIcon className="size-3.5" />
                    </button>
                  )}
                  <button
                    onClick={async () => {
                      if (!confirm(`Delete the trust rule "${rule.name}"? Its tokens stop working at once.`)) return
                      try {
                        await withStepUp(() => deleteTrustRuleAction({ ruleId: rule.id }))
                      } catch (e: any) {
                        alert(e?.message || "Failed to delete the trust rule")
                      }
                    }}
                    className="text-muted-foreground hover:text-destructive cursor-pointer"
                    title="Delete trust rule"
                  >
                    <TrashIcon className="size-3.5" />
                  </button>
                </span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <HistoryDialog rule={history} onClose={() => setHistory(null)} />
      <KeysDialog rule={keysFor} onClose={() => setKeysFor(null)} />
      <RenewDialog renewal={renewing} onClose={() => setRenewing(null)} />
    </Frame>
  )
}

// Its owner, whose access its tokens act with, and its renewals
function ruleTitle(rule: Rule) {
  const renewed = rule.renewedAt === null ? "" : `, renewed ${rule.renewals === 1 ? "once" : `${rule.renewals} times`}, last ${utcDate(rule.renewedAt)}`
  return `Owned by ${rule.createdBy}, made ${utcDate(rule.createdAt)}${renewed}`
}

type Evidence = Awaited<ReturnType<typeof trustRuleEvidenceAction>>
type Renewal = { rule: Rule; evidence: Evidence | null; error: string | null }

// A rule is renewed from what it did, not from memory: first how it was
// used and by which workloads, and what looks stale, then its new expiry.
// Renewing keeps its ID, so nothing that uses it changes, and makes it the
// renewing admin's.
function RenewDialog({ renewal, onClose }: { renewal: Renewal | null; onClose: () => void }) {
  const { environments } = useLoaderData("/dash/projects/:projectId/machines")
  const [expiresInDays, setExpiresInDays] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const rule = renewal?.rule
  const evidence = renewal?.evidence
  const maxDays = rule?.protectedAccess ? MACHINE_TOKEN_MAX_DAYS : Infinity
  // Its lifetime so far, as far as it may have it
  const days = expiresInDays ?? TOKEN_EXPIRY_DAYS.filter((option) => option <= maxDays)
    .reduce((best, option) => Math.abs(option - (rule?.lifetimeDays ?? 0)) < Math.abs(best - (rule?.lifetimeDays ?? 0)) ? option : best)

  function close() {
    setExpiresInDays(null)
    setError(null)
    onClose()
  }

  const scope = !rule ? "" : rule.environmentIds.length === 0
    ? "All environments"
    : rule.environmentIds.map((id) => environments.find((env) => env.id === id)?.name ?? "Deleted").join(", ")
  const facts: Array<[string, React.ReactNode]> = !rule ? [] : [
    ["Issuer", <>
      {rule.issuer}
      <span className="block text-muted-foreground">
        {rule.discovered
          ? <>Keys from its discovery document{evidence?.keys.fetchedAt ? <>, last fetched <TimeAgo ts={evidence.keys.fetchedAt} /></> : null}; fetched again on renewal</>
          : `Pasted keys${rule.keyIds.length ? `: ${rule.keyIds.join(", ")}` : ""}`}
      </span>
    </>],
    ["Audience", rule.audience],
    ["Subject", rule.subject],
    ...Object.entries(rule.claims).map(([name, value]): [string, React.ReactNode] => [name, String(value)]),
    ["Environments", `${scope}${rule.protectedAccess ? ", protected ones too" : ""}`],
    ["Owner", <>
      {rule.createdBy}
      <span className="block text-muted-foreground">
        made <TimeAgo ts={rule.createdAt} />
        {rule.renewedAt !== null && <>, renewed {rule.renewals === 1 ? "once" : `${rule.renewals} times`}, last <TimeAgo ts={rule.renewedAt} /></>}
      </span>
    </>],
  ]

  return (
    <Dialog open={renewal !== null} onOpenChange={(open) => { if (!open) close() }}>
      <DialogPopup className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="break-words">Renew {rule?.name}</DialogTitle>
          <DialogDescription>
            Check that it still names the right workload. Renewing keeps its ID, so nothing that uses it changes, and makes the rule
            yours: its tokens act for you from then on.
          </DialogDescription>
        </DialogHeader>
        <DialogPanel className="flex flex-col gap-4 text-sm">
          <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
            {facts.map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-xs text-muted-foreground wrap-anywhere">{label}</dt>
                <dd className="wrap-anywhere">{value}</dd>
              </div>
            ))}
          </dl>

          {renewal?.error && <p className="text-destructive">{renewal.error}</p>}
          {!evidence && !renewal?.error && <p className="text-muted-foreground">Looking up how it was used…</p>}
          {evidence && <>
            {evidence.warnings.length > 0 && (
              <ul className="flex flex-col gap-1 rounded-md bg-(--warning)/8 px-3 py-2 text-(--warning-foreground)">
                {evidence.warnings.map((warning) => <li key={warning}>{warning}</li>)}
              </ul>
            )}
            <div className="flex flex-col gap-1.5">
              <p className="font-medium">Use</p>
              <p className="text-muted-foreground">
                {evidence.exchanges.total === 0
                  ? "No workload has got a token under it."
                  : `${evidence.exchanges.lastMonth} ${evidence.exchanges.lastMonth === 1 ? "token" : "tokens"} in the last 30 days, ${evidence.exchanges.total} in all.`}
              </p>
              {evidence.exchanges.last.map((token) => (
                <div key={token.id} className="flex items-baseline justify-between gap-3">
                  <span className="min-w-0 truncate" title={token.name}>{token.name}</span>
                  <span className="flex shrink-0 items-baseline gap-2 text-xs text-muted-foreground">
                    <TimeAgo ts={token.createdAt} className="tabular-nums" />
                    {token.ipAddress && <span className="mono-sm">{formatIp(token.ipAddress)}</span>}
                  </span>
                </div>
              ))}
            </div>
            {evidence.seen.length > 0 && (
              <div className="flex flex-col gap-1">
                <p className="font-medium">Seen in its last {Math.min(evidence.exchanges.total, 100)} tokens</p>
                {evidence.seen.map((seen) => (
                  <p key={seen.label} className="break-words">
                    <span className="text-muted-foreground">{seen.label}: </span>
                    {seen.values.slice(0, 10).join(", ")}
                    {seen.values.length > 10 && `, and ${seen.values.length - 10} more`}
                  </p>
                ))}
              </div>
            )}
          </>}

          <div>
            <p className="font-medium mb-2">Expires in</p>
            <div className="grid grid-cols-4 gap-1.5">
              {TOKEN_EXPIRY_DAYS.map((option) => (
                <label
                  key={option}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-md px-2 py-2 cursor-pointer transition-colors text-sm font-medium whitespace-nowrap",
                    days === option ? "bg-primary/5" : "hover:bg-muted/50",
                    option > maxDays && "opacity-50 cursor-not-allowed",
                  )}
                >
                  <input type="radio" name="renew-expiry" checked={days === option} disabled={option > maxDays} onChange={() => setExpiresInDays(option)} className="accent-primary" />
                  {option === 365 ? "1 year" : `${option} days`}
                </label>
              ))}
            </div>
            {rule?.protectedAccess && <p className="text-xs text-muted-foreground mt-2">A rule for protected environments expires after {MACHINE_TOKEN_MAX_DAYS} days at most.</p>}
          </div>
          {error && <p className="text-destructive">{error}</p>}
        </DialogPanel>
        <DialogFooter>
          <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
          <Button
            disabled={saving || !evidence}
            onClick={async () => {
              if (!rule) return
              setSaving(true)
              setError(null)
              try {
                const renewed = await withStepUp(() => renewTrustRuleAction({ ruleId: rule.id, expiresInDays: days }))
                if (renewed) close()
              } catch (e: any) {
                setError(e?.message || "Failed to renew the trust rule")
              } finally {
                setSaving(false)
              }
            }}
          >
            Renew
          </Button>
        </DialogFooter>
      </DialogPopup>
    </Dialog>
  )
}

// The tokens workloads got under a rule, newest first
function HistoryDialog({ rule, onClose }: { rule: Rule | null; onClose: () => void }) {
  return (
    <Dialog open={rule !== null} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Recent tokens of {rule?.name}</DialogTitle>
          <DialogDescription>The last 20 jobs or pods that got a token under this rule.</DialogDescription>
        </DialogHeader>
        <div className="px-6 pb-6 flex flex-col gap-2">
          {rule?.exchanges.length === 0 && <p className="text-sm text-muted-foreground">None yet.</p>}
          {rule?.exchanges.map((token) => (
            <div key={token.id} className="flex items-baseline justify-between gap-3 text-sm">
              <span className="truncate" title={token.name}>{token.name.replace(`${rule.name} · `, "")}</span>
              <span className="flex shrink-0 items-baseline gap-2 text-xs text-muted-foreground">
                <TimeAgo ts={token.createdAt} className="tabular-nums" />
                {token.lastUsedIp && <span className="mono-sm">{formatIp(token.lastUsedIp)}</span>}
                {token.expiresAt !== null && token.expiresAt > Date.now() && <Badge variant="secondary">Valid</Badge>}
              </span>
            </div>
          ))}
        </div>
      </DialogPopup>
    </Dialog>
  )
}

// After a private cluster rotates its signing key
function KeysDialog({ rule, onClose }: { rule: Rule | null; onClose: () => void }) {
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  return (
    <Dialog open={rule !== null} onOpenChange={(open) => { if (!open) { setError(null); onClose() } }}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>New keys for {rule?.name}</DialogTitle>
          <DialogDescription>
            After the cluster rotates its signing key, paste what <code className="mono-sm">kubectl get --raw /openid/v1/jwks</code> prints now.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2"
          action={async (formData: FormData) => {
            setSaving(true)
            setError(null)
            try {
              const done = await withStepUp(() => replaceTrustRuleKeysAction({ ruleId: rule!.id, jwks: String(formData.get("jwks") ?? "") }))
              if (done) onClose()
            } catch (e: any) {
              setError(e?.message || "Failed to save the keys")
            } finally {
              setSaving(false)
            }
          }}
        >
          {error && <p className="text-sm text-destructive mb-3">{error}</p>}
          <Textarea name="jwks" rows={6} required className="mono-sm text-xs" placeholder='{"keys":[{"use":"sig","kty":"RSA","kid":"…"}]}' />
          <DialogFooter variant="bare" className="mt-4">
            <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
            <Button type="submit" disabled={saving}>Save keys</Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  )
}

type Preset = "github" | "kubernetes" | "other"

function Field({ label, hint, children }: { label: string; hint?: React.ReactNode; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-sm font-medium">{label}</span>
      {children}
      {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
    </label>
  )
}

function Choice({ checked, onChange, children }: { checked: boolean; onChange: () => void; children: React.ReactNode }) {
  return (
    <label className={cn("flex items-center gap-2 rounded-md px-3 py-2 cursor-pointer transition-colors text-sm font-medium", checked ? "bg-primary/5" : "hover:bg-muted/50")}>
      <input type="radio" checked={checked} onChange={onChange} className="accent-primary" />
      {children}
    </label>
  )
}

function CreateRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { projectId, environments, origin } = useLoaderData("/dash/projects/:projectId/machines")
  const [preset, setPreset] = useState<Preset>("github")
  const [fields, setFields] = useState<Record<string, string>>({})
  const [pasteKeys, setPasteKeys] = useState(true)
  const [idsInSubject, setIdsInSubject] = useState(true)
  const [scope, setScope] = useState<"all" | "selected">("selected")
  const [checked, setChecked] = useState<Record<string, boolean>>({})
  const [protectedAccess, setProtectedAccess] = useState(false)
  const [expiresInDays, setExpiresInDays] = useState(MACHINE_TOKEN_MAX_DAYS)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const field = (name: string) => fields[name]?.trim() ?? ""
  const input = (name: string, props: React.ComponentProps<typeof Input> = {}) => (
    <Input value={fields[name] ?? ""} onChange={(e) => setFields((prev) => ({ ...prev, [name]: e.target.value }))} {...props} />
  )

  function reset(nextOpen: boolean) {
    if (!nextOpen) {
      setPreset("github")
      setFields({})
      setPasteKeys(true)
      setIdsInSubject(true)
      setScope("selected")
      setChecked({})
      setProtectedAccess(false)
      setExpiresInDays(MACHINE_TOKEN_MAX_DAYS)
      setError(null)
    }
    onOpenChange(nextOpen)
  }

  // What the preset's fields mean as a rule
  function ruleFields(): { issuer: string; subject: string; claims: Record<string, string>; jwks?: string } {
    if (preset === "github") {
      const repository = field("repository")
      if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw new Error("Name the repository as owner/name")
      const [owner, name] = repository.split("/")
      const [ownerId, repositoryId] = [field("ownerId"), field("repositoryId")]
      if (!/^\d+$/.test(repositoryId) || (idsInSubject && !/^\d+$/.test(ownerId))) {
        throw new Error(idsInSubject ? "Give the owner's and the repository's IDs" : "Give the repository's ID")
      }
      const where = field("environment") ? `environment:${field("environment")}` : `ref:refs/heads/${field("branch") || "main"}`
      // With names in the subject, the ID is what tells a repository apart
      // from one that takes over its name after a rename
      return idsInSubject
        ? { issuer: GITHUB_ISSUER, subject: `repo:${owner}@${ownerId}/${name}@${repositoryId}:${where}`, claims: {} }
        : { issuer: GITHUB_ISSUER, subject: `repo:${repository}:${where}`, claims: { repository_id: repositoryId } }
    }
    if (preset === "kubernetes") {
      if (protectedAccess && !field("uid")) throw new Error("A rule for protected environments needs the service account's UID")
      return {
        issuer: field("issuer") || CLUSTER_ISSUER,
        subject: `system:serviceaccount:${field("namespace")}:${field("serviceAccount")}`,
        claims: field("uid") ? { "/kubernetes.io/serviceaccount/uid": field("uid") } : {},
        jwks: pasteKeys ? field("jwks") : undefined,
      }
    }
    const claims: Record<string, string> = {}
    for (const line of field("claims").split("\n").map((l) => l.trim()).filter(Boolean)) {
      const at = line.indexOf("=")
      if (at < 1) throw new Error(`Write each claim as name=value: ${line}`)
      claims[line.slice(0, at).trim()] = line.slice(at + 1).trim()
    }
    return { issuer: field("issuer"), subject: field("subject"), claims, jwks: pasteKeys ? field("jwks") : undefined }
  }

  const githubWithoutEnvironment = preset === "github" && protectedAccess && !field("environment")

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogPopup className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Add trust rule</DialogTitle>
          <DialogDescription>
            Which workload may get a token, and for what. Its JWT must match every field exactly.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2 flex flex-col gap-3"
          action={async () => {
            setError(null)
            let rule
            try {
              rule = ruleFields()
            } catch (e: any) {
              setError(e.message)
              return
            }
            const environmentIds = scope === "all" ? [] : environments.filter((env) => checked[env.id]).map((env) => env.id)
            if (scope === "selected" && environmentIds.length === 0) {
              setError("Select at least one environment")
              return
            }
            setSaving(true)
            try {
              const created = await withStepUp(() => createTrustRuleAction({
                projectId,
                name: field("name"),
                audience: field("audience") || origin,
                environmentIds,
                protectedAccess,
                expiresInDays,
                ...rule,
              }))
              if (created) reset(false)
            } catch (e: any) {
              setError(e?.message || "Failed to add the trust rule")
            } finally {
              setSaving(false)
            }
          }}
        >
          {error && <p className="text-sm text-destructive">{error}</p>}
          <div className="grid grid-cols-3 gap-1.5">
            <Choice checked={preset === "github"} onChange={() => setPreset("github")}>GitHub Actions</Choice>
            <Choice checked={preset === "kubernetes"} onChange={() => setPreset("kubernetes")}>Kubernetes</Choice>
            <Choice checked={preset === "other"} onChange={() => setPreset("other")}>Other issuer</Choice>
          </div>
          <Field label="Name">{input("name", { placeholder: "e.g. Deploy from main", required: true })}</Field>

          {preset === "github" && <>
            <Field label="Repository">{input("repository", { placeholder: "acme/api", required: true })}</Field>
            <Field label="GitHub environment" hint="Jobs that declare this environment. Empty: jobs on the branch below.">
              {input("environment", { placeholder: "production" })}
            </Field>
            {!field("environment") && <Field label="Branch">{input("branch", { placeholder: "main" })}</Field>}
            <div className="grid grid-cols-2 gap-1.5">
              <Choice checked={idsInSubject} onChange={() => setIdsInSubject(true)}>IDs in the subject</Choice>
              <Choice checked={!idsInSubject} onChange={() => setIdsInSubject(false)}>Names in the subject</Choice>
            </div>
            <p className="text-xs text-muted-foreground -mt-1.5">
              Repositories created or renamed since 15 July 2026 have IDs in their subject, older ones names, unless switched to IDs in their OIDC settings.
            </p>
            <div className={cn("grid gap-3", idsInSubject && "grid-cols-2")}>
              {idsInSubject && <Field label="Owner ID">{input("ownerId", { placeholder: "65", inputMode: "numeric", required: true })}</Field>}
              <Field label="Repository ID">{input("repositoryId", { placeholder: "74", inputMode: "numeric", required: true })}</Field>
            </div>
            <p className="text-xs text-muted-foreground -mt-1.5">
              <code className="mono-sm">gh api repos/{field("repository") || "acme/api"} --jq '.owner.id, .id'</code> prints both.
            </p>
          </>}

          {preset === "kubernetes" && <>
            <Field label="Issuer" hint={<><code className="mono-sm">kubectl get --raw /.well-known/openid-configuration</code> shows it.</>}>
              {input("issuer", { placeholder: CLUSTER_ISSUER })}
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Namespace">{input("namespace", { placeholder: "payments", required: true })}</Field>
              <Field label="Service account">{input("serviceAccount", { placeholder: "api", required: true })}</Field>
            </div>
            <Field label="Service account UID" hint="So a service account deleted and made again under the same name isn't trusted. Needed for protected environments.">
              {input("uid", { placeholder: "kubectl get serviceaccount api -n payments -o jsonpath='{.metadata.uid}'" })}
            </Field>
          </>}

          {preset === "other" && <>
            <Field label="Issuer">{input("issuer", { placeholder: "https://gitlab.com", required: true })}</Field>
            <Field label="Subject">{input("subject", { placeholder: "project_path:acme/api:ref_type:branch:ref:main", required: true })}</Field>
            <Field label="Further claims" hint="One name=value per line. Nested claims by JSON pointer: /kubernetes.io/namespace=payments">
              <Textarea rows={2} value={fields.claims ?? ""} onChange={(e) => setFields((prev) => ({ ...prev, claims: e.target.value }))} className="mono-sm text-xs" />
            </Field>
          </>}

          {preset !== "github" && <>
            <div className="grid grid-cols-2 gap-1.5">
              <Choice checked={pasteKeys} onChange={() => setPasteKeys(true)}>Paste its keys</Choice>
              <Choice checked={!pasteKeys} onChange={() => setPasteKeys(false)}>Public issuer</Choice>
            </div>
            {pasteKeys
              ? <Field label="Keys" hint={<>For a cluster Cloudflare can't reach: what <code className="mono-sm">kubectl get --raw /openid/v1/jwks</code> prints.</>}>
                <Textarea rows={3} required value={fields.jwks ?? ""} onChange={(e) => setFields((prev) => ({ ...prev, jwks: e.target.value }))} className="mono-sm text-xs" placeholder='{"keys":[…]}' />
              </Field>
              : <p className="text-xs text-muted-foreground">The keys come from the issuer's OIDC discovery document, as for EKS, GKE and AKS.</p>}
          </>}

          <Field label="Audience" hint="What the workload asks its platform to put in the JWT's aud.">
            {input("audience", { placeholder: origin })}
          </Field>

          <div>
            <p className="text-sm font-medium mb-1.5">Environments</p>
            <div className="grid grid-cols-2 gap-1.5">
              <Choice checked={scope === "selected"} onChange={() => setScope("selected")}>Specific ones</Choice>
              <Choice checked={scope === "all"} onChange={() => setScope("all")}>All environments</Choice>
            </div>
            {scope === "selected" && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {environments.map((env) => (
                  <label key={env.id} className={cn("flex items-center gap-2 rounded-md px-3 py-1.5 cursor-pointer text-sm", checked[env.id] ? "bg-primary/5" : "hover:bg-muted/50")}>
                    <input type="checkbox" checked={checked[env.id] ?? false} onChange={() => setChecked((prev) => ({ ...prev, [env.id]: !prev[env.id] }))} className="accent-primary" />
                    {env.name}
                  </label>
                ))}
              </div>
            )}
          </div>

          <div>
            <p className="text-sm font-medium mb-1.5">Expires in</p>
            <div className="grid grid-cols-4 gap-1.5">
              {TOKEN_EXPIRY_DAYS.map((days) => (
                <label
                  key={days}
                  className={cn(
                    "flex items-center justify-center gap-2 rounded-md px-3 py-2 cursor-pointer transition-colors text-sm font-medium",
                    expiresInDays === days ? "bg-primary/5" : "hover:bg-muted/50",
                    protectedAccess && days > MACHINE_TOKEN_MAX_DAYS && "opacity-50 cursor-not-allowed",
                  )}
                >
                  <input
                    type="radio"
                    checked={expiresInDays === days}
                    disabled={protectedAccess && days > MACHINE_TOKEN_MAX_DAYS}
                    onChange={() => setExpiresInDays(days)}
                    className="accent-primary"
                  />
                  {days === 365 ? "1 year" : `${days} days`}
                </label>
              ))}
            </div>
          </div>

          <label className="flex items-start gap-3 rounded-md px-3 py-2 cursor-pointer hover:bg-muted/50 transition-colors">
            <input
              type="checkbox"
              checked={protectedAccess}
              onChange={(e) => {
                setProtectedAccess(e.target.checked)
                if (e.target.checked && expiresInDays > MACHINE_TOKEN_MAX_DAYS) setExpiresInDays(MACHINE_TOKEN_MAX_DAYS)
              }}
              className="accent-primary mt-0.5"
            />
            <span className="flex flex-col gap-0.5">
              <span className="text-sm font-medium">Protected environments</span>
              <span className="text-xs text-muted-foreground">
                Its tokens read and change protected environments, like a machine token. Expires after {MACHINE_TOKEN_MAX_DAYS} days at most.
              </span>
            </span>
          </label>
          {githubWithoutEnvironment && (
            <p className="text-xs text-(--warning-foreground)">
              Without a GitHub environment, anyone who can push to the branch reads these environments. Name an environment with required reviewers.
            </p>
          )}

          <DialogFooter variant="bare" className="mt-1">
            <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
            <Button type="submit" disabled={saving}>Add trust rule</Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  )
}
