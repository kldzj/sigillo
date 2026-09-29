// Changes | Reads switch of the History tab: an environment's two signed
// chains, its secret changes (secret_event) and the reads of its values
// (secret_read, protected environments only).

"use client"

import { Link, router } from "spiceflow/react"
import { cn } from "sigillo-app/src/lib/utils"

export function HistorySwitch({ projectId, envSlug, active }: { projectId: string; envSlug: string; active: "changes" | "reads" }) {
  const views = [
    { key: "changes", label: "Changes", href: router.href("/dash/projects/:projectId/envs/:envSlug/history", { projectId, envSlug }) },
    { key: "reads", label: "Reads", href: router.href("/dash/projects/:projectId/envs/:envSlug/history/reads", { projectId, envSlug }) },
  ] as const
  return (
    <div className="inline-flex min-h-8 items-stretch gap-0.5 rounded-lg border border-input p-0.5 text-sm sm:min-h-7">
      {views.map((view) => (
        <Link
          key={view.key}
          href={view.href}
          className={cn(
            "flex items-center rounded-md px-2.5 no-underline transition-colors",
            view.key === active ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
          )}
        >
          {view.label}
        </Link>
      ))}
    </div>
  )
}
