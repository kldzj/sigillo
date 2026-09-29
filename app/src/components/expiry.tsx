// When tokens and trust rules stop working: the Expires cell of the
// Machines tab, and the banner every dashboard page shows while something
// expires soon. Both judge by describeExpiry (lib/utils.ts), as the API's
// Sigillo-Warning header does; the loaders do the judging.

"use client"

import { useState } from "react"
import { Link, router } from "spiceflow/react"
import { TriangleAlertIcon, XIcon } from "lucide-react"
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago"
import { EXPIRY_BANNER_COOKIE, type ExpiryLevel } from "sigillo-app/src/lib/utils"

// The date as a title, the same on the server and in the browser
export function utcDate(ts: number) {
  return `${new Date(ts).toISOString().slice(0, 16).replace("T", " ")} UTC`
}

export function ExpiryBadge({ expiresAt, expiry }: { expiresAt: number | null; expiry: { text: string; level: ExpiryLevel } }) {
  if (expiresAt === null) {
    return <span className="text-(--warning-foreground) text-xs" title="Made before tokens expired: regenerate it to give it an expiry">Never</span>
  }
  if (expiry.level === "expired") return <span className="text-destructive text-xs" title={utcDate(expiresAt)}>Expired</span>
  if (expiry.level === "ok") return <TimeAgo ts={expiresAt} className="text-muted-foreground text-xs tabular-nums" />
  return (
    <span
      className="inline-flex rounded-sm bg-(--warning)/12 px-1.5 py-0.5 text-xs font-medium whitespace-nowrap text-(--warning-foreground)"
      title={`Expires ${utcDate(expiresAt)}`}
    >
      {expiry.text}
    </span>
  )
}

type Banner = {
  items: { kind: string; id: string; name: string; projectId: string; projectName: string; when: string }[]
  more: number
  // The soonest expiry it shows: dismissing hides it until something expires sooner
  dismissKey: string
}

export function ExpiryBanner({ banner }: { banner: Banner }) {
  const [open, setOpen] = useState(true)
  if (!open) return null
  const count = banner.items.length + banner.more
  return (
    <>
      <div className="relative max-w-(--content-max-width) mx-auto w-full border-x border-border bg-(--warning)/8">
        <div className="flex items-start gap-3 px-4 py-2.5 sm:px-6">
          <TriangleAlertIcon className="mt-0.5 size-4 shrink-0 text-(--warning)" aria-hidden />
          <p className="min-w-0 flex-1 text-sm break-words">
            <span className="font-medium">{count === 1 ? "1 credential expires soon" : `${count} credentials expire soon`}: </span>
            {banner.items.map((item, i) => (
              <span key={item.id}>
                {i > 0 && ", "}
                {item.kind}{" "}
                <Link
                  href={router.href("/dash/projects/:projectId/machines", { projectId: item.projectId })}
                  className="font-medium underline underline-offset-2"
                >
                  {item.name}
                </Link>{" "}
                <span className="text-muted-foreground">({item.projectName}, {item.when})</span>
              </span>
            ))}
            {banner.more > 0 && `, and ${banner.more} more`}
            . Regenerate or renew them on each project's Machines tab.
          </p>
          <button
            type="button"
            onClick={() => {
              document.cookie = `${EXPIRY_BANNER_COOKIE}=${encodeURIComponent(banner.dismissKey)}; Path=/; Max-Age=86400; SameSite=Lax`
              setOpen(false)
            }}
            className="shrink-0 rounded-md p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            aria-label="Dismiss for a day"
            title="Dismiss for a day"
          >
            <XIcon className="size-4" />
          </button>
        </div>
      </div>
      <div className="border-t border-border" />
    </>
  )
}
