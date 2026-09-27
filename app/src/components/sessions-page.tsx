// Your sessions — every browser and CLI login of the signed-in user, with the
// device and IP it signed in from. Ending one signs that device out on its
// next request; the current session is ended with Log out instead.

"use client"

import { useLoaderData } from "spiceflow/react"
import { Button } from "sigillo-app/src/components/ui/button"
import { Badge } from "sigillo-app/src/components/ui/badge"
import { Frame } from "sigillo-app/src/components/ui/frame"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "sigillo-app/src/components/ui/table"
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago"
import { describeUserAgent } from "sigillo-app/src/lib/utils"
import { endSessionAction, endOtherSessionsAction } from "../actions.ts"

export function SessionsPage() {
  const { sessions } = useLoaderData('/dash/sessions')
  const others = sessions.filter((session) => !session.isCurrent).length

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Sessions</h1>
        {others > 0 && (
          <Button
            variant="outline"
            onClick={async () => {
              if (!confirm(`Sign out ${others === 1 ? "the other session" : `all ${others} other sessions`}?`)) return
              try {
                await endOtherSessionsAction()
              } catch (e: any) {
                alert(e?.message || "Failed to end sessions")
              }
            }}
          >
            End all other sessions
          </Button>
        )}
      </div>
      <p className="text-sm text-muted-foreground">
        Browsers and CLI logins signed in as you. End any you don't recognize.
      </p>

      <Frame className="w-full">
        <Table className="table-fixed">
          <colgroup>
            <col className="w-2/5" />
            <col className="w-1/4" />
            <col className="w-32" />
            <col className="w-20" />
          </colgroup>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Device</TableHead>
              <TableHead>IP address</TableHead>
              <TableHead>Signed in</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {sessions.map((session) => (
              <TableRow key={session.id}>
                <TableCell>
                  <span className="flex items-center gap-2 text-sm font-medium">
                    <span className="truncate" title={session.userAgent ?? undefined}>
                      {describeUserAgent(session.userAgent)}
                    </span>
                    {session.isCurrent && <Badge variant="secondary">This session</Badge>}
                  </span>
                </TableCell>
                <TableCell>
                  <code className="text-xs text-muted-foreground mono-sm">
                    {session.ipAddress ?? "—"}
                  </code>
                </TableCell>
                <TableCell>
                  <TimeAgo
                    ts={session.createdAt}
                    className="text-muted-foreground text-xs tabular-nums"
                  />
                </TableCell>
                <TableCell className="p-0 text-right pr-3">
                  {!session.isCurrent && (
                    <button
                      onClick={async () => {
                        if (!confirm(`Sign out ${describeUserAgent(session.userAgent)}?`)) return
                        try {
                          await endSessionAction({ sessionId: session.id })
                        } catch (e: any) {
                          alert(e?.message || "Failed to end session")
                        }
                      }}
                      className="text-xs text-muted-foreground hover:text-destructive cursor-pointer"
                    >
                      End
                    </button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Frame>
    </>
  )
}
