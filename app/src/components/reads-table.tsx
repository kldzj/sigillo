// History → Reads: who read a protected environment's values, when, how and from
// which IP (secret_read). Org admins only. Also shows protection being turned
// on and off, since reads in between are not recorded.

"use client";

import { EyeIcon, ShieldIcon } from "lucide-react";
import { router, useLoaderData } from "spiceflow/react";
import { EmptyState } from "sigillo-app/src/components/ui/empty-state";
import { Badge } from "sigillo-app/src/components/ui/badge";
import { Frame } from "sigillo-app/src/components/ui/frame";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectPopup,
  SelectItem,
} from "sigillo-app/src/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "sigillo-app/src/components/ui/table";
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago";
import { formatIp } from "sigillo-app/src/lib/utils";
import { HistorySwitch } from "./history-switch.tsx";

const KIND_LABELS: Record<string, string> = {
  list: "Listed",
  value: "Read value",
  download: "Downloaded",
  "event-log": "Read old value",
  copy: "Copied",
  protected: "Protection on",
  unprotected: "Protection off",
  audit: "Exported history",
};

export function ReadsTable() {
  const {
    projectName,
    environments,
    reads,
    selectedEnvId,
    isProtected,
    isAdmin,
    projectId,
  } = useLoaderData('/dash/projects/:projectId/envs/:envSlug/history/reads');
  const selectedEnv = environments.find((e) => e.id === selectedEnvId);

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold tracking-tight">{projectName}</h1>
        <div className="flex flex-wrap items-center gap-2">
        {selectedEnv && <HistorySwitch projectId={projectId} envSlug={selectedEnv.slug} active="reads" />}
        <Select
          defaultValue={selectedEnvId || ""}
          onValueChange={(val: string | null) => {
            if (!val || !projectId) return
            const env = environments.find((e) => e.id === val);
            if (env) router.push(router.href('/dash/projects/:projectId/envs/:envSlug/history/reads', { projectId, envSlug: env.slug }));
          }}
        >
          <SelectTrigger size="sm" className="w-auto min-w-40">
            <SelectValue placeholder="Environment">
              {environments.find((e) => e.id === selectedEnvId)?.name || "Environment"}
            </SelectValue>
          </SelectTrigger>
          <SelectPopup>
            {environments.map((env) => (
              <SelectItem key={env.id} value={env.id}>
                {env.name}
              </SelectItem>
            ))}
          </SelectPopup>
        </Select>
        </div>
      </div>

      {!isAdmin ? (
        <EmptyState
          icon={<ShieldIcon className="size-6 text-muted-foreground" />}
          title="Admins only"
          description="Only org admins can see who read this environment's values."
        />
      ) : reads.length === 0 ? (
        <EmptyState
          icon={<EyeIcon className="size-6 text-muted-foreground" />}
          title={isProtected ? "No reads yet" : "Reads are not recorded here"}
          description={isProtected
            ? "Every read of this environment's values will appear here."
            : "Mark this environment as protected on the Environments tab to record every read of its values."}
        />
      ) : (
        <>
          {!isProtected && (
            <p className="text-sm text-muted-foreground">
              Protection is off, so reads are not recorded right now.
            </p>
          )}
          <Frame className="w-full">
            <Table className="table-fixed">
              <colgroup>
                <col className="w-36" />
                <col className="w-40" />
                <col className="w-36" />
                <col />
                <col className="w-36" />
              </colgroup>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Time</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead>How</TableHead>
                  <TableHead>Secrets</TableHead>
                  <TableHead>IP address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reads.map((read) => (
                  <TableRow key={read.id}>
                    <TableCell>
                      <TimeAgo ts={read.createdAt} className="text-muted-foreground text-xs tabular-nums" />
                    </TableCell>
                    <TableCell>
                      <span className="text-sm truncate block">{read.who}</span>
                    </TableCell>
                    <TableCell>
                      {read.kind === "protected" || read.kind === "unprotected" ? (
                        <Badge variant={read.kind === "protected" ? "secondary" : "destructive"} size="sm">
                          {KIND_LABELS[read.kind]}
                        </Badge>
                      ) : (
                        <span className="text-sm">{KIND_LABELS[read.kind] ?? read.kind}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-sm mono-sm truncate block" title={read.names.join(", ")}>
                        {read.names.length ? read.names.join(", ") : "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <code className="block truncate text-xs text-muted-foreground mono-sm" title={read.ipAddress ?? undefined}>{formatIp(read.ipAddress) ?? "—"}</code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Frame>
        </>
      )}
    </>
  );
}
