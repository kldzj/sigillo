// Event log table — shows the append-only secretEvent audit trail.
// Env select filters events. Eye icon fetches and shows an old value (set
// events only), which protected environments record in the read log.
// Badges: green for "set", red for "delete".

"use client";

import { ClockIcon, EyeIcon, EyeOffIcon } from "lucide-react";
import { cn } from "sigillo-app/src/lib/utils";
import { AdminOnlyEnvironment, EmptyState } from "sigillo-app/src/components/ui/empty-state";
import { useState } from "react";
import { router, useLoaderData } from "spiceflow/react";
import { revealEventValueAction } from "../actions.ts";
import { withStepUp } from "./step-up.ts";
import { Badge } from "sigillo-app/src/components/ui/badge";
import { Spinner } from "sigillo-app/src/components/ui/spinner";
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

// Secret values use the .text-security-disc CSS class from globals.css.

export function EventLogTable() {
  const {
    projectName,
    events,
    environments,
    selectedEnvId,
    locked,
    projectId,
  } = useLoaderData('/dash/projects/:projectId/envs/:envSlug/event-log');
  const [visibleValues, setVisibleValues] = useState<Record<string, boolean>>({});
  const [values, setValues] = useState<Record<string, string | null>>({});

  const toggleValue = async (id: string) => {
    const show = !visibleValues[id];
    setVisibleValues((prev) => ({ ...prev, [id]: show }));
    if (!show || id in values) return;
    try {
      // A protected environment asks for the passkey first
      const result = await withStepUp(() => revealEventValueAction({ eventId: id }));
      if (result) setValues((prev) => ({ ...prev, [id]: result.value }));
      else setVisibleValues((prev) => ({ ...prev, [id]: false }));
    } catch (e: any) {
      setVisibleValues((prev) => ({ ...prev, [id]: false }));
      alert(e?.message || "Failed to load the value");
    }
  };

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">{projectName}</h1>
        <Select
          defaultValue={selectedEnvId || ""}
          onValueChange={(val: string | null) => {
            if (!val || !projectId) return
            const env = environments.find((e) => e.id === val);
            if (env) router.push(router.href('/dash/projects/:projectId/envs/:envSlug/event-log', { projectId, envSlug: env.slug }));
          }}
        >
          <SelectTrigger size="sm" className="w-auto min-w-40">
            <SelectValue placeholder="All environments">
              {environments.find((e) => e.id === selectedEnvId)?.name || "All environments"}
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

      {locked ? (
        <AdminOnlyEnvironment />
      ) : events.length === 0 ? (
        <EmptyState
          icon={<ClockIcon className="size-6 text-muted-foreground" />}
          title="No events yet"
          description="Secret changes will appear here as an audit trail."
        />
      ) : (
        <Frame className="w-full">
          <Table className="table-fixed">
            <colgroup>
              <col className="w-40" />
              <col className="w-24" />
              <col style={{ width: "300px" }} />
              <col className="w-36" />
              <col className="w-24" />
            </colgroup>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Secret</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>User</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((evt) => {
                const isVisible = visibleValues[evt.id] ?? false;
                const hasValue = evt.hasValue;
                const loading = isVisible && !(evt.id in values);
                return (
                  <TableRow key={evt.id}>
                    <TableCell>
                      <span className="text-sm mono-sm font-medium">{evt.name}</span>
                    </TableCell>
                    <TableCell>
                      {evt.operation === "set" ? (
                        <Badge variant="default" size="sm" className="bg-emerald-600 text-white">
                          set
                        </Badge>
                      ) : (
                        <Badge variant="destructive" size="sm">
                          delete
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {hasValue ? (
                        <div className="flex items-center gap-1.5">
                          <span className="relative min-w-0 flex-1" aria-busy={loading}>
                            <span
                              className={cn(
                                "block text-sm mono-sm truncate",
                                isVisible && !loading ? "value-reveal" : "text-security-disc",
                              )}
                            >
                              {isVisible && !loading ? values[evt.id] : "••••••••••••"}
                            </span>
                            {loading && <span aria-hidden className="pointer-events-none absolute inset-0 rounded-sm value-loading" />}
                          </span>
                          <button
                            onClick={() => void toggleValue(evt.id)}
                            disabled={loading}
                            className="text-muted-foreground hover:text-foreground cursor-pointer shrink-0 disabled:cursor-default"
                            title={loading ? "Loading value" : isVisible ? "Hide value" : "Reveal value"}
                          >
                            {loading ? (
                              <Spinner className="size-3.5" />
                            ) : isVisible ? (
                              <EyeOffIcon className="size-3.5" />
                            ) : (
                              <EyeIcon className="size-3.5" />
                            )}
                          </button>
                        </div>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <TimeAgo
                        ts={evt.createdAt}
                        className="text-muted-foreground text-xs tabular-nums"
                      />
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground truncate">{evt.userName}</span>
                      {evt.unsigned && (
                        <span className="ml-1.5 text-xs text-destructive" title="Not part of the signed history: added to the database around it">
                          unsigned
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Frame>
      )}
    </>
  );
}
