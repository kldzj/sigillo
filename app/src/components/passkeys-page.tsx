// Your passkeys: they approve access to protected environments, in the browser
// and for the CLI. The first one takes a Google sign-in from the last 5
// minutes, and an admin's approval once your organization has an admin with a
// passkey. Each further one takes an approval with a passkey you have: in this
// browser, or on another device with a code, like the CLI. Additions and
// removals are logged for the admins of your organizations.

"use client";

import { useEffect, useState, useTransition } from "react";
import { z } from "zod";
import { parseFormData } from "spiceflow";
import { router, useLoaderData } from "spiceflow/react";
import { KeyRoundIcon } from "lucide-react";
import { Button } from "sigillo-app/src/components/ui/button";
import { Badge } from "sigillo-app/src/components/ui/badge";
import { Frame } from "sigillo-app/src/components/ui/frame";
import { Input } from "sigillo-app/src/components/ui/input";
import { EmptyState } from "sigillo-app/src/components/ui/empty-state";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "sigillo-app/src/components/ui/table";
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago";
import { authClient } from "../auth-client.ts";
import { removePasskeyAction, requestEnrollmentAction, enrollmentStatusAction } from "../actions.ts";
import { approveInBrowser, withStepUp } from "./step-up.ts";

const addSchema = z.object({ name: z.string().trim().max(60) });
const addFields = addSchema.keyof().enum;

export function PasskeysPage() {
  const { passkeys, freshSignIn, recentLogin, enrollment, approveUrl } = useLoaderData("/dash/passkeys");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  // The first passkey needs a sign-in from the last 5 minutes, further ones a login from the last day
  const needsFreshSignIn = !enrollment.approved && (passkeys.length === 0 ? !freshSignIn : !recentLogin);

  // A request waiting for approval: check on it until it's answered
  const waitingFor = enrollment.pending?.id;
  useEffect(() => {
    if (!waitingFor) return;
    const timer = setInterval(async () => {
      const { status } = await enrollmentStatusAction({ requestId: waitingFor });
      if (status !== "pending") router.refresh();
    }, 3000);
    return () => clearInterval(timer);
  }, [waitingFor]);

  const ask = (viaCode: boolean) => startTransition(async () => {
    setError(null);
    try {
      await requestEnrollmentAction({ viaCode });
      router.refresh();
    } catch (e: any) {
      setError(e?.message || "Asking for an approval failed");
    }
  });

  const add = (name: string) => startTransition(async () => {
    setError(null);
    try {
      // Another passkey needs an approval with one you already have, unless
      // one was approved for this browser already
      if (passkeys.length > 0 && !enrollment.approved && !await approveInBrowser({ purpose: "admin", environmentIds: [] })) return;
      const { error } = await authClient.passkey.addPasskey({ name: name || undefined });
      if (error) {
        // Cancelling the browser's prompt comes back as a passthrough of its NotAllowedError
        const cancelled = "code" in error && (error.code === "ERROR_CEREMONY_ABORTED" || error.code === "ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY");
        if (!cancelled) setError(error.message || "Adding the passkey failed");
        return;
      }
      router.refresh();
    } catch (e: any) {
      if (e?.name !== "NotAllowedError") setError(e?.message || "Adding the passkey failed");
    }
  });

  const addForm = (
    <form
      className="flex gap-2 items-center max-w-md"
      action={(formData: FormData) => add(parseFormData(addSchema, formData).name)}
    >
      <Input name={addFields.name} placeholder="Name, e.g. MacBook" maxLength={60} className="flex-1" />
      <Button type="submit" loading={pending} disabled={pending}>
        Add a passkey
      </Button>
    </form>
  );

  return (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Passkeys</h1>
      <p className="text-sm text-muted-foreground">
        A passkey approves reading and changing a protected environment, in the browser and for the CLI, and admin actions in an organization that has one. Add two, such as
        your laptop and your phone, or a security key, so losing one doesn't lock you out.
      </p>

      {passkeys.length === 0 ? (
        <EmptyState
          icon={<KeyRoundIcon className="size-6 text-muted-foreground" />}
          title="No passkeys yet"
          description={enrollment.needsAdmin
            ? "Your organization's admins approve your first passkey, so a stolen login can't add one."
            : needsFreshSignIn
              ? "For your first passkey, sign in again: the sign-in has to be less than 5 minutes old."
              : "Add one to use protected environments."}
        />
      ) : (
        <Frame className="w-full">
          <Table className="table-fixed">
            <colgroup>
              <col />
              <col className="w-36" />
              <col className="w-20" />
            </colgroup>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>Added</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {passkeys.map((passkey) => (
                <TableRow key={passkey.id}>
                  <TableCell>
                    <span className="flex items-center gap-2 text-sm font-medium">
                      <span className="truncate">{passkey.name || "Passkey"}</span>
                      {passkey.backedUp && <Badge variant="secondary">Synced</Badge>}
                    </span>
                  </TableCell>
                  <TableCell>
                    <TimeAgo ts={passkey.createdAt} className="text-muted-foreground text-xs tabular-nums" />
                  </TableCell>
                  <TableCell className="p-0 text-right pr-3">
                    <button
                      onClick={async () => {
                        if (!confirm(`Remove ${passkey.name || "this passkey"}? It can no longer approve anything.`)) return;
                        try {
                          await withStepUp(() => removePasskeyAction({ passkeyId: passkey.id }));
                        } catch (e: any) {
                          alert(e?.message || "Failed to remove the passkey");
                        }
                      }}
                      className="text-xs text-muted-foreground hover:text-destructive cursor-pointer"
                    >
                      Remove
                    </button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Frame>
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}

      {enrollment.approved ? (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">Approved: add your passkey in this browser now.</p>
          {addForm}
        </div>
      ) : enrollment.pending?.userCode ? (
        <div className="flex flex-col gap-2 max-w-md">
          <p className="text-sm text-muted-foreground">
            On a device with one of your passkeys, open <code className="mono-sm">{approveUrl}</code> and enter:
          </p>
          <p className="text-2xl font-semibold mono-sm tracking-[0.25em]">{enrollment.pending.userCode}</p>
          <p className="text-xs text-muted-foreground">Waiting for your approval…</p>
        </div>
      ) : enrollment.pending ? (
        <p className="text-sm text-muted-foreground max-w-md">
          {enrollment.pending.approversNeeded > 1
            ? `Waiting for an admin of each of your organizations with protected environments to approve your first passkey: ${enrollment.pending.approvedBy} of ${enrollment.pending.approversNeeded} have.`
            : "Waiting for an admin to approve your first passkey."}{" "}
          They see your request on a project's Access tab. Come back to this page in this browser once they have.
        </p>
      ) : needsFreshSignIn ? (
        <div className="flex flex-col gap-2 items-start">
          {passkeys.length > 0 && (
            <p className="text-sm text-muted-foreground">This login is more than a day old: sign in again to add a passkey.</p>
          )}
          <Button onClick={() => { window.location.href = "/logout?redirect=/dash/passkeys"; }}>Sign in again</Button>
        </div>
      ) : enrollment.needsAdmin ? (
        <div>
          <Button loading={pending} disabled={pending} onClick={() => ask(false)}>Ask an admin to approve</Button>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {addForm}
          {passkeys.length > 0 && (
            <div className="flex flex-col gap-1 items-start">
              <p className="text-sm text-muted-foreground">Your passkey isn't in this browser?</p>
              {freshSignIn ? (
                <Button variant="outline" size="sm" disabled={pending} onClick={() => ask(true)}>Approve on another device</Button>
              ) : (
                <p className="text-sm text-muted-foreground">
                  <a className="underline" href="/logout?redirect=/dash/passkeys">Sign in again</a> first, then approve it on a device that has one.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </>
  );
}
