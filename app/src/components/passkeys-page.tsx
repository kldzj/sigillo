// Your passkeys: they approve access to protected environments, in the browser
// and for the CLI. Adding the first one needs a sign-in from the last 5
// minutes; adding or removing one after that an approval with a passkey. Additions
// and removals are logged for the admins of your organizations.

"use client";

import { useState, useTransition } from "react";
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
import { removePasskeyAction } from "../actions.ts";
import { approveInBrowser, withStepUp } from "./step-up.ts";

const addSchema = z.object({ name: z.string().trim().max(60) });
const addFields = addSchema.keyof().enum;

export function PasskeysPage() {
  const { passkeys, freshSignIn, recentLogin } = useLoaderData("/dash/passkeys");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  // The first passkey needs a sign-in from the last 5 minutes, further ones a login from the last day
  const needsFreshSignIn = passkeys.length === 0 ? !freshSignIn : !recentLogin;

  const add = (name: string) => startTransition(async () => {
    setError(null);
    try {
      // Another passkey needs an approval with one you already have
      if (passkeys.length > 0 && !await approveInBrowser({ purpose: "admin", environmentIds: [] })) return;
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
          description={needsFreshSignIn
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

      {needsFreshSignIn ? (
        <div className="flex flex-col gap-2 items-start">
          {passkeys.length > 0 && (
            <p className="text-sm text-muted-foreground">This login is more than a day old: sign in again to add a passkey.</p>
          )}
          <Button onClick={() => { window.location.href = "/logout?redirect=/dash/passkeys"; }}>Sign in again</Button>
        </div>
      ) : (
        <form
          className="flex gap-2 items-center max-w-md"
          action={(formData: FormData) => add(parseFormData(addSchema, formData).name)}
        >
          <Input name={addFields.name} placeholder="Name, e.g. MacBook" maxLength={60} className="flex-1" />
          <Button type="submit" loading={pending} disabled={pending}>
            Add a passkey
          </Button>
        </form>
      )}
    </>
  );
}
