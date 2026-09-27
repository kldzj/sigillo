// Your passkeys: they approve reads of protected environments, in the browser
// and for the CLI. Adding the first one needs a sign-in from the last 5
// minutes; every further one an approval with an existing passkey. Additions
// and removals are logged for the admins of your organizations.

"use client";

import { useState, useTransition } from "react";
import { z } from "zod";
import { parseFormData } from "spiceflow";
import { router, useLoaderData } from "spiceflow/react";
import { startAuthentication } from "@simplewebauthn/browser";
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
import { startPasskeysApprovalAction, finishStepUpAction, removePasskeyAction } from "../actions.ts";

const addSchema = z.object({ name: z.string().trim().max(60) });
const addFields = addSchema.keyof().enum;

export function PasskeysPage() {
  const { passkeys, freshSignIn } = useLoaderData("/dash/passkeys");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const needsFreshSignIn = passkeys.length === 0 && !freshSignIn;

  const add = (name: string) => startTransition(async () => {
    setError(null);
    try {
      // Another passkey needs an approval with one you already have
      if (passkeys.length > 0) {
        const started = await startPasskeysApprovalAction();
        const response = await startAuthentication({ optionsJSON: started.options });
        const { approved } = await finishStepUpAction({ requestId: started.requestId, response });
        if (!approved) {
          setError("That passkey couldn't be verified.");
          return;
        }
      }
      const { error } = await authClient.passkey.addPasskey({ name: name || undefined });
      if (error) {
        if (!("code" in error) || error.code !== "ERROR_CEREMONY_ABORTED") setError(error.message || "Adding the passkey failed");
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
        A passkey approves reading a protected environment, in the browser and for the CLI. Add two, such as
        your laptop and your phone, or a security key, so losing one doesn't lock you out.
      </p>

      {passkeys.length === 0 ? (
        <EmptyState
          icon={<KeyRoundIcon className="size-6 text-muted-foreground" />}
          title="No passkeys yet"
          description={needsFreshSignIn
            ? "For your first passkey, sign in again: the sign-in has to be less than 5 minutes old."
            : "Add one to read protected environments."}
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
                        if (!confirm(`Remove ${passkey.name || "this passkey"}? It can no longer approve reads.`)) return;
                        try {
                          await removePasskeyAction({ passkeyId: passkey.id });
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
        <div>
          <Button onClick={() => { window.location.href = "/logout"; }}>Sign in again</Button>
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
