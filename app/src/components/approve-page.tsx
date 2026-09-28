// /approve: the CLI or an agent asks for access to protected environments
// and prints this page with a code. The code is typed here, never part of the
// link, so a link someone sends you approves nothing. The page shows where the
// request came from, and approving takes your passkey: the session that
// asked may then read and change those environments for 15 minutes.

"use client";

import { useState, useTransition } from "react";
import { z } from "zod";
import { parseFormData } from "spiceflow";
import { startAuthentication } from "@simplewebauthn/browser";
import { Button } from "sigillo-app/src/components/ui/button";
import { CodeInput } from "./code-input.tsx";
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago";
import { describeUserAgent, formatIp } from "sigillo-app/src/lib/utils";
import { findApprovalAction, approvalOptionsAction, finishStepUpAction } from "../actions.ts";

const codeSchema = z.object({ userCode: z.string().trim().min(1, "Enter the code shown in your terminal") });
const codeFields = codeSchema.keyof().enum;

type Request = NonNullable<Awaited<ReturnType<typeof findApprovalAction>>>;

export function ApprovePage() {
  const [request, setRequest] = useState<Request | null>(null);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (done) {
    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="text-center max-w-sm">
          <h1 className="text-2xl font-bold mb-2">Approved</h1>
          <p className="text-muted-foreground">
            {request?.purpose === "enroll"
              ? "That device can add its passkey now, within the next 15 minutes. You can close this page."
              : "The CLI can read and change these environments for the next 15 minutes. You can close this page."}
          </p>
        </div>
      </div>
    );
  }

  if (request) {
    const approve = () => startTransition(async () => {
      setError(null);
      try {
        const started = await approvalOptionsAction({ requestId: request.id });
        if ("noPasskey" in started) {
          setError("You don't have a passkey yet: add one under user menu → Passkeys, then run the command again.");
          return;
        }
        const response = await startAuthentication({ optionsJSON: started.options });
        const { approved } = await finishStepUpAction({ requestId: request.id, response });
        if (approved) setDone(true);
        else setError("That passkey couldn't be verified. Try again, or start the command again.");
      } catch (e: any) {
        if (e?.name !== "NotAllowedError") setError(e?.message || "Approving failed");
      }
    });

    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="max-w-md w-full flex flex-col gap-4">
          <h1 className="text-2xl font-bold text-center">{request.purpose === "enroll" ? "Approve a new passkey?" : "Approve access?"}</h1>
          <div className="rounded-lg border border-border p-4 text-sm flex flex-col gap-2">
            {request.purpose === "enroll" ? (
              <div>
                <span className="text-muted-foreground">Adds a passkey for your account on the device below. </span>
                <span className="font-medium">It can then approve access to protected environments.</span>
              </div>
            ) : (
              <div>
                <span className="text-muted-foreground">Environments: </span>
                <span className="font-medium">
                  {request.environments.map((env) => `${env.project} / ${env.name}`).join(", ")}
                </span>
              </div>
            )}
            <div>
              <span className="text-muted-foreground">From: </span>
              {describeUserAgent(request.userAgent)}
              {request.ipAddress ? `, ${formatIp(request.ipAddress)}` : ""}
              {request.country ? ` (${request.country})` : ""}
            </div>
            <div>
              <span className="text-muted-foreground">Asked: </span>
              <TimeAgo ts={request.createdAt} className="tabular-nums" />
            </div>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            {request.purpose === "enroll"
              ? <>Approve only if <strong>you</strong> are adding a passkey on that device right now, and the code matches the one it shows.</>
              : <>Approve only if <strong>you</strong> just ran the command asking for this, and the code matches the one in your own terminal.</>}
          </p>
          {error && <p className="text-sm text-destructive text-center">{error}</p>}
          <div className="flex gap-3 justify-center">
            <Button type="button" variant="outline" size="lg" disabled={pending} onClick={() => setRequest(null)}>
              Cancel
            </Button>
            <Button type="button" size="lg" loading={pending} disabled={pending} onClick={approve}>
              Approve with passkey
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex justify-center items-center min-h-[60vh]">
      <form
        className="max-w-sm w-full flex flex-col gap-4 text-center"
        action={(formData: FormData) => startTransition(async () => {
          setError(null);
          const { userCode } = parseFormData(codeSchema, formData);
          const found = await findApprovalAction({ userCode });
          if (found) setRequest(found);
          else setError("No request with this code. It may have expired: run the command again.");
        })}
      >
        <h1 className="text-2xl font-bold">Approve access</h1>
        <p className="text-sm text-muted-foreground">
          Enter the code your terminal shows to approve access to a protected environment.
        </p>
        <CodeInput name={codeFields.userCode} placeholder="XXXX-XXXX" autoFocus />
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button type="submit" loading={pending} disabled={pending}>Continue</Button>
      </form>
    </div>
  );
}
