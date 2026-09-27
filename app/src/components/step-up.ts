// Step-up in the browser: a read of a protected environment answers
// { stepUp } until this session has a passkey approval. withStepUp asks for
// the passkey on the spot and runs the read once more.

"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { router } from "spiceflow/react";
import { startStepUpAction, finishStepUpAction } from "../actions.ts";

type StepUp = { stepUp: { environmentIds: string[] } };

function isStepUp(value: unknown): value is StepUp {
  return typeof value === "object" && value !== null && "stepUp" in value;
}

// Approves reading the environments in this browser session for 15 minutes
async function approveInBrowser(environmentIds: string[]): Promise<boolean> {
  const started = await startStepUpAction({ environmentIds });
  if ("noPasskey" in started) {
    if (confirm("This environment is protected: reading it needs a passkey. Add one now?")) {
      router.push(router.href("/dash/passkeys"));
    }
    return false;
  }
  let response;
  try {
    response = await startAuthentication({ optionsJSON: started.options });
  } catch (error: any) {
    // Cancelled in the browser's passkey prompt
    if (error?.name === "NotAllowedError") return false;
    throw error;
  }
  const { approved } = await finishStepUpAction({ requestId: started.requestId, response });
  if (!approved) alert("That passkey couldn't be verified, so nothing was read.");
  return approved;
}

// Runs the read, and once more after a passkey approval when it needs one.
// Null when the user didn't approve.
export async function withStepUp<T>(read: () => Promise<T | StepUp>): Promise<T | null> {
  const first = await read();
  if (!isStepUp(first)) return first;
  if (!await approveInBrowser(first.stepUp.environmentIds)) return null;
  const second = await read();
  return isStepUp(second) ? null : second;
}
