// Step-up in the browser: an action on a protected environment, or an admin
// action in an organization with one, answers { stepUp } until this session
// has a passkey approval. withStepUp asks for the passkey on the spot and runs
// the action once more.

"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { router } from "spiceflow/react";
import { startStepUpAction, finishStepUpAction } from "../actions.ts";

type StepUp = { stepUp: { purpose: "access" | "admin" | "enroll"; environmentIds: string[] } };

function isStepUp(value: unknown): value is StepUp {
  return typeof value === "object" && value !== null && "stepUp" in value;
}

// Approves in this browser session: access to the environments for 15
// minutes, or admin actions and managing passkeys for 5
export async function approveInBrowser({ purpose, environmentIds }: StepUp["stepUp"]): Promise<boolean> {
  const started = await startStepUpAction({ purpose, environmentIds });
  if ("noPasskey" in started) {
    const question = purpose === "access"
      ? "This environment is protected: it needs a passkey. Add one now?"
      : "This organization has protected environments, so admin actions need a passkey. Add one now?";
    if (confirm(question)) router.push(router.href("/dash/passkeys"));
    return false;
  }
  let response;
  try {
    response = await startAuthentication({ optionsJSON: started.options });
  } catch (error: any) {
    // Cancelled in the browser's passkey prompt, or replaced by another one
    if (error?.name === "NotAllowedError" || error?.name === "AbortError" || error?.code === "ERROR_CEREMONY_ABORTED") return false;
    throw error;
  }
  const { approved } = await finishStepUpAction({ requestId: started.requestId, response });
  if (!approved) alert("That passkey couldn't be verified, so nothing was done.");
  return approved;
}

// Runs the action, and again after each passkey approval it asks for, at
// most three. Null when the user didn't approve.
export async function withStepUp<T>(action: () => Promise<T | StepUp>): Promise<T | null> {
  let result = await action();
  for (let round = 0; round < 3 && isStepUp(result); round++) {
    if (!await approveInBrowser(result.stepUp)) return null;
    result = await action();
  }
  return isStepUp(result) ? null : result;
}
