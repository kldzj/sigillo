// Client component for the device authorization flow (RFC 8628).
// Two steps: validate the code, then require an explicit Approve click.
// Never prefilled or auto-approved: a /device?user_code=X link can be sent by
// an attacker who started the login (RFC 8628 §5.4 remote phishing), so the
// code is typed from your own terminal, and you confirm after a warning. Once
// you have a passkey, approving takes it too: the new login outlives the
// session that approves it.

"use client"

import { useState, useTransition } from "react"
import { z } from "zod"
import { parseFormData } from "spiceflow"
import { ErrorBoundary } from "spiceflow/react"
import { Button } from "sigillo-app/src/components/ui/button"
import { formatUserCode } from "sigillo-app/src/lib/utils"
import { CodeInput } from "./code-input.tsx"
import { authClient } from "../auth-client.ts"
import { approveInBrowser } from "./step-up.ts"

const codeSchema = z.object({
  userCode: z.string().trim().min(1, 'Enter the code shown in your terminal'),
})
const codeFields = codeSchema.keyof().enum

export function DeviceFlow() {
  const [step, setStep] = useState<
    | { kind: 'enter' }
    | { kind: 'confirm'; userCode: string }
    | { kind: 'done'; approved: boolean }
  >({ kind: 'enter' })
  const [decisionError, setDecisionError] = useState<string | null>(null)
  const [pending, startTransition] = useTransition()

  function decide(approve: boolean) {
    if (step.kind !== 'confirm') return
    setDecisionError(null)
    const userCode = step.userCode
    const send = () => (approve ? authClient.device.approve({ userCode }) : authClient.device.deny({ userCode }))
      .then(({ error }) => error as { code?: string } | null, () => ({ code: 'FAILED' }))
    startTransition(async () => {
      let error = await send()
      // Once you have a passkey, approving a login asks for it first
      if (error?.code === 'PASSKEY_APPROVAL_REQUIRED') {
        if (!await approveInBrowser({ purpose: 'admin', environmentIds: [] })) return
        error = await send()
      }
      // A login from before the server told Google sign-ins apart
      if (error?.code === 'SIGN_IN_REQUIRED') {
        setDecisionError('Only a login from signing in with Google approves a CLI login. Log out, sign in again, and enter the code.')
        setStep({ kind: 'enter' })
        return
      }
      if (error) {
        setDecisionError('Invalid or expired code. Start the login again and enter the new code.')
        setStep({ kind: 'enter' })
        return
      }
      setStep({ kind: 'done', approved: approve })
    })
  }

  if (step.kind === 'done') {
    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="text-center max-w-sm">
          <h1 className="text-2xl font-bold mb-2">
            {step.approved ? 'Device Approved' : 'Device Denied'}
          </h1>
          <p className="text-muted-foreground">
            {step.approved
              ? 'You can close this page. Your CLI or agent is now authenticated.'
              : 'The login request was rejected. You can close this page.'}
          </p>
        </div>
      </div>
    )
  }

  if (step.kind === 'confirm') {
    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="text-center max-w-sm flex flex-col gap-4">
          <h1 className="text-2xl font-bold">Approve this login?</h1>
          <p className="text-3xl mono-sm tracking-[0.25em]">{step.userCode}</p>
          <p className="text-sm text-muted-foreground">
            A CLI or agent is asking for full access to your Sigillo account and secrets.
            Approve only if <strong>you</strong> started this login and the code above matches
            the one shown in your own terminal. If someone sent you this link, deny it.
          </p>
          <div className="flex gap-3 justify-center">
            <Button type="button" variant="outline" size="lg" disabled={pending} onClick={() => decide(false)}>
              Deny
            </Button>
            <Button type="button" size="lg" loading={pending} disabled={pending} onClick={() => decide(true)}>
              Approve
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex justify-center items-center min-h-[60vh]">
      <div className="text-center max-w-sm">
        <h1 className="text-2xl font-bold mb-2">Device Login</h1>
        <p className="text-muted-foreground mb-6">Enter the code shown on your CLI or agent:</p>
        {decisionError && <p className="text-red-500 text-sm mb-4">{decisionError}</p>}
        <ErrorBoundary
          above
          fallback={<ErrorBoundary.ErrorMessage className="text-red-500 text-sm mb-4" />}
        >
          <form
            className="flex flex-col gap-4"
            action={async (formData: FormData) => {
              // As XXXX-XXXX: better-auth ignores the dash when it looks the code up
              const userCode = formatUserCode(parseFormData(codeSchema, formData).userCode)
              const { data, error } = await authClient.device({ query: { user_code: userCode } })
                .catch(() => ({ data: null, error: true }))
              if (error || !data) throw new Error('Invalid or expired code. Please try again.')
              setDecisionError(null)
              setStep({ kind: 'confirm', userCode })
            }}
          >
            <CodeInput name={codeFields.userCode} autoFocus placeholder="XXXX-XXXX" required />
            <Button type="submit" size="lg">Continue</Button>
          </form>
        </ErrorBoundary>
      </div>
    </div>
  )
}
