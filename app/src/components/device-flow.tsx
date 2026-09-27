// Client component for the device authorization flow (RFC 8628).
// Two steps: validate the code, then require an explicit Approve click.
// Never auto-approve: /device?user_code=X links can be sent by an attacker
// who started the login (RFC 8628 §5.4 remote phishing), so the user must
// see a warning and confirm they started the login themselves.

"use client"

import { useState } from "react"
import { Button } from "sigillo-app/src/components/ui/button"
import { Input } from "sigillo-app/src/components/ui/input"
import { authClient } from "../auth-client.ts"

type Step =
  | { kind: 'enter' }
  | { kind: 'confirm'; userCode: string }
  | { kind: 'approved' }
  | { kind: 'denied' }

export function DeviceFlow({ initialCode = '' }: { initialCode?: string }) {
  const [userCode, setUserCode] = useState(initialCode)
  const [step, setStep] = useState<Step>({ kind: 'enter' })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    const formatted = userCode.trim().replace(/-/g, '').toUpperCase()
    const { data, error: err } = await authClient.device({ query: { user_code: formatted } })
      .catch(() => ({ data: null, error: true }))
    setLoading(false)
    if (err || !data) {
      setError('Invalid or expired code. Please try again.')
      return
    }
    setStep({ kind: 'confirm', userCode: formatted })
  }

  async function handleDecision(approve: boolean) {
    if (step.kind !== 'confirm') return
    setError(null)
    setLoading(true)
    const { error: err } = await (approve
      ? authClient.device.approve({ userCode: step.userCode })
      : authClient.device.deny({ userCode: step.userCode })
    ).catch(() => ({ error: true }))
    setLoading(false)
    if (err) {
      setError('Invalid or expired code. Please start the login again.')
      setStep({ kind: 'enter' })
      return
    }
    setStep({ kind: approve ? 'approved' : 'denied' })
  }

  if (step.kind === 'approved' || step.kind === 'denied') {
    return (
      <div className="flex justify-center items-center min-h-[60vh]">
        <div className="text-center max-w-sm">
          <h1 className="text-2xl font-bold mb-2">
            {step.kind === 'approved' ? 'Device Approved' : 'Device Denied'}
          </h1>
          <p className="text-muted-foreground">
            {step.kind === 'approved'
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
          <p className="text-3xl mono-sm tracking-[0.25em]">{step.userCode.replace(/^(.{4})(.{4})$/, '$1-$2')}</p>
          <p className="text-sm text-muted-foreground">
            A CLI or agent is asking for full access to your Sigillo account and secrets.
            Approve only if <strong>you</strong> started this login and the code above matches
            the one shown in your own terminal. If someone sent you this link, deny it.
          </p>
          {error && <p className="text-red-500 text-sm">{error}</p>}
          <div className="flex gap-3 justify-center">
            <Button variant="outline" size="lg" disabled={loading} onClick={() => handleDecision(false)}>
              Deny
            </Button>
            <Button size="lg" loading={loading} disabled={loading} onClick={() => handleDecision(true)}>
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
        {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
        <form onSubmit={handleVerify} className="flex flex-col gap-4">
          <Input
            value={userCode}
            onChange={(e) => setUserCode(e.target.value)}
            placeholder="ABCD-EFGH"
            maxLength={12}
            className="h-12 text-center text-2xl mono-sm tracking-[0.25em] uppercase"
          />
          <Button
            type="submit"
            disabled={loading || !userCode.trim()}
            size="lg"
            loading={loading}
          >
            {loading ? 'Checking…' : 'Continue'}
          </Button>
        </form>
      </div>
    </div>
  )
}
