"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, setToken } from "@/lib/api";
import { cn, errMsg } from "@/lib/utils";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input } from "@/components/ui/field";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** 0 to 4: length, mixed case, digit, symbol. Shown as a thin bar, never as a lecture. */
function strength(pw: string) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw) || pw.length >= 14) s++;
  return s;
}
const STRENGTH = ["Too short", "Weak", "Fair", "Good", "Strong"];

export function RegisterForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [agree, setAgree] = useState(false);
  const [touched, setTouched] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const emailBad = touched && email.length > 0 && !EMAIL_RE.test(email);
  const pwShort = touched && password.length > 0 && password.length < 8;
  const s = password ? strength(password) : 0;
  const valid = name.trim() && org.trim() && EMAIL_RE.test(email) && password.length >= 8 && agree;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!valid) return;
    setError(null);
    setPending(true);
    try {
      const res = await api.auth.register({ name: name.trim(), org_name: org.trim(), email: email.trim(), password });
      setToken(res.access_token, res.refresh_token);
      router.push("/dashboard/posture");
    } catch (err) {
      setError(errMsg(err, "Could not create the account."));
      setPending(false);
    }
  }

  return (
    <AuthShell
      eyebrow="Create account"
      title="Start your inventory"
      lede="One workspace for your organisation. Add assets, scan them, and export the CBOM."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-ink link-underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-5" noValidate>
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Full name">
            {({ id }) => (
              <Input id={id} autoComplete="name" placeholder="Ada Lovelace" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            )}
          </Field>
          <Field label="Organisation">
            {({ id }) => (
              <Input id={id} autoComplete="organization" placeholder="Acme Bank" value={org} onChange={(e) => setOrg(e.target.value)} />
            )}
          </Field>
        </div>
        <Field label="Work email" error={emailBad ? "Enter a valid email address." : undefined}>
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onBlur={() => setTouched(true)}
              aria-invalid={invalid}
              aria-describedby={describedBy}
            />
          )}
        </Field>
        <Field label="Password" error={pwShort ? "Use at least 8 characters." : undefined}>
          {({ id, describedBy, invalid }) => (
            <div>
              <Input
                id={id}
                type="password"
                autoComplete="new-password"
                placeholder="At least 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={invalid}
                aria-describedby={describedBy}
              />
              <div className="mt-2 flex items-center gap-3" aria-live="polite">
                <div className="grid h-[3px] flex-1 grid-cols-4 gap-1">
                  {[0, 1, 2, 3].map((i) => (
                    <span
                      key={i}
                      className={cn(
                        "h-full origin-left transition-[background-color,transform] duration-ui ease-instrument",
                        i < s ? (s <= 1 ? "bg-immediate" : s === 2 ? "bg-urgent" : "bg-safe") : "bg-rule"
                      )}
                    />
                  ))}
                </div>
                <span className="w-16 text-right font-mono text-[11px] text-ink-3">{password ? STRENGTH[s] : ""}</span>
              </div>
            </div>
          )}
        </Field>
        <Checkbox
          checked={agree}
          onChange={setAgree}
          label={
            <>
              I agree to the{" "}
              <Link href="/terms" target="_blank" className="text-ink link-underline">
                Terms of Service
              </Link>{" "}
              and{" "}
              <Link href="/privacy" target="_blank" className="text-ink link-underline">
                Privacy Policy
              </Link>
              .
            </>
          }
        />
        {error && (
          <p role="alert" className="border border-immediate/50 bg-immediate/10 px-3 py-2 text-sm text-immediate">
            {error}
          </p>
        )}
        <Button type="submit" size="lg" className="w-full justify-center" pending={pending} pendingLabel="Creating account" disabled={!valid}>
          Create account
        </Button>
      </form>
    </AuthShell>
  );
}
