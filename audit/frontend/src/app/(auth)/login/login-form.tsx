"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { api, setToken } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { AuthShell } from "@/components/auth/auth-shell";
import { OtpInput } from "@/components/auth/otp-input";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { IconEye, IconEyeOff } from "@/components/icons";

function safeNext(raw: string | null) {
  // Only same-site paths; never an absolute URL from the query string.
  if (raw && raw.startsWith("/") && !raw.startsWith("//")) return raw;
  return "/dashboard/posture";
}

export function LoginForm() {
  const router = useRouter();
  const next = safeNext(useSearchParams().get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [tempToken, setTempToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      const res = await api.auth.login({ email: email.trim(), password });
      if (res.mfa_required && res.temp_token) {
        setTempToken(res.temp_token);
        setPending(false);
        return;
      }
      setToken(res.access_token, res.refresh_token);
      router.push(next);
    } catch (err) {
      setError(errMsg(err, "Sign in failed."));
      setPending(false);
    }
  }

  async function submitCode(value = code) {
    if (!tempToken || value.length !== 6) return;
    setError(null);
    setPending(true);
    try {
      const res = await api.auth.mfaLogin(tempToken, value);
      setToken(res.access_token, res.refresh_token);
      router.push(next);
    } catch (err) {
      setError(errMsg(err, "That code did not work."));
      setCode("");
      setPending(false);
    }
  }

  return (
    <AuthShell
      eyebrow={tempToken ? "Step 2 of 2" : "Sign in"}
      title={tempToken ? "Enter your code" : "Welcome back"}
      lede={
        tempToken
          ? "Open your authenticator app and enter the six digit code for SeQr."
          : "Sign in to see your organisation's cryptographic posture."
      }
      footer={
        <>
          New to SeQr?{" "}
          <Link href="/register" className="font-medium text-ink link-underline">
            Create an account
          </Link>
        </>
      }
    >
      <AnimatePresence mode="wait" initial={false}>
        {!tempToken ? (
          <motion.form
            key="password"
            onSubmit={submitPassword}
            exit={{ opacity: 0, x: -16 }}
            transition={{ duration: 0.2 }}
            className="space-y-5"
            noValidate
          >
            <Field label="Email">
              {({ id }) => (
                <Input
                  id={id}
                  type="email"
                  autoComplete="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoFocus
                />
              )}
            </Field>
            <Field label="Password">
              {({ id }) => (
                <div className="relative">
                  <Input
                    id={id}
                    type={show ? "text" : "password"}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pr-11"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShow((s) => !s)}
                    aria-label={show ? "Hide password" : "Show password"}
                    aria-pressed={show}
                    className="absolute right-0 top-0 inline-flex h-10 w-10 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
                  >
                    {show ? <IconEyeOff size={18} /> : <IconEye size={18} />}
                  </button>
                </div>
              )}
            </Field>
            {error && (
              <p role="alert" className="border border-immediate/50 bg-immediate/10 px-3 py-2 text-sm text-immediate">
                {error}
              </p>
            )}
            <Button
              type="submit"
              size="lg"
              className="w-full justify-center"
              pending={pending}
              pendingLabel="Signing in"
              disabled={!email || !password}
            >
              Sign in
            </Button>
          </motion.form>
        ) : (
          <motion.div
            key="otp"
            initial={{ opacity: 0, x: 16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.28, ease: [0.2, 0, 0, 1] }}
            className="space-y-5"
          >
            <OtpInput value={code} onChange={setCode} onComplete={(v) => submitCode(v)} disabled={pending} autoFocus />
            {error && (
              <p role="alert" className="border border-immediate/50 bg-immediate/10 px-3 py-2 text-sm text-immediate">
                {error}
              </p>
            )}
            <div className="flex items-center gap-3">
              <Button size="lg" onClick={() => submitCode()} pending={pending} pendingLabel="Verifying" disabled={code.length !== 6}>
                Verify and sign in
              </Button>
              <Button
                variant="ghost"
                size="lg"
                onClick={() => {
                  setTempToken(null);
                  setCode("");
                  setError(null);
                }}
              >
                Use another account
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </AuthShell>
  );
}
