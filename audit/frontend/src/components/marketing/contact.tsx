"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import type { Mode } from "./plans";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MODE_LABEL: Record<Mode, string> = { cli: "CLI", cloud: "SeQr cloud", onprem: "On-premise" };

export function Contact({ mode, setMode }: { mode: Mode; setMode: (m: Mode) => void }) {
  const [email, setEmail] = useState("");
  const [touched, setTouched] = useState(false);
  const [state, setState] = useState<"idle" | "sending" | "done" | "error" | "unconfigured">("idle");
  const [message, setMessage] = useState("");
  const valid = EMAIL_RE.test(email.trim());

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!valid) return;
    setState("sending");
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), mode }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) setState("done");
      else if (res.status === 503) setState("unconfigured");
      else {
        setMessage(data.error || "Something went wrong. Try again.");
        setState("error");
      }
    } catch {
      setMessage("Network error. Try again.");
      setState("error");
    }
  }

  const mailto = `mailto:lochan@seqr.in?subject=${encodeURIComponent(`SeQr scan request (${MODE_LABEL[mode]})`)}&body=${encodeURIComponent(`Work email: ${email}\nDeployment: ${MODE_LABEL[mode]}\n`)}`;

  return (
    <section id="contact" className="border-b border-ink">
      <div className="mx-auto grid max-w-page gap-12 px-5 py-24 sm:px-8 lg:grid-cols-[1.1fr_1fr] lg:items-end lg:py-36">
        <div>
          <p className="eyebrow">Contact · 07</p>
          <h2 className="mt-5 font-display text-[clamp(2.6rem,6vw,5.5rem)] leading-[0.95] text-ink">
            Find out before
            <br />
            your auditor does.
          </h2>
        </div>
        <div className="lg:pb-3">
          <AnimatePresence mode="wait">
            {state === "done" ? (
              <motion.div key="done" initial={{ opacity: 0, scale: 1.08, rotate: -2 }} animate={{ opacity: 1, scale: 1, rotate: 0 }} transition={{ duration: 0.45, ease: [0.34, 1.4, 0.64, 1] }} role="status">
                <p className="inline-block border-[3px] border-safe px-3 py-2 font-mono text-sm uppercase tracking-[0.12em] text-safe">Request received</p>
                <p className="mt-4 text-[17px] text-ink-2">We reply within one working day, to {email}.</p>
              </motion.div>
            ) : state === "unconfigured" ? (
              <motion.div key="mail" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                <p className="text-[17px] text-ink">The request form is offline on this deployment.</p>
                <p className="mt-2 text-ink-2">Send the same request by email and we reply within one working day.</p>
                <Button asChild size="lg" className="mt-6">
                  <a href={mailto}>Email us directly</a>
                </Button>
              </motion.div>
            ) : (
              <motion.form key="form" onSubmit={submit} noValidate exit={{ opacity: 0 }} className="space-y-4">
                <p className="max-w-md text-[17px] text-ink-2">Leave a work email. We scan your public estate and walk you through it on a call.</p>
                <div className="grid gap-3 sm:grid-cols-[1fr_180px]">
                  <label className="block">
                    <span className="sr-only">Work email</span>
                    <Input
                      id="lead-email"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      onBlur={() => setTouched(true)}
                      placeholder="you@company.com"
                      aria-invalid={touched && !!email && !valid}
                      className="h-12 border-ink text-base"
                    />
                  </label>
                  <label className="block">
                    <span className="sr-only">Deployment</span>
                    <Select value={mode} onChange={(e) => setMode(e.target.value as Mode)} className="h-12 border-ink">
                      {(Object.keys(MODE_LABEL) as Mode[]).map((m) => (
                        <option key={m} value={m}>
                          {MODE_LABEL[m]}
                        </option>
                      ))}
                    </Select>
                  </label>
                </div>
                {touched && email && !valid && <p className="text-xs text-immediate">Enter a valid email address.</p>}
                {state === "error" && (
                  <p role="alert" className="text-sm text-immediate">
                    {message}
                  </p>
                )}
                <Button type="submit" size="lg" pending={state === "sending"} pendingLabel="Sending" disabled={!email}>
                  Request a scan
                </Button>
              </motion.form>
            )}
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
}
