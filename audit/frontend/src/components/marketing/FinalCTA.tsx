"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;

export function FinalCTA() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || "Something went wrong. Try again.");
        return;
      }
      setSubmitted(true);
    } catch {
      setError("Network error. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section id="contact" className="px-6" style={{ background: paper.ink }}>
      <div className="mx-auto max-w-4xl py-28 text-center">
        <motion.h2
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 0.6, ease: EASE }}
          className="font-display mx-auto max-w-[16ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(2.2rem, 5.5vw, 4rem)", color: paper.bg, lineHeight: 1.02 }}
        >
          See what your scanners cannot.
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="mx-auto mt-6 max-w-[52ch] text-lg"
          style={{ color: "rgba(244, 241, 233, 0.66)" }}
        >
          Get your cryptographic inventory, actively measured and mapped to PCI DSS 12.3.3 and
          SEBI CSCRF. We reply within one business day.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.18, ease: EASE }}
          className="mx-auto mt-10 max-w-md"
        >
          {submitted ? (
            <p
              className="rounded-full px-6 py-3.5 text-sm"
              style={{ background: "rgba(244,241,233,0.08)", color: paper.bg }}
            >
              Thanks. We will be in touch at {email}.
            </p>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-3 sm:flex-row">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.in"
                className="flex-1 rounded-full px-5 py-3.5 text-sm outline-none"
                style={{
                  background: "rgba(244,241,233,0.06)",
                  border: "1px solid rgba(244,241,233,0.18)",
                  color: paper.bg,
                }}
              />
              <button
                type="submit"
                disabled={submitting}
                className="rounded-full px-6 py-3.5 text-sm font-medium transition-transform hover:-translate-y-px disabled:opacity-60"
                style={{ background: paper.accent, color: paper.bg }}
              >
                {submitting ? "Sending" : "Request a scan"}
              </button>
            </form>
          )}
          {error && (
            <p className="mt-3 text-xs" style={{ color: "#f0a58a" }}>
              {error}
            </p>
          )}
        </motion.div>
      </div>
    </section>
  );
}
