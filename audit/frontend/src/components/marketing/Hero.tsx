"use client";

import { motion } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const RESEARCH_URL = "https://github.com/LochanPS/seqr-labs-research";
const EASE = [0.22, 1, 0.36, 1] as const;

const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.62)";
const CREAM_FAINT = "rgba(244, 241, 233, 0.40)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const AMBER_ON_DARK = "#D7A352";

function Figure() {
  const rows = [
    { label: "Passive probe", pct: 0, tone: CREAM_FAINT },
    { label: "Active ML-KEM probe", pct: 60, tone: AMBER_ON_DARK },
  ];
  return (
    <div
      className="relative rounded-2xl p-7"
      style={{ background: paper.ink, border: `1px solid ${DARK_LINE}`, boxShadow: "0 24px 60px rgba(23,21,18,0.28)" }}
    >
      <p
        className="font-mono text-[0.7rem] uppercase tracking-[0.2em]"
        style={{ color: CREAM_FAINT }}
      >
        Fig 1 — Hybrid PQC key exchange
      </p>
      <div className="mt-6 space-y-6">
        {rows.map((r, i) => (
          <div key={r.label}>
            <div className="mb-2 flex items-baseline justify-between">
              <span className="text-sm" style={{ color: CREAM_MUTED }}>
                {r.label}
              </span>
              <span
                className="font-display tabular-nums"
                style={{ fontSize: "1.75rem", fontWeight: 800, color: r.tone }}
              >
                {r.pct}%
              </span>
            </div>
            <div className="h-[7px] w-full overflow-hidden rounded-full" style={{ background: "rgba(244,241,233,0.10)" }}>
              <motion.div
                className="h-full origin-left rounded-full"
                style={{ background: r.tone, width: `${Math.max(r.pct, 2)}%` }}
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                transition={{ duration: 1, delay: 0.6 + i * 0.18, ease: EASE }}
              />
            </div>
          </div>
        ))}
      </div>
      <p className="mt-7 border-t pt-4 text-xs" style={{ color: CREAM_FAINT, borderColor: DARK_LINE }}>
        The same endpoints (n = 53), asked two ways. Passive scanning cannot see hybrid
        post-quantum support. Active probing can.
      </p>
    </div>
  );
}

export function Hero() {
  return (
    <section
      className="relative flex min-h-screen items-center"
      style={{ background: paper.bg }}
    >
      <div className="mx-auto grid w-full max-w-6xl grid-cols-1 items-center gap-16 px-6 py-36 lg:grid-cols-[1.15fr_0.85fr]">
        <div>
          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: EASE }}
            className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
            style={{ color: paper.accent }}
          >
            A measurement study · Indian financial services · 2026
          </motion.p>

          <motion.h1
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.06, ease: EASE }}
            className="font-display mt-6 font-extrabold tracking-tight"
            style={{ color: paper.ink, fontSize: "clamp(2.9rem, 7vw, 5.75rem)", lineHeight: 0.98 }}
          >
            Quantum-safe,
            <br />
            <span style={{ color: paper.accent }}>in name only.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.16, ease: EASE }}
            className="mt-8 max-w-xl text-[1.075rem] leading-relaxed"
            style={{ color: paper.inkMuted }}
          >
            We actively measured the TLS cryptography behind 60+ Indian financial-services
            endpoints. Standard scanners call it 0% post-quantum. The real number is 60%, and
            it is a mirage: certificates stay 100% classical, and half of firms expose an
            origin that routes around the protection entirely.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.24, ease: EASE }}
            className="mt-10 flex flex-wrap items-center gap-6"
          >
            <a
              href="#try-it-live"
              className="rounded-full px-6 py-3 text-[0.95rem] font-medium transition-transform hover:-translate-y-px"
              style={{ background: paper.ink, color: paper.bg }}
            >
              Run a live scan
            </a>
            <a
              href={RESEARCH_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="border-b-2 pb-0.5 text-[0.95rem] font-semibold transition-opacity hover:opacity-60"
              style={{ color: paper.ink, borderColor: paper.ink }}
            >
              Read the paper
            </a>
          </motion.div>

          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.5 }}
            className="mt-10 font-mono text-[0.8rem] font-medium"
            style={{ color: paper.inkMuted }}
          >
            pip install seqr · open research · built in India
          </motion.p>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.3, ease: EASE }}
        >
          <Figure />
        </motion.div>
      </div>
    </section>
  );
}
