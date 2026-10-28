"use client";

import { motion } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.68)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const AMBER = "#A65A16";

const STEPS = [
  {
    n: "01",
    title: "Scan",
    body: "Point SeQr at a domain, mail server, SSH host, or codebase. It actively probes TLS and certificates for quantum-vulnerable cryptography. No agents, no special access.",
  },
  {
    n: "02",
    title: "Inventory",
    body: "Every finding becomes a Cryptographic Bill of Materials in CycloneDX 1.6, the machine-readable inventory PCI DSS 12.3.3 and SEBI CSCRF now ask auditors to see.",
  },
  {
    n: "03",
    title: "Map",
    body: "See what to fix and in what order, mapped to PCI DSS, SEBI CSCRF, RBI Q-SAFE, and the DST roadmap, with the correct post-quantum replacement for each algorithm.",
  },
];

export function HowItWorks() {
  return (
    <section className="px-6" style={{ background: paper.bg }}>
      <div className="mx-auto max-w-6xl py-28">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5, ease: EASE }}
          className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
          style={{ color: paper.accent }}
        >
          02 · How it works
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-4 max-w-[20ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(1.9rem, 4.5vw, 3rem)", color: paper.ink, lineHeight: 1.04 }}
        >
          From a scan to an audit-ready inventory.
        </motion.h2>

        <div className="mt-14 grid grid-cols-1 gap-4 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <motion.div
              key={s.n}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.5, delay: i * 0.08, ease: EASE }}
              className="flex flex-col rounded-2xl p-7"
              style={{ background: paper.ink, border: `1px solid ${DARK_LINE}`, boxShadow: "0 18px 44px rgba(23,21,18,0.18)" }}
            >
              <span className="font-mono text-sm tabular-nums" style={{ color: AMBER }}>
                {s.n}
              </span>
              <h3 className="font-display mt-4 text-2xl font-semibold tracking-tight" style={{ color: CREAM }}>
                {s.title}
              </h3>
              <p className="mt-3 text-sm leading-relaxed" style={{ color: CREAM_MUTED }}>
                {s.body}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
