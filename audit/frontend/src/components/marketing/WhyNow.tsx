"use client";

import { motion } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.72)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const AMBER = "#A65A16";

const FRAMEWORKS = [
  { name: "PCI DSS 12.3.3", status: "Mandatory now", detail: "Since 31 March 2025, card-data environments must keep a documented cryptographic inventory, reviewed annually. SeQr satisfies the control the moment your first scan completes." },
  { name: "SEBI CSCRF", status: "Live for SEBI REs", detail: "Since June 2025, regulated entities must inventory all cryptographic assets and prioritise post-quantum migration by risk. Exactly what a SeQr CBOM produces." },
  { name: "RBI Q-SAFE", status: "Framework ~Nov 2026", detail: "RBI's Q-SAFE committee is reviewing financial-sector cryptography through CBOM and crypto-agility. Banks should hold a standing inventory before guidance lands." },
  { name: "DST roadmap", status: "CII inventory by 2027", detail: "India's national PQC roadmap targets a cryptographic-asset inventory for critical infrastructure, which includes banking and finance, by 2027. Recommendatory; sectoral regulators enforce." },
  { name: "DPDP Act 2023", status: "Enforceable May 2027", detail: "Section 8 safeguards and penalties up to Rs 250 Cr become enforceable 13 May 2027. Quantum-vulnerable transport over personal data is a liability you can measure ahead of the deadline." },
];

export function WhyNow() {
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
          03 · Why now
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-4 max-w-[22ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(1.9rem, 4.5vw, 3rem)", color: paper.ink, lineHeight: 1.04 }}
        >
          The inventory is already the deliverable.
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.12 }}
          className="mt-6 max-w-[60ch] text-lg leading-relaxed"
          style={{ color: paper.inkMuted }}
        >
          Two of these are live today. The rest are dated, not hypothetical. Every one asks
          first for a cryptographic inventory.
        </motion.p>

        <div className="mt-14 grid grid-cols-1 gap-4 md:grid-cols-2">
          {FRAMEWORKS.map((f, i) => (
            <motion.div
              key={f.name}
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-50px" }}
              transition={{ duration: 0.5, delay: (i % 2) * 0.08, ease: EASE }}
              className={`flex flex-col rounded-2xl p-7 ${i === FRAMEWORKS.length - 1 ? "md:col-span-2" : ""}`}
              style={{
                background: paper.ink,
                border: `1px solid ${DARK_LINE}`,
                boxShadow: "0 18px 44px rgba(23,21,18,0.18)",
              }}
            >
              <div className="flex items-baseline justify-between gap-4">
                <h3 className="font-display text-xl font-semibold tracking-tight" style={{ color: CREAM }}>
                  {f.name}
                </h3>
                <span className="shrink-0 font-mono text-[0.68rem] uppercase tracking-[0.12em]" style={{ color: AMBER }}>
                  {f.status}
                </span>
              </div>
              <p className="mt-4 max-w-[70ch] text-sm leading-relaxed" style={{ color: CREAM_MUTED }}>
                {f.detail}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
