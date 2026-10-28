"use client";

import { motion } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;
const RESEARCH_URL = "https://github.com/LochanPS/seqr-labs-research";
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.68)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const AMBER = "#A65A16";

const FACTS = [
  { k: "60+", v: "endpoints actively measured" },
  { k: "Open", v: "datasets and methodology" },
  { k: "n = 53", v: "primary corpus, with 95% CIs" },
];

export function ResearchStat() {
  return (
    <section className="px-6" style={{ background: paper.bgRaise, borderTop: `1px solid ${paper.line}`, borderBottom: `1px solid ${paper.line}` }}>
      <div className="mx-auto max-w-5xl py-24">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5, ease: EASE }}
          className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
          style={{ color: paper.accent }}
        >
          The research
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-4 max-w-[20ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(1.8rem, 4vw, 2.75rem)", color: paper.ink, lineHeight: 1.05 }}
        >
          Not a claim. A measurement.
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.12 }}
          className="mt-5 max-w-[60ch] text-lg leading-relaxed"
          style={{ color: paper.inkMuted }}
        >
          Every number on this page comes from an independent study of Indian financial-services
          TLS endpoints, with open data and methodology. Read the paper, check the datasets,
          reproduce the scan.
        </motion.p>

        <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-3">
          {FACTS.map((f, i) => (
            <motion.div
              key={f.k}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.5, delay: i * 0.08, ease: EASE }}
              className="flex flex-col rounded-2xl p-6"
              style={{ background: paper.ink, border: `1px solid ${DARK_LINE}`, boxShadow: "0 18px 44px rgba(23,21,18,0.18)" }}
            >
              <div className="font-display text-2xl font-bold tracking-tight" style={{ color: AMBER }}>
                {f.k}
              </div>
              <div className="mt-1 text-sm" style={{ color: CREAM_MUTED }}>
                {f.v}
              </div>
            </motion.div>
          ))}
        </div>

        <a
          href={RESEARCH_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-10 inline-block border-b-2 pb-0.5 text-[0.95rem] font-semibold transition-opacity hover:opacity-60"
          style={{ color: paper.ink, borderColor: paper.ink }}
        >
          Read the paper and datasets
        </a>
      </div>
    </section>
  );
}
