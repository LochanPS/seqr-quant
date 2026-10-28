"use client";

import { motion } from "framer-motion";
import { Check } from "lucide-react";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.78)";
const CREAM_FAINT = "rgba(244, 241, 233, 0.5)";
const DARK_LINE = "rgba(244, 241, 233, 0.14)";
const AMBER = "#A65A16";

const TIERS = [
  {
    name: "Free CLI",
    price: "0",
    note: "pip install seqr",
    features: [
      "Passive TLS, SSH and mail scan",
      "Key exchange + forward-secrecy checks",
      "Runs anywhere, no sign-up",
    ],
    cta: "Get the CLI",
    href: "https://pypi.org/project/seqr/",
    featured: false,
  },
  {
    name: "Professional",
    price: "Contact",
    note: "annual license",
    features: [
      "Active ML-KEM probe (the real number)",
      "CycloneDX 1.6 CBOM inventory",
      "PCI DSS 12.3.3 + SEBI CSCRF mapping",
      "Origin discovery, scan history, PDF reports",
    ],
    cta: "Request access",
    href: "#contact",
    featured: true,
  },
  {
    name: "On-premise",
    price: "Custom",
    note: "air-gapped",
    features: [
      "Zero data egress, runs on your infrastructure",
      "Offline license, no telemetry",
      "For banks, PSUs, and critical infrastructure",
      "Dedicated support + SLA",
    ],
    cta: "Talk to us",
    href: "#contact",
    featured: false,
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="px-6" style={{ background: paper.bg }}>
      <div className="mx-auto max-w-6xl py-28">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.5, ease: EASE }}
          className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
          style={{ color: paper.accent }}
        >
          04 · Pricing
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-4 font-bold tracking-tight"
          style={{ fontSize: "clamp(1.9rem, 4.5vw, 3rem)", color: paper.ink }}
        >
          Start free. Scale to on-premise.
        </motion.h2>

        <div className="mt-14 grid grid-cols-1 gap-5 md:grid-cols-3">
          {TIERS.map((t, i) => (
            <motion.div
              key={t.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.08, ease: EASE }}
              className="flex flex-col rounded-2xl p-7"
              style={{
                background: paper.ink,
                border: `1px solid ${t.featured ? "rgba(166,90,22,0.55)" : DARK_LINE}`,
                boxShadow: t.featured
                  ? "0 24px 60px rgba(23,21,18,0.35), 0 0 0 1px rgba(166,90,22,0.15)"
                  : "0 18px 44px rgba(23,21,18,0.20)",
              }}
            >
              <div className="flex items-center justify-between">
                <p className="font-mono text-[0.7rem] uppercase tracking-[0.18em]" style={{ color: CREAM_FAINT }}>
                  {t.name}
                </p>
                {t.featured && (
                  <span className="rounded-full px-2.5 py-1 font-mono text-[0.6rem] uppercase tracking-[0.14em]" style={{ background: "rgba(166,90,22,0.16)", color: AMBER }}>
                    Popular
                  </span>
                )}
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="font-display font-extrabold tracking-tight" style={{ fontSize: "2.5rem", color: CREAM }}>
                  {t.price}
                </span>
                <span className="text-sm" style={{ color: CREAM_FAINT }}>{t.note}</span>
              </div>
              <ul className="mt-6 flex-1 space-y-3">
                {t.features.map((f) => (
                  <li key={f} className="flex items-start gap-2.5 text-sm" style={{ color: CREAM_MUTED }}>
                    <Check className="mt-0.5 h-4 w-4 shrink-0" style={{ color: AMBER }} />
                    {f}
                  </li>
                ))}
              </ul>
              <a
                href={t.href}
                target={t.href.startsWith("http") ? "_blank" : undefined}
                rel={t.href.startsWith("http") ? "noopener noreferrer" : undefined}
                className="mt-8 rounded-full px-5 py-3 text-center text-sm font-medium transition-transform hover:-translate-y-px"
                style={{
                  background: t.featured ? AMBER : "transparent",
                  color: t.featured ? paper.ink : CREAM,
                  border: t.featured ? "none" : `1px solid ${DARK_LINE}`,
                }}
              >
                {t.cta}
              </a>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
