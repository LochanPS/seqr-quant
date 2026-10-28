"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const EASE = [0.22, 1, 0.36, 1] as const;
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.68)";
const CREAM_FAINT = "rgba(244, 241, 233, 0.42)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const AMBER = "#A65A16";

function useCountUp(target: number, run: boolean, dur = 1300) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!run) return;
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      const e = 1 - Math.pow(1 - p, 4);
      setV(Math.round(target * e));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [run, target, dur]);
  return v;
}

const STATS = [
  { n: 100, label: "of certificates stay classical", sub: "RSA / ECDSA, forgeable by a quantum computer" },
  { n: 51, label: "of firms expose an origin", sub: "reachable outside the protected CDN edge" },
  { n: 0, label: "are end-to-end quantum-safe", sub: "across every endpoint we measured" },
];

function StatCard({ n, label, sub, run, i }: { n: number; label: string; sub: string; run: boolean; i: number }) {
  const val = useCountUp(n, run);
  const tone = n === 0 ? CREAM_FAINT : AMBER;
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      animate={run ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.55, delay: 0.2 + i * 0.1, ease: EASE }}
      className="flex flex-col rounded-2xl p-7"
      style={{ background: paper.ink, border: `1px solid ${DARK_LINE}`, boxShadow: "0 18px 44px rgba(23,21,18,0.18)" }}
    >
      <span
        className="font-display tabular-nums leading-none"
        style={{ fontSize: "clamp(2.75rem, 6vw, 4rem)", fontWeight: 800, color: tone }}
      >
        {run ? val : 0}%
      </span>
      <p className="mt-4 text-base font-medium" style={{ color: CREAM }}>{label}</p>
      <p className="mt-1 text-sm" style={{ color: CREAM_FAINT }}>{sub}</p>
      <div className="mt-5 h-[5px] w-full overflow-hidden rounded-full" style={{ background: "rgba(244,241,233,0.10)" }}>
        <motion.div
          className="h-full origin-left rounded-full"
          style={{ background: tone, width: `${Math.max(n, 1)}%` }}
          initial={{ scaleX: 0 }}
          animate={run ? { scaleX: 1 } : {}}
          transition={{ duration: 1, delay: 0.4 + i * 0.1, ease: EASE }}
        />
      </div>
    </motion.div>
  );
}

export function MirageReveal() {
  const ref = useRef<HTMLDivElement>(null);
  const run = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section id="finding" className="px-6" style={{ background: paper.bg }}>
      <div ref={ref} className="mx-auto max-w-6xl py-28">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={run ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5, ease: EASE }}
          className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
          style={{ color: paper.accent }}
        >
          01 · The mirage
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 16 }}
          animate={run ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-5 max-w-[20ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(2rem, 5vw, 3.4rem)", color: paper.ink, lineHeight: 1.03 }}
        >
          The 60% is a default, not a decision.
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          animate={run ? { opacity: 1 } : {}}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="mt-6 max-w-[60ch] text-lg leading-relaxed"
          style={{ color: paper.inkMuted }}
        >
          The post-quantum key exchange lives only at the content-delivery edge, switched on
          by CloudFront and Cloudflare. Look past the edge and the picture inverts.
        </motion.p>

        <div className="mt-14 grid grid-cols-1 gap-4 md:grid-cols-3">
          {STATS.map((s, i) => (
            <StatCard key={s.label} {...s} run={run} i={i} />
          ))}
        </div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={run ? { opacity: 1 } : {}}
          transition={{ duration: 0.6, delay: 0.7 }}
          className="mt-12 max-w-[62ch] text-lg leading-relaxed"
          style={{ color: paper.ink }}
        >
          Nobody in the data migrated on purpose. They inherited edge defaults that stop at the
          certificate, at the origin server, and at the cryptographic inventory that PCI DSS and
          SEBI now require.
        </motion.p>
      </div>
    </section>
  );
}
