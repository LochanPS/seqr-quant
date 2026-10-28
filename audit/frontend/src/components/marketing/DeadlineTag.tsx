"use client";

import { motion } from "framer-motion";
import { marketing } from "@/lib/marketing-tokens";
import { usePrefersReducedMotion } from "@/lib/use-motion-preference";

// Refined, typographic deadline marker — replaces the old amber "sticker" pill.
// Neutral hairline + monospace label, accent reserved for the date, one live pulse.
export function DeadlineTag({ className = "" }: { className?: string }) {
  const reduced = usePrefersReducedMotion();
  return (
    <div
      className={`inline-flex items-center gap-2.5 rounded-md px-3 py-1.5 ${className}`}
      style={{ border: `1px solid ${marketing.border}`, background: "rgba(255,255,255,0.02)" }}
    >
      <span className="relative flex h-1.5 w-1.5">
        {!reduced && (
          <motion.span
            className="absolute inline-flex h-full w-full rounded-full"
            style={{ background: marketing.accent }}
            animate={{ scale: [1, 2.6], opacity: [0.6, 0] }}
            transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut" }}
          />
        )}
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ background: marketing.accent }} />
      </span>
      <span className="font-mono text-[11px] uppercase tracking-[0.16em]" style={{ color: marketing.textMuted }}>
        DST 2027 quantum-readiness milestone
      </span>
      <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em]" style={{ color: marketing.accent }}>
        2027
      </span>
    </div>
  );
}
