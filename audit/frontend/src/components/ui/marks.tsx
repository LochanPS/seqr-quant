"use client";

import { useRef } from "react";
import { cn } from "@/lib/utils";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

export type Tone = "immediate" | "urgent" | "planned" | "safe" | "hybrid" | "neutral" | "accent";

const TONE_TEXT: Record<Tone, string> = {
  immediate: "text-immediate border-immediate/50 bg-immediate/10",
  urgent: "text-urgent border-urgent/50 bg-urgent/10",
  planned: "text-planned border-planned/50 bg-planned/10",
  safe: "text-safe border-safe/50 bg-safe/10",
  hybrid: "text-hybrid border-hybrid/50 bg-hybrid/10",
  neutral: "text-ink-2 border-rule bg-surface",
  accent: "text-accent border-accent/50 bg-accent/10",
};

/** Map any backend status word to a data tone. Unknown values stay neutral. */
export function toneFor(value: string | null | undefined): Tone {
  const v = (value ?? "").toLowerCase();
  if (["vulnerable", "immediate", "fail", "failed", "critical", "high", "suspended", "error", "deprecated"].includes(v)) return "immediate";
  if (["urgent", "partial", "monitor", "medium", "running", "pending", "queued", "in_progress", "conflict"].includes(v)) return "urgent";
  if (["planned", "roadmap", "low", "draft", "scheduled"].includes(v)) return "planned";
  if (["safe", "pass", "complete", "completed", "done", "active", "published", "converged", "ok", "ready", "enabled"].includes(v)) return "safe";
  if (["hybrid", "mixed"].includes(v)) return "hybrid";
  return "neutral";
}

export function Chip({
  children,
  tone = "neutral",
  className,
}: {
  children: React.ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-xs border px-1.5 py-[1px] font-mono text-[11px] uppercase tracking-[0.06em]",
        TONE_TEXT[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

export function StatusChip({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) return <span className="font-mono text-xs text-ink-3">n/a</span>;
  return (
    <Chip tone={toneFor(value)} className={className}>
      {value.replace(/_/g, " ")}
    </Chip>
  );
}

/**
 * A stamp that presses onto the page when it mounts or its `value` changes:
 * scale 1.12 to 1, a 2 degree rotation that settles, and ink that bleeds in.
 */
export function Stamp({
  children,
  tone = "neutral",
  value,
  className,
}: {
  children: React.ReactNode;
  tone?: Tone;
  value?: string | number | boolean;
  className?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.fromTo(
          ref.current,
          { scale: 1.12, rotate: -2, opacity: 0 },
          { scale: 1, rotate: 0, opacity: 1, duration: 0.42, ease: "press" }
        );
      });
      return () => mm.revert();
    },
    { dependencies: [value], scope: ref, revertOnUpdate: true }
  );
  return (
    <span
      ref={ref}
      className={cn(
        "inline-flex items-center gap-1.5 border-2 px-2 py-0.5 font-mono text-xs font-medium uppercase tracking-[0.1em]",
        TONE_TEXT[tone],
        "bg-transparent",
        className
      )}
    >
      {children}
    </span>
  );
}

/** A small solid square used as a state glyph in legends and ledgers. */
export function Swatch({ tone, className }: { tone: Tone; className?: string }) {
  const bg: Record<Tone, string> = {
    immediate: "bg-immediate",
    urgent: "bg-urgent",
    planned: "bg-planned",
    safe: "bg-safe",
    hybrid: "bg-hybrid",
    neutral: "bg-ink-3",
    accent: "bg-accent",
  };
  return <span aria-hidden className={cn("inline-block h-2 w-2 shrink-0", bg[tone], className)} />;
}
