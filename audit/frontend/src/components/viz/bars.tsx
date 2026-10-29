"use client";

import { useRef } from "react";
import { cn } from "@/lib/utils";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import type { Tone } from "@/components/ui/marks";

const BAR: Record<Tone, string> = {
  immediate: "bg-immediate",
  urgent: "bg-urgent",
  planned: "bg-planned",
  safe: "bg-safe",
  hybrid: "bg-hybrid",
  neutral: "bg-ink-2",
  accent: "bg-accent",
};

/** Horizontal distribution bars that rise from the baseline with a 30ms stagger. */
export function DistributionBars({
  data,
  toneOf,
  className,
  empty = "No data yet.",
}: {
  data: { label: string; value: number }[];
  toneOf?: (label: string) => Tone;
  className?: string;
  empty?: string;
}) {
  const root = useRef<HTMLDivElement>(null);
  const max = Math.max(1, ...data.map((d) => d.value));
  const key = data.map((d) => `${d.label}:${d.value}`).join("|");

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.from(".bar-fill", { scaleX: 0, transformOrigin: "0% 50%", duration: 0.7, stagger: 0.03, ease: "instrument" });
      });
      return () => mm.revert();
    },
    { scope: root, dependencies: [key], revertOnUpdate: true }
  );

  if (!data.length || data.every((d) => d.value === 0)) return <p className="text-sm text-ink-3">{empty}</p>;

  return (
    <div ref={root} className={cn("space-y-2.5", className)}>
      {data.map((d) => (
        <div key={d.label} className="grid grid-cols-[minmax(84px,30%)_1fr_3rem] items-center gap-3">
          <span className="truncate font-mono text-[12px] text-ink-2">{d.label}</span>
          <span className="relative h-2 bg-surface-2">
            <span
              className={cn("bar-fill absolute inset-y-0 left-0", BAR[toneOf?.(d.label) ?? "neutral"])}
              style={{ width: `${(d.value / max) * 100}%` }}
            />
          </span>
          <span className="text-right font-mono text-[12px] text-ink tabular">{d.value}</span>
        </div>
      ))}
    </div>
  );
}

/** A single proportional strip (stacked), e.g. vulnerable / hybrid / safe of a total. */
export function StackStrip({ parts, className }: { parts: { label: string; value: number; tone: Tone }[]; className?: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  return (
    <div className={className}>
      <div className="flex h-3 w-full gap-px bg-bg" role="img" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
        {total === 0 ? (
          <span className="h-full w-full bg-surface-2" />
        ) : (
          parts.map((p) =>
            p.value ? <span key={p.label} className={cn("h-full", BAR[p.tone])} style={{ width: `${(p.value / total) * 100}%` }} /> : null
          )
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {parts.map((p) => (
          <span key={p.label} className="inline-flex items-center gap-1.5 font-mono text-[11px] text-ink-2">
            <span className={cn("h-2 w-2", BAR[p.tone])} />
            {p.label} <span className="text-ink tabular">{p.value}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
