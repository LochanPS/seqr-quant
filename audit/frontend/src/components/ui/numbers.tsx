"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { gsap } from "@/lib/gsap";

/**
 * A numeral that tweens from its previous value to the new one (never from zero on a
 * refetch). Tabular figures keep the width steady while it counts.
 */
export function CountUp({
  value,
  decimals = 0,
  suffix = "",
  prefix = "",
  className,
  duration = 0.7,
}: {
  value: number;
  decimals?: number;
  suffix?: string;
  prefix?: string;
  className?: string;
  duration?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const prev = useRef(0);
  const fmt = (n: number) =>
    prefix + n.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || !Number.isFinite(value)) {
      el.textContent = fmt(value);
      prev.current = value;
      return;
    }
    const state = { n: prev.current };
    const tween = gsap.to(state, {
      n: value,
      duration,
      ease: "instrument",
      onUpdate: () => {
        el.textContent = fmt(state.n);
      },
      onComplete: () => {
        prev.current = value;
      },
    });
    return () => {
      prev.current = state.n;
      tween.kill();
    };
    // fmt is derived from props that are part of the deps below
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, decimals, suffix, prefix, duration]);

  return (
    <span ref={ref} className={cn("tabular", className)}>
      {fmt(prev.current)}
    </span>
  );
}

/** Label, big numeral, footnote. Set into a ruled strip, never floated as a card. */
export function Readout({
  label,
  value,
  foot,
  tone,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  foot?: React.ReactNode;
  tone?: "immediate" | "urgent" | "planned" | "safe" | "hybrid";
  className?: string;
}) {
  const toneCls = tone
    ? { immediate: "text-immediate", urgent: "text-urgent", planned: "text-planned", safe: "text-safe", hybrid: "text-hybrid" }[tone]
    : "text-ink";
  return (
    <div className={cn("min-w-0 p-5", className)}>
      <p className="eyebrow">{label}</p>
      <p className={cn("mt-2 font-display text-[2.4rem] leading-none tabular", toneCls)}>{value}</p>
      {foot && <p className="mt-2 text-xs text-ink-3">{foot}</p>}
    </div>
  );
}

/** A ruled strip of readouts that splits into columns with hairline separators. */
export function ReadoutStrip({ children, cols = 4, className }: { children: React.ReactNode; cols?: 2 | 3 | 4 | 5 | 6; className?: string }) {
  const grid = {
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-3",
    4: "sm:grid-cols-2 lg:grid-cols-4",
    5: "sm:grid-cols-3 lg:grid-cols-5",
    6: "sm:grid-cols-3 lg:grid-cols-6",
  }[cols];
  return (
    // A 1px gap over a rule-colored ground draws hairlines between cells at every breakpoint.
    <div className={cn("grid grid-cols-1 gap-px border-y border-rule bg-rule [&>*]:bg-bg", grid, className)}>
      {children}
    </div>
  );
}
