"use client";

import { useId, useRef } from "react";
import { motion } from "motion/react";
import { cn, formatDate, formatRelative } from "@/lib/utils";
import { gsap, useGSAP, SplitText, MOTION_QUERIES } from "@/lib/gsap";
import { Tip } from "./overlay";

/** Headline whose lines rise out of a mask. Falls back to a plain heading with reduced motion. */
export function SplitHeading({
  as: Tag = "h1",
  children,
  className,
  delay = 0,
}: {
  as?: "h1" | "h2" | "h3";
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef<HTMLHeadingElement>(null);
  useGSAP(
    () => {
      const el = ref.current;
      if (!el) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const split = SplitText.create(el, { type: "lines", mask: "lines", linesClass: "split-line" });
        // Revert to plain text once landed so resizes reflow naturally.
        gsap.from(split.lines, {
          yPercent: 110,
          duration: 0.85,
          stagger: 0.08,
          delay,
          ease: "instrument",
          onComplete: () => split.revert(),
        });
        return () => split.revert();
      });
      return () => mm.revert();
    },
    { scope: ref }
  );
  return (
    <Tag ref={ref} className={className}>
      {children}
    </Tag>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
}: {
  eyebrow?: React.ReactNode;
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("flex flex-col gap-6 border-b border-ink pb-6 lg:flex-row lg:items-end lg:justify-between", className)}>
      <div className="min-w-0 max-w-3xl">
        {eyebrow && <p className="eyebrow mb-3">{eyebrow}</p>}
        <SplitHeading className="font-display text-[2.25rem] leading-[1.02] text-ink sm:text-[2.75rem]">{title}</SplitHeading>
        {description && (
          <motion.p
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="mt-3 text-[15px] leading-relaxed text-ink-2"
          >
            {description}
          </motion.p>
        )}
      </div>
      {actions && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.25, duration: 0.4 }}
          className="flex flex-wrap items-center gap-2"
        >
          {actions}
        </motion.div>
      )}
    </header>
  );
}

/** A section of a page: mono index, title, optional actions, then content. */
export function Section({
  id,
  index,
  title,
  description,
  actions,
  children,
  className,
}: {
  id?: string;
  index?: string;
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.section
      id={id}
      initial={{ opacity: 0, y: 12 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={{ duration: 0.55, ease: [0.2, 0, 0, 1] }}
      className={cn("scroll-mt-24", className)}
    >
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex items-baseline gap-3 font-display text-[1.45rem] leading-tight text-ink">
            {index && <span className="font-mono text-xs text-ink-3">{index}</span>}
            {title}
          </h2>
          {description && <p className="mt-1 max-w-2xl text-sm text-ink-2">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </motion.section>
  );
}

export function RelTime({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) return <span className={cn("text-ink-3", className)}>never</span>;
  return (
    <Tip label={formatDate(value)}>
      <time dateTime={value} className={cn("cursor-default whitespace-nowrap", className)}>
        {formatRelative(value)}
      </time>
    </Tip>
  );
}

/** Segmented control: a sliding ink fill marks the active option. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  className,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode }[];
  label: string;
  className?: string;
}) {
  const id = useId();
  return (
    <div role="radiogroup" aria-label={label} className={cn("inline-flex max-w-full flex-wrap border border-ink", className)}>
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(o.value)}
            className={cn(
              "relative h-8 px-3 text-[13px] font-medium transition-colors duration-micro [&+&]:border-l [&+&]:border-ink",
              active ? "text-bg" : "text-ink-2 hover:text-ink"
            )}
          >
            {active && (
              <motion.span
                layoutId={id}
                className="absolute inset-0 bg-ink"
                transition={{ type: "spring", stiffness: 520, damping: 42 }}
              />
            )}
            <span className="relative">{o.label}</span>
          </button>
        );
      })}
    </div>
  );
}
