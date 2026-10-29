"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

const START = new Date("2025-01-01").getTime();
const END = new Date("2028-01-01").getTime();

const MARKERS = [
  {
    id: "pci",
    name: "PCI DSS 12.3.3",
    date: "2025-03-31",
    when: "Since 31 March 2025",
    status: "Mandatory now",
    live: true,
    detail:
      "Card-data environments must keep a documented inventory of cryptographic cipher suites and protocols, reviewed at least once a year. SeQr builds that inventory as a CycloneDX CBOM.",
  },
  {
    id: "sebi",
    name: "SEBI CSCRF",
    date: "2025-06-15",
    when: "Since June 2025",
    status: "Live for SEBI REs",
    live: true,
    detail:
      "Regulated entities are expected to inventory their cryptographic assets and prioritise post-quantum migration under the Cybersecurity and Cyber Resilience Framework.",
  },
  {
    id: "rbi",
    name: "RBI Q-SAFE",
    date: "2026-11-15",
    when: "Expected around November 2026",
    status: "Framework around Nov 2026",
    live: false,
    detail:
      "RBI's Q-SAFE committee is reviewing financial-sector cryptography through CBOM and crypto-agility. Banks that already hold an inventory will be ready for whatever it asks.",
  },
  {
    id: "dpdp",
    name: "DPDP Act 2023",
    date: "2027-05-13",
    when: "13 May 2027",
    status: "Enforceable 13 May 2027",
    live: false,
    detail:
      "Section 8 safeguards, with penalties up to Rs 250 crore, become enforceable. Personal data on quantum-vulnerable transport is a long-shelf-life exposure.",
  },
  {
    id: "dst",
    name: "DST roadmap",
    date: "2027-10-01",
    when: "By 2027",
    status: "CII inventory by 2027",
    live: false,
    detail:
      "India's national post-quantum roadmap targets a cryptographic-asset inventory for critical information infrastructure, which includes BFSI. It is recommendatory, not a statutory filing deadline.",
  },
];

const pct = (d: string | number) => ((new Date(d).getTime() - START) / (END - START)) * 100;

export function WhyNow() {
  const root = useRef<HTMLElement>(null);
  const [open, setOpen] = useState("pci");
  // "Today" depends on the viewer's clock, so it is placed after hydration.
  const [today, setToday] = useState<{ x: number; label: string } | null>(null);
  useEffect(() => {
    setToday({
      x: Math.min(100, Math.max(0, pct(Date.now()))),
      label: new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }),
    });
  }, []);
  const active = MARKERS.find((m) => m.id === open)!;

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const tl = gsap.timeline({ scrollTrigger: { trigger: ".ruler", start: "top 75%" } });
        tl.from(".ruler-axis", { scaleX: 0, transformOrigin: "0% 50%", duration: 1.1, ease: "instrument" })
          .from(".ruler-tick", { scaleY: 0, transformOrigin: "50% 0%", stagger: 0.02, duration: 0.3 }, 0.2)
          .from(".ruler-mark", { opacity: 0, y: -12, stagger: 0.12, duration: 0.5, ease: "press" }, 0.6)
          .from(".ruler-today", { opacity: 0, scaleY: 0, transformOrigin: "50% 100%", duration: 0.6 }, 1.1);
        return () => tl.kill();
      });
      return () => mm.revert();
    },
    { scope: root, dependencies: [!!today], revertOnUpdate: true }
  );

  const months = Array.from({ length: 37 }, (_, i) => i);

  return (
    <section id="why-now" ref={root} className="border-b border-ink bg-surface">
      <div className="mx-auto max-w-page px-5 py-24 sm:px-8 lg:py-32">
        <div className="grid gap-6 lg:grid-cols-[1fr_1fr] lg:items-end">
          <div>
            <p className="eyebrow">Why now · 05</p>
            <h2 className="mt-5 font-display text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] text-ink">
              The inventory is
              <br />
              already expected.
            </h2>
          </div>
          <p className="max-w-lg text-[17px] leading-relaxed text-ink-2 lg:justify-self-end">
            Two requirements are live today. Three more land before the end of 2027. Select a marker to read what each one asks for.
          </p>
        </div>

        <div className="ruler relative mt-20 overflow-x-auto pb-4">
          <div className="relative mx-8 min-w-[760px] pt-24">
            <div className="ruler-axis h-px bg-ink" />
            <div className="relative h-4">
              {months.map((m) => (
                <span
                  key={m}
                  className={cn("ruler-tick absolute top-0 w-px bg-ink", m % 12 === 0 ? "h-4" : m % 3 === 0 ? "h-2.5" : "h-1.5")}
                  style={{ left: `${(m / 36) * 100}%` }}
                />
              ))}
            </div>
            <div className="relative mt-2 h-5 font-mono text-[11px] text-ink-3">
              {[2025, 2026, 2027, 2028].map((y, i) => (
                <span key={y} className="absolute -translate-x-1/2" style={{ left: `${(i / 3) * 100}%` }}>
                  {y}
                </span>
              ))}
            </div>

            {today && (
              <div className="ruler-today absolute bottom-[40px] top-6 w-px bg-accent" style={{ left: `${today.x}%` }}>
                <span className="absolute -top-1 left-1/2 -translate-x-1/2 -translate-y-full whitespace-nowrap bg-accent px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] text-bg">
                  Today · {today.label}
                </span>
              </div>
            )}

            {MARKERS.map((m, i) => {
              const on = m.id === open;
              return (
                <button
                  key={m.id}
                  onClick={() => setOpen(m.id)}
                  onFocus={() => setOpen(m.id)}
                  aria-expanded={on}
                  aria-controls="why-detail"
                  className="ruler-mark group absolute flex -translate-x-1/2 flex-col items-center"
                  style={{ left: `${pct(m.date)}%`, top: i % 2 === 0 ? 30 : 0 }}
                >
                  <span
                    className={cn(
                      "whitespace-nowrap border px-2 py-1 font-mono text-[11px] transition-colors duration-micro",
                      on ? "border-ink bg-ink text-bg" : m.live ? "border-ink bg-bg text-ink group-hover:bg-surface-2" : "border-rule bg-bg text-ink-2 group-hover:border-ink group-hover:text-ink"
                    )}
                  >
                    {m.name}
                  </span>
                  <span className={cn("w-px bg-ink", i % 2 === 0 ? "h-[42px]" : "h-[72px]")} />
                  <span className={cn("h-2.5 w-2.5 border border-ink", m.live ? "bg-ink" : "bg-bg")} />
                </button>
              );
            })}
          </div>
        </div>

        <div id="why-detail" className="mt-10 grid gap-8 border-t border-ink pt-8 lg:grid-cols-[1fr_2fr]" aria-live="polite">
          <AnimatePresence mode="wait">
            <motion.div key={active.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.28, ease: [0.2, 0, 0, 1] }} className="contents">
              <div>
                <p className="font-display text-3xl text-ink">{active.name}</p>
                <p className="mt-2 font-mono text-xs text-ink-3">{active.when}</p>
                <p
                  className={cn(
                    "mt-4 inline-block border-2 px-2 py-0.5 font-mono text-xs uppercase tracking-[0.1em]",
                    active.live ? "border-immediate text-immediate" : "border-planned text-planned"
                  )}
                >
                  {active.status}
                </p>
              </div>
              <p className="max-w-2xl text-[17px] leading-relaxed text-ink-2">{active.detail}</p>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
}
