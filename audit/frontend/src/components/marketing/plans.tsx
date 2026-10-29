"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { Flip } from "@/lib/gsap";
import { Button } from "@/components/ui/button";
import { CommandLine } from "@/components/ui/code";
import { IconExternal } from "@/components/icons";
import { scrollToSection } from "./scroll";

export type Mode = "cli" | "cloud" | "onprem";

const MODES: { value: Mode; label: string; title: string; lede: string }[] = [
  { value: "cli", label: "Your laptop", title: "The SeQr CLI", lede: "Free and open. Run a passive scan from anywhere, with no account." },
  { value: "cloud", label: "SeQr cloud", title: "The SeQr platform", lede: "The full audit: active probing, the CBOM, the graph, remediation planning and reports." },
  { value: "onprem", label: "Your infrastructure", title: "On-premise and air-gapped", lede: "The same platform, inside your network. Nothing leaves it." },
];

const CAPS: { label: string; modes: Mode[] }[] = [
  { label: "Passive TLS, SSH and mail scan", modes: ["cli", "cloud", "onprem"] },
  { label: "Runs anywhere, no sign-up", modes: ["cli"] },
  { label: "Active ML-KEM probe, the real number", modes: ["cloud", "onprem"] },
  { label: "CycloneDX 1.6 CBOM inventory", modes: ["cloud", "onprem"] },
  { label: "Origin discovery behind the CDN", modes: ["cloud", "onprem"] },
  { label: "Crypto-asset graph and policy engine", modes: ["cloud", "onprem"] },
  { label: "Remediation planner and signed bundles", modes: ["cloud", "onprem"] },
  { label: "Scan history and PDF reports", modes: ["cloud", "onprem"] },
  { label: "Discovery agent for internal systems", modes: ["onprem"] },
  { label: "Zero data egress, offline licence, no telemetry", modes: ["onprem"] },
  { label: "SSO with OIDC and SAML", modes: ["cloud", "onprem"] },
];

export function Plans({ onRequest }: { onRequest: (mode: Mode) => void }) {
  const [mode, setMode] = useState<Mode>("cloud");
  const list = useRef<HTMLUListElement>(null);
  const state = useRef<Flip.FlipState | null>(null);
  const m = MODES.find((x) => x.value === mode)!;
  const ordered = [...CAPS].sort((a, b) => Number(b.modes.includes(mode)) - Number(a.modes.includes(mode)));

  const choose = (v: Mode) => {
    if (list.current) state.current = Flip.getState(list.current.querySelectorAll("[data-cap]"));
    setMode(v);
  };

  useLayoutEffect(() => {
    if (!state.current) return;
    if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      Flip.from(state.current, { duration: 0.55, ease: "instrument", stagger: 0.012 });
    }
    state.current = null;
  }, [mode]);

  return (
    <section id="plans" className="border-b border-ink">
      <div className="mx-auto max-w-page px-5 py-24 sm:px-8 lg:py-32">
        <p className="eyebrow">Plans · 06</p>
        <h2 className="mt-5 max-w-3xl font-display text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] text-ink">Where should it run?</h2>

        <div className="mt-12 grid gap-12 lg:grid-cols-[380px_1fr]">
          <div role="radiogroup" aria-label="Where SeQr runs" className="flex flex-col border-t border-ink">
            {MODES.map((x, i) => {
              const on = x.value === mode;
              return (
                <button
                  key={x.value}
                  role="radio"
                  aria-checked={on}
                  onClick={() => choose(x.value)}
                  className={cn("flex items-baseline gap-4 border-b border-rule px-4 py-5 text-left transition-colors duration-micro", on ? "bg-ink text-bg" : "text-ink hover:bg-surface")}
                >
                  <span className={cn("font-mono text-xs", on ? "text-bg/60" : "text-ink-3")}>{String(i + 1).padStart(2, "0")}</span>
                  <span className="font-display text-2xl">{x.label}</span>
                </button>
              );
            })}
          </div>

          <div>
            <div className="flex flex-wrap items-end justify-between gap-6 border-b border-ink pb-6">
              <div>
                <p className="font-display text-3xl text-ink">{m.title}</p>
                <p className="mt-2 max-w-lg text-ink-2">{m.lede}</p>
              </div>
              {mode === "cli" ? (
                <Button asChild variant="secondary">
                  <a href="https://pypi.org/project/seqr/" target="_blank" rel="noopener noreferrer">
                    View on PyPI <IconExternal size={14} />
                  </a>
                </Button>
              ) : (
                <Button
                  onClick={() => {
                    onRequest(mode);
                    scrollToSection("contact", "#lead-email");
                  }}
                >
                  Request access
                </Button>
              )}
            </div>
            {mode === "cli" && <CommandLine command="pip install seqr" className="mt-6 max-w-md" />}
            <ul ref={list} className="mt-6">
              {ordered.map((c) => {
                const yes = c.modes.includes(mode);
                return (
                  <li key={c.label} data-cap data-flip-id={c.label} className="flex items-center gap-4 border-b border-rule py-3">
                    <span aria-hidden className={cn("h-2.5 w-2.5 shrink-0 border border-ink", yes ? "bg-ink" : "bg-transparent")} />
                    <span className={cn("text-[15px]", yes ? "text-ink" : "text-ink-3 line-through decoration-rule")}>{c.label}</span>
                    <span className="sr-only">{yes ? "included" : "not included"}</span>
                  </li>
                );
              })}
            </ul>
            <p className="mt-6 text-sm text-ink-3">Pricing depends on asset count and deployment. We quote after a short call, never before.</p>
          </div>
        </div>
      </div>
    </section>
  );
}
