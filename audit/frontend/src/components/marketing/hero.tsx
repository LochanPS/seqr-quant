"use client";

import { useRef } from "react";
import { gsap, useGSAP, SplitText, MOTION_QUERIES } from "@/lib/gsap";
import { Button } from "@/components/ui/button";
import { IconExternal } from "@/components/icons";
import { RESEARCH_URL, scrollToSection } from "./scroll";

/**
 * Hero. The signature figure is a handshake drawn as an engineering diagram: a client,
 * a CDN edge and an origin. Lines draw in, the edge's key exchange scrambles from
 * classical to hybrid post-quantum, and the two research readouts fill like gauges.
 */
export function Hero() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const split = SplitText.create(".hero-title", { type: "lines", mask: "lines" });
        // Start the edge on its classical exchange; the timeline scrambles it to hybrid.
        root.current?.querySelectorAll(".hs-kex").forEach((el) => (el.textContent = "X25519"));
        const tl = gsap.timeline({ defaults: { ease: "instrument" } });
        tl.from(".hero-eyebrow", { opacity: 0, y: 8, duration: 0.5 })
          .from(split.lines, { yPercent: 110, duration: 1, stagger: 0.1 }, 0.1)
          .from(".hero-lede", { opacity: 0, y: 12, duration: 0.7 }, 0.5)
          .from(".hero-cta > *", { opacity: 0, y: 10, duration: 0.5, stagger: 0.08 }, 0.65)
          .from(".hs-frame", { drawSVG: "0%", duration: 1.2 }, 0.3)
          .from(".hs-node", { opacity: 0, y: 6, duration: 0.5, stagger: 0.12 }, 0.6)
          .from(".hs-line", { drawSVG: "0%", duration: 1, stagger: 0.2 }, 0.9)
          .from(".hs-tick", { scaleY: 0, transformOrigin: "50% 100%", duration: 0.3, stagger: 0.01 }, 1.0)
          .to(".hs-kex", { duration: 1.2, scrambleText: { text: "X25519MLKEM768", chars: "ABCDEFKLMNX0123456789", speed: 0.6 } }, 1.5)
          .from(".hs-kex-tag", { opacity: 0, scale: 1.15, rotate: -2, duration: 0.4, ease: "press" }, 2.6)
          .from(".hs-bar", { scaleX: 0, transformOrigin: "0% 50%", duration: 1.1, stagger: 0.2 }, 1.8)
          .from(".hs-count", { textContent: 0, snap: { textContent: 1 }, duration: 1.1, stagger: 0.2 }, 1.8)
          .from(".hs-caption", { opacity: 0, duration: 0.6 }, 2.4);

        // Scrolling away pushes the figure back and softens it into the next section.
        gsap.to(".hero-figure", {
          yPercent: -8,
          opacity: 0.35,
          ease: "none",
          scrollTrigger: { trigger: root.current, start: "top top", end: "bottom top", scrub: true },
        });
        return () => split.revert();
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  return (
    <section ref={root} className="relative border-b border-ink pt-[72px]">
      <div className="mx-auto grid max-w-page gap-12 px-5 pb-20 pt-16 sm:px-8 lg:grid-cols-[1.2fr_1fr] lg:gap-16 lg:pb-28 lg:pt-24">
        <div className="flex flex-col justify-center">
          <p className="hero-eyebrow eyebrow">A measurement study · Indian financial services · 2026</p>
          <h1 className="hero-title mt-6 font-display text-[clamp(2.8rem,6.4vw,7rem)] leading-[0.95] tracking-[-0.02em] text-ink">
            Quantum-safe,
            <br />
            <span className="text-accent">in name only.</span>
          </h1>
          <p className="hero-lede mt-8 max-w-[34rem] text-[17px] leading-relaxed text-ink-2">
            We actively measured the TLS behind more than 60 Indian financial-services endpoints. Standard scanners report 0% post-quantum. The real figure
            is 60%, yet every certificate stays classical and half of firms expose an origin that routes around the protection.
          </p>
          <div className="hero-cta mt-10 flex flex-wrap items-center gap-3">
            <Button size="lg" onClick={() => scrollToSection("try-it-live", "#scan-domain")}>
              Scan a domain
            </Button>
            <Button asChild size="lg" variant="secondary">
              <a href={RESEARCH_URL} target="_blank" rel="noopener noreferrer">
                Read the research <IconExternal size={16} />
              </a>
            </Button>
          </div>
        </div>

        <figure className="hero-figure relative">
          <HandshakeFigure />
          <figcaption className="hs-caption mt-4 max-w-md text-xs leading-relaxed text-ink-3">
            Fig. 1. The same 53 endpoints, asked two ways. A passive probe cannot see hybrid post-quantum key exchange. An active ML-KEM probe can.
          </figcaption>
        </figure>
      </div>
    </section>
  );
}

function HandshakeFigure() {
  const ink = "rgb(var(--ink))";
  const ink3 = "rgb(var(--ink-3))";
  const rule = "rgb(var(--rule))";
  return (
    <div className="border border-ink bg-surface">
      <div className="flex items-center justify-between border-b border-ink px-4 py-2">
        <span className="eyebrow text-ink">Handshake, as measured</span>
        <span className="font-mono text-[11px] text-ink-3">TLS 1.3 · port 443</span>
      </div>
      <svg viewBox="0 0 560 300" className="block w-full" role="img" aria-label="A client completes a hybrid post-quantum handshake with the CDN edge, while the origin behind it remains classical.">
        <rect className="hs-frame" x="12" y="12" width="536" height="276" fill="none" stroke={rule} strokeDasharray="2 4" />
        {/* ticks along the bottom, like a ruler */}
        {Array.from({ length: 53 }).map((_, i) => (
          <line key={i} className="hs-tick" x1={20 + i * 10} x2={20 + i * 10} y1={288} y2={i % 5 === 0 ? 278 : 283} stroke={ink3} strokeWidth={0.75} />
        ))}

        {/* paths */}
        <path className="hs-line" d="M120,110 H250" stroke={ink} strokeWidth={1.5} fill="none" />
        <path className="hs-line" d="M380,110 H420 V210 H440" stroke={ink3} strokeWidth={1.25} strokeDasharray="5 5" fill="none" />
        <path className="hs-line" d="M80,140 V210 H440" stroke="rgb(var(--immediate))" strokeWidth={1.25} strokeDasharray="2 4" fill="none" />

        {/* client */}
        <g className="hs-node">
          <rect x="40" y="80" width="80" height="60" fill="rgb(var(--bg))" stroke={ink} />
          <text x="52" y="102" className="fill-ink font-mono" style={{ fontSize: 10, letterSpacing: "0.08em" }}>
            CLIENT
          </text>
          <text x="52" y="124" className="fill-ink-3 font-mono" style={{ fontSize: 9 }}>
            asks for PQC
          </text>
        </g>

        {/* edge */}
        <g className="hs-node">
          <rect x="250" y="70" width="130" height="80" fill="rgb(var(--bg))" stroke={ink} strokeWidth={1.5} />
          <text x="262" y="92" className="fill-ink font-mono" style={{ fontSize: 10, letterSpacing: "0.08em" }}>
            CDN EDGE
          </text>
          <text className="hs-kex fill-ink font-mono" x="262" y="116" style={{ fontSize: 11 }}>
            X25519MLKEM768
          </text>
          <g className="hs-kex-tag">
            <rect x="262" y="126" width="54" height="15" fill="none" stroke="rgb(var(--hybrid))" strokeWidth={1.25} />
            <text x="289" y="137" textAnchor="middle" className="font-mono" style={{ fontSize: 8.5, fill: "rgb(var(--hybrid))", letterSpacing: "0.1em" }}>
              HYBRID
            </text>
          </g>
        </g>

        {/* origin */}
        <g className="hs-node">
          <rect x="440" y="180" width="100" height="62" fill="rgb(var(--bg))" stroke="rgb(var(--immediate))" />
          <text x="452" y="201" className="fill-ink font-mono" style={{ fontSize: 10, letterSpacing: "0.08em" }}>
            ORIGIN
          </text>
          <text x="452" y="219" className="fill-ink-3 font-mono" style={{ fontSize: 9 }}>
            RSA-2048
          </text>
          <text x="452" y="232" className="font-mono" style={{ fontSize: 9, fill: "rgb(var(--immediate))" }}>
            classical
          </text>
        </g>

        <text x="186" y="102" textAnchor="middle" className="fill-ink-3 font-mono" style={{ fontSize: 8.5 }}>
          key exchange
        </text>
        <text x="200" y="202" className="font-mono" style={{ fontSize: 8.5, fill: "rgb(var(--immediate))" }}>
          direct route around the edge
        </text>
        <text x="392" y="168" className="fill-ink-3 font-mono" style={{ fontSize: 8.5 }} transform="rotate(90 392 168)">
          edge to origin
        </text>
      </svg>
      <div className="grid gap-px border-t border-ink bg-rule sm:grid-cols-2 [&>*]:bg-bg">
        {[
          { label: "Passive probe", pct: 0, cls: "bg-ink-3" },
          { label: "Active ML-KEM probe", pct: 60, cls: "bg-accent" },
        ].map((r) => (
          <div key={r.label} className="p-4">
            <div className="flex items-baseline justify-between">
              <span className="eyebrow">{r.label}</span>
              <span className="font-display text-3xl leading-none text-ink tabular">
                <span className="hs-count">{r.pct}</span>%
              </span>
            </div>
            <div className="relative mt-3 h-2 bg-surface-2">
              <span className={`hs-bar absolute inset-y-0 left-0 ${r.cls}`} style={{ width: `${Math.max(r.pct, 0.5)}%` }} />
            </div>
            <p className="mt-2 font-mono text-[10px] text-ink-3">hybrid PQC key exchange detected, n = 53</p>
          </div>
        ))}
      </div>
    </div>
  );
}
