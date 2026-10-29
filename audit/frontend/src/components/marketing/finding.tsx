"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

const STATS = [
  { n: 100, suffix: "%", label: "of certificates stay classical", note: "RSA and ECDSA, forgeable by a quantum computer. Primary corpus, n = 53." },
  { n: 51, suffix: "%", label: "of firms expose an origin", note: "Reachable outside the CDN edge. n = 118, 95% CI 42 to 60. India 48%, international 62%." },
  { n: 0, suffix: "", label: "are quantum-safe end to end", note: "Across every endpoint measured, edge to origin." },
];

/**
 * The finding. Pinned while the user scrolls: the "quantum-safe" CDN shield peels away
 * from the bottom up, revealing the classical origin it was standing in front of.
 */
export function Finding() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(`${MOTION_QUERIES.full} and (min-width: 1024px)`, () => {
        const tl = gsap.timeline({
          scrollTrigger: { trigger: root.current, start: "top top", end: "+=140%", scrub: 0.6, pin: true, anticipatePin: 1 },
          defaults: { ease: "none" },
        });
        tl.to(".peel", { clipPath: "inset(0% 0% 100% 0%)", duration: 1 })
          .to(".peel-edge", { yPercent: -100, opacity: 0, duration: 0.3 }, 0.85)
          .from(".origin-detail > *", { opacity: 0, y: 10, stagger: 0.08, duration: 0.3 }, 0.55)
          .from(".finding-stat", { opacity: 0.15, duration: 0.25, stagger: 0.25 }, 0.1);
        gsap.utils.toArray<HTMLElement>(".finding-count").forEach((el) => {
          gsap.from(el, { textContent: 0, snap: { textContent: 1 }, duration: 1.4, ease: "instrument", scrollTrigger: { trigger: el, start: "top 85%" } });
        });
      });
      mm.add(`${MOTION_QUERIES.full} and (max-width: 1023px)`, () => {
        gsap.to(".peel", { clipPath: "inset(0% 0% 100% 0%)", ease: "none", scrollTrigger: { trigger: ".peel-stage", start: "top 70%", end: "bottom 30%", scrub: true } });
        gsap.utils.toArray<HTMLElement>(".finding-count").forEach((el) => {
          gsap.from(el, { textContent: 0, snap: { textContent: 1 }, duration: 1.2, scrollTrigger: { trigger: el, start: "top 90%" } });
        });
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  return (
    <section id="finding" ref={root} className="relative border-b border-ink lg:h-dvh">
      <div className="mx-auto grid h-full max-w-page items-center gap-12 px-5 py-24 sm:px-8 lg:grid-cols-[1fr_1fr] lg:gap-20 lg:py-0">
        <div>
          <p className="eyebrow">The finding · 01</p>
          <h2 className="mt-5 font-display text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] text-ink">
            The edge says safe.
            <br />
            The origin disagrees.
          </h2>
          <p className="mt-6 max-w-lg text-[17px] leading-relaxed text-ink-2">
            A CDN can terminate TLS with hybrid ML-KEM, and a passive scanner sees only that. Behind it, the origin still runs RSA and X25519, and
            in half of firms anyone can reach it directly.
          </p>
          <dl className="mt-10 border-t border-ink">
            {STATS.map((s) => (
              <div key={s.label} className="finding-stat grid grid-cols-[120px_1fr] items-baseline gap-6 border-b border-rule py-5">
                <dt className="font-display text-5xl leading-none text-ink tabular">
                  <span className="finding-count">{s.n}</span>
                  {s.suffix}
                </dt>
                <dd>
                  <span className="block text-[15px] text-ink">{s.label}</span>
                  <span className="mt-1 block font-mono text-[11px] leading-relaxed text-ink-3">{s.note}</span>
                </dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="peel-stage relative aspect-[4/5] w-full max-w-[520px] justify-self-center lg:aspect-[4/5]">
          {/* Underneath: the origin, as it really is. */}
          <div className="absolute inset-0 flex flex-col border border-immediate bg-bg p-7">
            <div className="flex items-center justify-between">
              <span className="eyebrow text-immediate">Origin · direct</span>
              <span className="font-mono text-[11px] text-ink-3">13.x.x.x</span>
            </div>
            <div className="origin-detail mt-auto space-y-4">
              <p className="font-display text-4xl leading-none text-ink">origin.examplebank.in</p>
              <dl className="grid grid-cols-2 gap-px border border-rule bg-rule font-mono text-sm [&>div]:bg-bg">
                {[
                  ["Certificate", "RSA-2048"],
                  ["Key exchange", "X25519"],
                  ["PQC", "none"],
                  ["Reachable", "from anywhere"],
                ].map(([k, v]) => (
                  <div key={k} className="p-3">
                    <dt className="eyebrow">{k}</dt>
                    <dd className="mt-1 text-ink">{v}</dd>
                  </div>
                ))}
              </dl>
              <p className="inline-block border-2 border-immediate px-2 py-0.5 font-mono text-xs uppercase tracking-[0.1em] text-immediate">Harvest now, decrypt later</p>
            </div>
          </div>

          {/* On top: the shield everyone measures. Peels away with scroll. */}
          <div className="peel absolute inset-0 flex flex-col border border-ink bg-ink p-7 text-bg" style={{ clipPath: "inset(0% 0% 0% 0%)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-bg/70">CDN edge · what scanners see</span>
              <span className="font-mono text-[11px] text-bg/60">Cloudflare</span>
            </div>
            <div className="mt-auto space-y-4">
              <p className="font-display text-4xl leading-none">examplebank.in</p>
              <p className="font-mono text-sm text-bg/80">Key exchange X25519MLKEM768</p>
              <p className="inline-block border-2 border-bg/80 px-2 py-0.5 font-mono text-xs uppercase tracking-[0.1em]">Quantum-safe</p>
            </div>
            <span className="peel-edge pointer-events-none absolute inset-x-0 bottom-0 h-px bg-accent" />
          </div>
        </div>
      </div>
    </section>
  );
}
