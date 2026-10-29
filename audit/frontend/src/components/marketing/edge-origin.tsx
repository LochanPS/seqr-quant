"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import { IconExternal } from "@/components/icons";
import { RESEARCH_URL } from "./scroll";

const P_EDGE = "M150,170 C220,170 240,96 310,96 L470,96 L560,96";
const P_ORIGIN = "M150,206 C260,206 400,292 540,292";

/** Two routes from one client. Packets ride each path; the origin route ends in alarm. */
export function EdgeOrigin() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const intro = gsap.timeline({ scrollTrigger: { trigger: root.current, start: "top 70%" } });
        intro
          .from(".eo-node", { opacity: 0, y: 10, stagger: 0.12, duration: 0.5 })
          .from(".eo-path", { drawSVG: "0%", duration: 1.1, stagger: 0.25 }, 0.2)
          .from(".eo-copy > *", { opacity: 0, y: 12, stagger: 0.1, duration: 0.6 }, 0.2);

        const loop = gsap.timeline({ repeat: -1, paused: true, defaults: { ease: "power1.inOut" } });
        loop
          .to(".pk-edge", { duration: 2.2, motionPath: { path: ".eo-route-edge", align: ".eo-route-edge", alignOrigin: [0.5, 0.5] } }, 0)
          .fromTo(".pk-origin", { fill: "rgb(var(--accent))" }, { duration: 2.6, fill: "rgb(var(--immediate))", motionPath: { path: ".eo-route-origin", align: ".eo-route-origin", alignOrigin: [0.5, 0.5] } }, 0.6)
          .fromTo(".eo-alarm", { opacity: 0, scale: 1.25 }, { opacity: 1, scale: 1, transformOrigin: "50% 50%", duration: 0.35, ease: "press" }, 3.0)
          .to(".eo-alarm", { opacity: 0, duration: 0.4 }, 3.9);
        // Packets are hidden by default (reduced motion keeps them off); park them on their paths.
        gsap.set(".pk-edge", { opacity: 1, motionPath: { path: ".eo-route-edge", align: ".eo-route-edge", alignOrigin: [0.5, 0.5], end: 0 } });
        gsap.set(".pk-origin", { opacity: 1, motionPath: { path: ".eo-route-origin", align: ".eo-route-origin", alignOrigin: [0.5, 0.5], end: 0 } });
        // Only loop while visible, so it costs nothing off-screen.
        const st = gsap.timeline({
          scrollTrigger: { trigger: root.current, start: "top bottom", end: "bottom top", onToggle: (self) => (self.isActive ? loop.play() : loop.pause()) },
        });
        return () => {
          loop.kill();
          st.kill();
        };
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  const ink = "rgb(var(--ink))";
  return (
    <section ref={root} className="border-b border-ink bg-surface">
      <div className="mx-auto grid max-w-page items-center gap-14 px-5 py-24 sm:px-8 lg:grid-cols-[0.9fr_1.1fr] lg:py-32">
        <div className="eo-copy">
          <p className="eyebrow">Edge and origin · 02</p>
          <h2 className="mt-5 font-display text-[clamp(2.2rem,4.4vw,3.75rem)] leading-[1] text-ink">One client, two routes.</h2>
          <p className="mt-6 max-w-lg text-[17px] leading-relaxed text-ink-2">
            The route through the edge negotiates ML-KEM and passes inspection. The second route goes straight to the origin and negotiates
            what the origin offers, which is classical. Traffic captured on it today can be decrypted once a large quantum computer exists.
          </p>
          <p className="mt-4 max-w-lg text-[17px] leading-relaxed text-ink">SeQr probes both. It finds candidate origins and assesses them directly.</p>
          <a href={RESEARCH_URL} target="_blank" rel="noopener noreferrer" className="mt-8 inline-flex items-center gap-2 text-sm text-ink link-underline">
            See the method, measurement paper section 4.6 <IconExternal size={14} />
          </a>
        </div>
        <figure>
          <svg viewBox="0 0 700 360" className="w-full" role="img" aria-label="A client reaches a quantum-safe CDN edge on one route, and a classical exposed origin on another.">
            <path className="eo-path eo-route-edge" d={P_EDGE} fill="none" stroke="rgb(var(--hybrid))" strokeWidth={1.75} />
            <path className="eo-path eo-route-origin" d={P_ORIGIN} fill="none" stroke="rgb(var(--immediate))" strokeWidth={1.5} strokeDasharray="6 6" />

            <g className="eo-node">
              <rect x="20" y="150" width="130" height="76" fill="rgb(var(--bg))" stroke={ink} />
              <text x="34" y="176" className="fill-ink font-mono" style={{ fontSize: 11, letterSpacing: "0.08em" }}>
                CLIENT
              </text>
              <text x="34" y="200" className="fill-ink-3 font-mono" style={{ fontSize: 10 }}>
                TLS 1.3, asks for PQC
              </text>
            </g>
            <g className="eo-node">
              <rect x="310" y="56" width="160" height="80" fill="rgb(var(--bg))" stroke="rgb(var(--hybrid))" strokeWidth={1.5} />
              <text x="324" y="82" className="fill-ink font-mono" style={{ fontSize: 11, letterSpacing: "0.08em" }}>
                CDN EDGE
              </text>
              <text x="324" y="106" className="font-mono" style={{ fontSize: 10, fill: "rgb(var(--hybrid))" }}>
                X25519MLKEM768
              </text>
              <text x="324" y="122" className="fill-ink-3 font-mono" style={{ fontSize: 9 }}>
                hybrid, passes scanners
              </text>
            </g>
            <g className="eo-node">
              <rect x="560" y="70" width="120" height="52" fill="rgb(var(--bg))" stroke={ink} />
              <text x="574" y="92" className="fill-ink font-mono" style={{ fontSize: 10, letterSpacing: "0.08em" }}>
                REPORT
              </text>
              <text x="574" y="110" className="font-mono" style={{ fontSize: 10, fill: "rgb(var(--safe))" }}>
                quantum-safe
              </text>
            </g>
            <g className="eo-node">
              <rect x="540" y="250" width="150" height="84" fill="rgb(var(--bg))" stroke="rgb(var(--immediate))" />
              <text x="554" y="274" className="fill-ink font-mono" style={{ fontSize: 11, letterSpacing: "0.08em" }}>
                EXPOSED ORIGIN
              </text>
              <text x="554" y="296" className="fill-ink-3 font-mono" style={{ fontSize: 10 }}>
                RSA-2048 · X25519
              </text>
              <text x="554" y="314" className="font-mono" style={{ fontSize: 10, fill: "rgb(var(--immediate))" }}>
                classical
              </text>
            </g>
            <g className="eo-alarm" opacity={0}>
              <rect x="534" y="244" width="162" height="96" fill="none" stroke="rgb(var(--immediate))" strokeWidth={2} />
            </g>
            <rect className="pk-edge" width="10" height="10" fill="rgb(var(--hybrid))" opacity={0} />
            <rect className="pk-origin" width="10" height="10" fill="rgb(var(--accent))" opacity={0} />
          </svg>
          <figcaption className="mt-3 font-mono text-[11px] text-ink-3">Fig. 2. Packets on each route, looped while the figure is on screen.</figcaption>
        </figure>
      </div>
    </section>
  );
}
