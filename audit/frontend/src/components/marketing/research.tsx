"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import { IconExternal } from "@/components/icons";
import { RESEARCH_URL } from "./scroll";

export function Research() {
  const root = useRef<HTMLElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.from(".rs-num", { textContent: 0, snap: { textContent: 1 }, duration: 1.6, ease: "instrument", scrollTrigger: { trigger: root.current, start: "top 70%" } });
        gsap.from(".rs-rule", { scaleX: 0, transformOrigin: "0% 50%", duration: 1.2, ease: "instrument", scrollTrigger: { trigger: root.current, start: "top 70%" } });
      });
      return () => mm.revert();
    },
    { scope: root }
  );
  return (
    <section ref={root} className="border-b border-ink bg-ink text-bg">
      <div className="mx-auto grid max-w-page gap-10 px-5 py-24 sm:px-8 lg:grid-cols-[auto_1fr] lg:items-end lg:gap-20 lg:py-32">
        <p className="font-display text-[clamp(7rem,20vw,16rem)] leading-[0.8] tabular">
          <span className="rs-num">118</span>
        </p>
        <div>
          <span className="rs-rule block h-px w-full bg-bg/40" />
          <p className="mt-6 max-w-xl text-[19px] leading-relaxed">
            Financial-services domains measured for origin exposure, with 53 in the primary corpus for the handshake study. Every figure on this page comes from that work, with 95% confidence intervals.
          </p>
          <p className="mt-3 font-mono text-xs text-bg/60">PQC readiness of Indian financial services, measurement paper v1.0, 2026.</p>
          <a href={RESEARCH_URL} target="_blank" rel="noopener noreferrer" className="mt-8 inline-flex items-center gap-2 text-sm underline decoration-bg/40 underline-offset-4 transition-colors duration-micro hover:decoration-bg">
            Read the paper data <IconExternal size={14} />
          </a>
        </div>
      </div>
    </section>
  );
}
