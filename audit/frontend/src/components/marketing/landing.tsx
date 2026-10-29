"use client";

import { useRef, useState } from "react";
import { gsap, useGSAP, ScrollSmoother, ScrollTrigger, MOTION_QUERIES } from "@/lib/gsap";
import { MarketingNav } from "./nav";
import { Hero } from "./hero";
import { Finding } from "./finding";
import { EdgeOrigin } from "./edge-origin";
import { HowItWorks } from "./how";
import { LiveScan } from "./live-scan";
import { WhyNow } from "./why-now";
import { Plans, type Mode } from "./plans";
import { Research } from "./research";
import { Contact } from "./contact";
import { Footer } from "./footer";
import { scrollToSection } from "./scroll";

/**
 * The landing page. ScrollSmoother runs only here (never in the app) and only with full
 * motion; the fixed nav lives outside the smoothed content so it stays put.
 */
export function Landing() {
  const [mode, setMode] = useState<Mode>("cloud");
  const wrapper = useRef<HTMLDivElement>(null);

  useGSAP(() => {
    const mm = gsap.matchMedia();
    mm.add(`${MOTION_QUERIES.full} and (pointer: fine)`, () => {
      const smoother = ScrollSmoother.create({ wrapper: "#smooth-wrapper", content: "#smooth-content", smooth: 1.1, effects: false, smoothTouch: false });
      if (window.location.hash) {
        const id = window.location.hash.slice(1);
        requestAnimationFrame(() => scrollToSection(id));
      }
      return () => smoother.kill();
    });
    // Fonts shift line heights after load; re-measure every trigger once they are in.
    document.fonts?.ready.then(() => ScrollTrigger.refresh());
    return () => mm.revert();
  }, { scope: wrapper });

  return (
    <>
      <a href="#try-it-live" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[80] focus:bg-ink focus:px-3 focus:py-2 focus:text-bg">
        Skip to the live scan
      </a>
      <MarketingNav />
      <div id="smooth-wrapper" ref={wrapper}>
        <div id="smooth-content">
          <main>
            <Hero />
            <Finding />
            <EdgeOrigin />
            <HowItWorks />
            <LiveScan />
            <WhyNow />
            <Plans onRequest={setMode} />
            <Research />
            <Contact mode={mode} setMode={setMode} />
          </main>
          <Footer />
        </div>
      </div>
    </>
  );
}
