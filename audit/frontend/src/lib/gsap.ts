"use client";

// One place registers every GSAP plugin and the two house eases, so components import
// `gsap` from here and never re-register. All plugins ship free with GSAP 3.13+.
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SplitText } from "gsap/SplitText";
import { DrawSVGPlugin } from "gsap/DrawSVGPlugin";
import { MotionPathPlugin } from "gsap/MotionPathPlugin";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";
import { Flip } from "gsap/Flip";
import { ScrollSmoother } from "gsap/ScrollSmoother";
import { ScrollToPlugin } from "gsap/ScrollToPlugin";
import { CustomEase } from "gsap/CustomEase";
import { useGSAP } from "@gsap/react";

let registered = false;

if (typeof window !== "undefined" && !registered) {
  gsap.registerPlugin(
    useGSAP,
    ScrollTrigger,
    SplitText,
    DrawSVGPlugin,
    MotionPathPlugin,
    ScrambleTextPlugin,
    Flip,
    ScrollSmoother,
    ScrollToPlugin,
    CustomEase
  );
  // "instrument": fast out, long settle. "press": a stamp that overshoots and lands.
  CustomEase.create("instrument", "0.2,0,0,1");
  CustomEase.create("press", "M0,0 C0.24,0 0.3,1.12 0.52,1.08 0.7,1.04 0.82,1 1,1");
  CustomEase.create("needle", "M0,0 C0.18,0 0.32,1.06 0.5,1.05 0.68,1.03 0.8,1 1,1");
  gsap.defaults({ ease: "instrument", duration: 0.6 });
  registered = true;
}

export const DUR = { micro: 0.12, ui: 0.24, reveal: 0.75, choreo: 2.4 } as const;

/** Media queries every timeline is built inside, so reduced motion is honoured. */
export const MOTION_QUERIES = {
  full: "(prefers-reduced-motion: no-preference)",
  reduced: "(prefers-reduced-motion: reduce)",
} as const;

export {
  gsap,
  useGSAP,
  ScrollTrigger,
  SplitText,
  DrawSVGPlugin,
  MotionPathPlugin,
  ScrambleTextPlugin,
  Flip,
  ScrollSmoother,
  ScrollToPlugin,
  CustomEase,
};
