"use client";

import { ScrollSmoother, gsap } from "@/lib/gsap";

import { NAV_OFFSET } from "./constants";
export { RESEARCH_URL, NAV_OFFSET } from "./constants";

/** Scroll to a landing section, through ScrollSmoother when it is running. */
export function scrollToSection(id: string, focusSelector?: string) {
  const el = document.getElementById(id);
  if (!el) return;
  const smoother = ScrollSmoother.get();
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (smoother) {
    smoother.scrollTo(el, !reduced, `top ${NAV_OFFSET}px`);
  } else {
    const y = el.getBoundingClientRect().top + window.scrollY - NAV_OFFSET;
    window.scrollTo({ top: y, behavior: reduced ? "auto" : "smooth" });
  }
  history.replaceState(null, "", `#${id}`);
  if (focusSelector) {
    gsap.delayedCall(reduced ? 0 : 0.9, () => document.querySelector<HTMLElement>(focusSelector)?.focus({ preventScroll: true }));
  }
}
