"use client";

import { useEffect, useState } from "react";
import { motion, useScroll, useSpring } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";
import { LogoMark } from "@/components/Logo";

const LINKS = [
  { label: "The finding", href: "#finding" },
  { label: "Live scan", href: "#try-it-live" },
  { label: "Pricing", href: "#pricing" },
];

export function MarketingNav() {
  const [scrolled, setScrolled] = useState(false);
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 30, mass: 0.3 });

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 32);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className="fixed inset-x-0 top-0 z-50 transition-all duration-300"
      style={{
        background: scrolled ? "rgba(244, 241, 233, 0.82)" : "transparent",
        backdropFilter: scrolled ? "blur(14px) saturate(1.4)" : "none",
        borderBottom: scrolled ? `1px solid ${paper.line}` : "1px solid transparent",
      }}
    >
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <a
          href="/"
          aria-label="SeQr"
          className="flex items-center gap-2.5 font-display text-[1.15rem] font-extrabold tracking-tight"
          style={{ color: paper.ink }}
        >
          <LogoMark className="h-6 w-6" />
          SeQr
        </a>

        <nav className="hidden items-center gap-8 md:flex">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="text-[0.9rem] transition-opacity hover:opacity-60"
              style={{ color: paper.inkMuted }}
            >
              {l.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-4">
          <a
            href="/login"
            className="hidden text-[0.9rem] transition-opacity hover:opacity-60 sm:block"
            style={{ color: paper.inkMuted }}
          >
            Sign in
          </a>
          <a
            href="#try-it-live"
            className="rounded-full px-4 py-2 text-[0.9rem] font-medium transition-transform hover:-translate-y-px"
            style={{ background: paper.ink, color: paper.bg }}
          >
            Run a scan
          </a>
        </div>
      </div>

      <motion.div
        className="h-px origin-left"
        style={{ scaleX: progress, background: paper.accent }}
      />
    </header>
  );
}
