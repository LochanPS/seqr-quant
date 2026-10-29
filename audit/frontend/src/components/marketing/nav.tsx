"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";
import { Wordmark } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { IconClose, IconMenu } from "@/components/icons";
import { scrollToSection } from "./scroll";

const LINKS = [
  { id: "finding", label: "The finding" },
  { id: "how", label: "How it works" },
  { id: "try-it-live", label: "Live scan" },
  { id: "why-now", label: "Why now" },
  { id: "plans", label: "Plans" },
];

export function MarketingNav() {
  const [compact, setCompact] = useState(false);
  const [active, setActive] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setCompact(window.scrollY > 24);
      // The active section is the last one whose top has passed under the nav.
      let current: string | null = null;
      for (const l of LINKS) {
        const el = document.getElementById(l.id);
        if (el && el.getBoundingClientRect().top <= 120) current = l.id;
      }
      setActive(current);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    document.documentElement.style.overflow = open ? "hidden" : "";
    return () => {
      document.documentElement.style.overflow = "";
    };
  }, [open]);

  const go = (id: string) => {
    setOpen(false);
    scrollToSection(id, id === "try-it-live" ? "#scan-domain" : undefined);
  };

  return (
    <>
      <header
        className={cn(
          "fixed inset-x-0 top-0 z-40 bg-bg transition-[height,border-color] duration-ui ease-instrument",
          compact ? "h-14 border-b border-ink" : "h-[72px] border-b border-transparent"
        )}
      >
        <div className="mx-auto flex h-full max-w-page items-center gap-8 px-5 sm:px-8">
          <Link href="/" aria-label="SeQr home" className="shrink-0">
            <Wordmark className={cn("transition-[font-size] duration-ui", compact ? "text-[24px]" : "text-[28px]")} labs />
          </Link>
          <nav aria-label="Sections" className="hidden flex-1 items-center gap-6 lg:flex">
            {LINKS.map((l) => (
              <a
                key={l.id}
                href={`#${l.id}`}
                onClick={(e) => {
                  e.preventDefault();
                  go(l.id);
                }}
                className={cn("relative py-1 text-sm transition-colors duration-micro", active === l.id ? "text-ink" : "text-ink-2 hover:text-ink")}
              >
                {l.label}
                {active === l.id && (
                  <motion.span layoutId="nav-underline" className="absolute inset-x-0 -bottom-0.5 h-px bg-ink" transition={{ type: "spring", stiffness: 500, damping: 40 }} />
                )}
              </a>
            ))}
            <Link href="/blog" className="py-1 text-sm text-ink-2 transition-colors duration-micro hover:text-ink">
              Blog
            </Link>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <Link href="/login" className="hidden px-3 text-sm text-ink-2 transition-colors duration-micro hover:text-ink sm:inline">
              Sign in
            </Link>
            <Button size="sm" onClick={() => go("try-it-live")} className="hidden sm:inline-flex">
              Scan a domain
            </Button>
            <button
              onClick={() => setOpen(true)}
              aria-label="Open menu"
              aria-expanded={open}
              className="inline-flex h-10 w-10 items-center justify-center text-ink lg:hidden"
            >
              <IconMenu size={20} />
            </button>
          </div>
        </div>
      </header>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 flex flex-col bg-bg px-6 py-5"
            role="dialog"
            aria-modal="true"
            aria-label="Menu"
          >
            <div className="flex items-center justify-between">
              <Wordmark className="text-[26px]" labs />
              <button onClick={() => setOpen(false)} aria-label="Close menu" className="inline-flex h-10 w-10 items-center justify-center text-ink">
                <IconClose size={20} />
              </button>
            </div>
            <ol className="mt-12 flex-1">
              {[...LINKS.map((l) => ({ ...l, href: `#${l.id}` })), { id: "blog", label: "Blog", href: "/blog" }, { id: "login", label: "Sign in", href: "/login" }].map((l, i) => (
                <motion.li
                  key={l.id}
                  initial={{ opacity: 0, y: 18 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.05 + i * 0.045, duration: 0.45, ease: [0.2, 0, 0, 1] }}
                  className="border-b border-rule"
                >
                  {l.href.startsWith("#") ? (
                    <a
                      href={l.href}
                      onClick={(e) => {
                        e.preventDefault();
                        go(l.id);
                      }}
                      className="flex items-baseline gap-4 py-4 font-display text-3xl text-ink"
                    >
                      <span className="font-mono text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                      {l.label}
                    </a>
                  ) : (
                    <Link href={l.href} onClick={() => setOpen(false)} className="flex items-baseline gap-4 py-4 font-display text-3xl text-ink">
                      <span className="font-mono text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                      {l.label}
                    </Link>
                  )}
                </motion.li>
              ))}
            </ol>
            <Button size="lg" className="w-full justify-center" onClick={() => go("try-it-live")}>
              Scan a domain
            </Button>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
