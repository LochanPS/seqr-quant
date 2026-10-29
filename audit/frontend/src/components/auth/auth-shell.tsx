"use client";

import Link from "next/link";
import { motion } from "motion/react";
import { Wordmark } from "@/components/brand";
import { Lattice } from "./lattice";
import { SplitHeading } from "@/components/ui/page";

export function AuthShell({
  eyebrow,
  title,
  lede,
  children,
  footer,
}: {
  eyebrow: string;
  title: string;
  lede: string;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  return (
    <main className="grid min-h-dvh lg:grid-cols-[1.05fr_1fr]">
      <aside className="relative hidden flex-col justify-between overflow-hidden border-r border-ink bg-surface p-10 lg:flex">
        <Link href="/" aria-label="SeQr home" className="relative z-10 w-fit">
          <Wordmark className="text-[30px]" labs />
        </Link>
        <div aria-hidden className="absolute inset-0 flex items-center justify-center p-8 opacity-90">
          <div className="aspect-square w-[min(88%,620px)]">
            <Lattice />
          </div>
        </div>
        <div className="relative z-10 max-w-sm border-t border-ink pt-4">
          <p className="eyebrow">Fig. 1</p>
          <p className="mt-2 text-sm leading-relaxed text-ink-2">
            A lattice in two dimensions. ML-KEM, the key exchange that replaces RSA and ECDH, rests on the
            difficulty of finding short vectors in lattices of far higher dimension.
          </p>
        </div>
      </aside>

      <section className="flex flex-col px-5 py-8 sm:px-10 lg:px-16">
        <div className="flex items-center justify-between lg:justify-end">
          <Link href="/" aria-label="SeQr home" className="lg:hidden">
            <Wordmark className="text-[26px]" />
          </Link>
          <Link href="/" className="text-sm text-ink-2 link-underline hover:text-ink">
            Back to site
          </Link>
        </div>

        <div className="mx-auto flex w-full max-w-[420px] flex-1 flex-col justify-center py-12">
          <p className="eyebrow mb-4">{eyebrow}</p>
          <SplitHeading className="font-display text-[2.6rem] leading-[1] text-ink">{title}</SplitHeading>
          <motion.p
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25, duration: 0.5 }}
            className="mt-3 text-[15px] text-ink-2"
          >
            {lede}
          </motion.p>
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35, duration: 0.55, ease: [0.2, 0, 0, 1] }}
            className="mt-10"
          >
            {children}
          </motion.div>
          <div className="mt-10 border-t border-rule pt-5 text-sm text-ink-2">{footer}</div>
        </div>
      </section>
    </main>
  );
}
