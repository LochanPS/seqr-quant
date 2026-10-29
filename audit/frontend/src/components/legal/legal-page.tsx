"use client";

import Link from "next/link";
import { Fragment, useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Wordmark } from "@/components/brand";
import { SplitHeading } from "@/components/ui/page";
import type { Block, LegalDoc } from "./content";

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/^\d+\.\s*/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

/** Render **bold** and [label](href) inline markup. */
function Inline({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g);
  return (
    <>
      {parts.map((p, i) => {
        const b = p.match(/^\*\*(.+)\*\*$/);
        if (b) return <strong key={i} className="font-semibold text-ink">{b[1]}</strong>;
        const a = p.match(/^\[(.+)\]\((.+)\)$/);
        if (a)
          return a[2].startsWith("/") ? (
            <Link key={i} href={a[2]} className="text-ink link-underline">
              {a[1]}
            </Link>
          ) : (
            <a key={i} href={a[2]} className="text-ink link-underline">
              {a[1]}
            </a>
          );
        return <Fragment key={i}>{p}</Fragment>;
      })}
    </>
  );
}

function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <>
      {blocks.map((b, i) =>
        "p" in b ? (
          <p key={i} className="mt-4 text-[16px] leading-[1.75] text-ink-2">
            <Inline text={b.p} />
          </p>
        ) : (
          <ul key={i} className="mt-4 space-y-2.5">
            {b.ul.map((li, j) => (
              <li key={j} className="grid grid-cols-[1.75rem_1fr] text-[16px] leading-[1.75] text-ink-2">
                <span className="pt-[0.1em] font-mono text-xs text-ink-3">{String.fromCharCode(97 + j)}.</span>
                <span>
                  <Inline text={li} />
                </span>
              </li>
            ))}
          </ul>
        )
      )}
    </>
  );
}

export function LegalPage({ doc, other }: { doc: LegalDoc; other: { label: string; href: string } }) {
  const ids = doc.sections.map((s) => slug(s.heading));
  const [active, setActive] = useState(ids[0]);

  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -65% 0px" }
    );
    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) io.observe(el);
    });
    return () => io.disconnect();
  }, [ids]);

  return (
    <div className="min-h-dvh bg-bg">
      <header className="sticky top-0 z-30 border-b border-ink bg-bg">
        <div className="mx-auto flex h-14 max-w-page items-center justify-between px-5 sm:px-8">
          <Link href="/" aria-label="SeQr home">
            <Wordmark className="text-[24px]" labs />
          </Link>
          <nav className="flex items-center gap-5 text-sm">
            <Link href={other.href} className="text-ink-2 transition-colors duration-micro hover:text-ink">
              {other.label}
            </Link>
            <Link href="/" className="text-ink-2 transition-colors duration-micro hover:text-ink">
              Home
            </Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto grid max-w-page gap-12 px-5 pb-32 pt-16 sm:px-8 lg:grid-cols-[240px_1fr] lg:gap-20">
        <aside className="lg:sticky lg:top-24 lg:self-start">
          <p className="eyebrow mb-3">Contents</p>
          <ol className="border-l border-rule">
            {doc.sections.map((s, i) => {
              const id = ids[i];
              const on = id === active;
              return (
                <li key={id}>
                  <a
                    href={`#${id}`}
                    className={cn("-ml-px block border-l py-1.5 pl-4 text-sm transition-colors duration-micro", on ? "border-ink text-ink" : "border-transparent text-ink-3 hover:text-ink")}
                  >
                    {s.heading.replace(/^\d+\.\s*/, "")}
                  </a>
                </li>
              );
            })}
          </ol>
        </aside>

        <article className="max-w-measure">
          <p className="eyebrow">SeQr Labs · Legal</p>
          <SplitHeading className="mt-4 font-display text-[clamp(2.6rem,6vw,4.5rem)] leading-[0.98] text-ink">{doc.title}</SplitHeading>
          <p className="mt-4 font-mono text-xs text-ink-3">Last updated {doc.updated}</p>
          <div className="mt-8 border-t border-ink pt-2">
            <Blocks blocks={doc.intro} />
          </div>
          {doc.sections.map((s, i) => (
            <section key={ids[i]} id={ids[i]} className="scroll-mt-24 pt-12">
              <h2 className="group flex items-baseline gap-3 font-display text-[1.6rem] leading-tight text-ink">
                <span className="font-mono text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                <span>{s.heading.replace(/^\d+\.\s*/, "")}</span>
                <a href={`#${ids[i]}`} aria-label={`Link to ${s.heading}`} className="font-mono text-sm text-ink-3 opacity-0 transition-opacity duration-micro focus:opacity-100 group-hover:opacity-100">
                  #
                </a>
              </h2>
              <Blocks blocks={s.blocks} />
            </section>
          ))}
        </article>
      </main>
    </div>
  );
}
