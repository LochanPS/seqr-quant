"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import { Chip, StatusChip } from "@/components/ui/marks";
import { Curve } from "@/components/viz/curve";

// Three panels, scrolled sideways while the section is pinned. Each shows a real piece
// of the product, rendered with the same components the dashboard uses (display only).

const ROWS = [
  { loc: "api.examplebank.in:443 (cert)", alg: "RSA-2048", status: "vulnerable", tl: "urgent" },
  { loc: "api.examplebank.in:443 (kex)", alg: "X25519", status: "vulnerable", tl: "planned" },
  { loc: "cdn.examplebank.in:443 (kex)", alg: "X25519MLKEM768", status: "hybrid", tl: "monitor" },
  { loc: "git.examplebank.in:22 (ssh)", alg: "ssh-ed25519", status: "vulnerable", tl: "planned" },
  { loc: "smtp.examplebank.in:587 (cert)", alg: "ECDSA-P256", status: "vulnerable", tl: "urgent" },
];

function Discover() {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="border border-ink bg-bg p-5" aria-hidden>
        <p className="eyebrow">Add an asset</p>
        <div className="mt-4 grid grid-cols-4 gap-px border border-rule bg-rule text-[12px]">
          {["Web / TLS", "SSH", "Mail", "Postgres"].map((t, i) => (
            <span key={t} className={i === 0 ? "bg-ink px-2 py-2.5 text-bg" : "bg-bg px-2 py-2.5 text-ink-2"}>
              {t}
            </span>
          ))}
        </div>
        <p className="mt-4 text-[12px] text-ink-2">Host</p>
        <p className="mt-1 border border-ink px-3 py-2 font-mono text-sm text-ink">api.examplebank.in</p>
        <p className="mt-4 text-[12px] text-ink-2">Data sensitivity</p>
        <div className="mt-1 flex gap-2 text-[12px]">
          {["Internal", "Confidential", "Regulated"].map((t, i) => (
            <span key={t} className={i === 2 ? "border border-ink bg-ink px-2 py-1 text-bg" : "border border-rule px-2 py-1 text-ink-2"}>
              {t}
            </span>
          ))}
        </div>
      </div>
      <div className="border border-ink bg-bg p-5" aria-hidden>
        <p className="eyebrow">Scan in progress</p>
        <ol className="mt-4 border-l border-ink">
          {["Resolving host", "TLS handshake and certificate", "Active ML-KEM probe", "Origin discovery", "Writing inventory"].map((s, i) => (
            <li key={s} className="how-step relative py-2 pl-5 text-sm text-ink">
              <span className={`absolute -left-[5px] top-[13px] h-2 w-2 ${i < 3 ? "bg-ink" : i === 3 ? "bg-accent" : "border border-rule bg-bg"}`} />
              <span className={i > 3 ? "text-ink-3" : undefined}>{s}</span>
            </li>
          ))}
        </ol>
        <div className="mt-4 flex flex-wrap gap-2">
          <StatusChip value="vulnerable" />
          <Chip>2 origin candidates</Chip>
        </div>
      </div>
    </div>
  );
}

function Inventory() {
  return (
    <div className="border border-ink bg-bg" aria-hidden>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink px-5 py-3">
        <p className="eyebrow">Cryptographic bill of materials</p>
        <div className="flex gap-1.5">
          <Chip>CycloneDX 1.6</Chip>
          <Chip>JSON</Chip>
          <Chip>CSV</Chip>
        </div>
      </div>
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-rule">
            {["Location", "Algorithm", "Status", "Timeline"].map((h) => (
              <th key={h} className="eyebrow px-5 py-2 text-left font-normal">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ROWS.map((r) => (
            <tr key={r.loc} className="how-row border-b border-rule last:border-0">
              <td className="max-w-[220px] truncate px-5 py-2.5 font-mono text-ink-2">{r.loc}</td>
              <td className="px-5 py-2.5 font-mono text-ink">{r.alg}</td>
              <td className="px-5 py-2.5">
                <StatusChip value={r.status} />
              </td>
              <td className="px-5 py-2.5">
                <StatusChip value={r.tl} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Prioritise() {
  return (
    <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
      <div className="border border-ink bg-bg p-5" aria-hidden>
        <p className="eyebrow mb-3">Risk removed against engineer-hours</p>
        <Curve
          height={200}
          xLabel="Hours"
          yLabel="Removed"
          markX={24}
          points={[
            { x: 4, y: 22 },
            { x: 8, y: 41 },
            { x: 16, y: 63 },
            { x: 24, y: 78 },
            { x: 36, y: 88 },
            { x: 48, y: 94 },
          ]}
        />
      </div>
      <div className="border border-ink bg-bg p-5" aria-hidden>
        <p className="eyebrow">Mapped to</p>
        <ul className="mt-3 space-y-3 text-sm">
          {[
            ["PCI DSS 12.3.3", "pass"],
            ["SEBI CSCRF", "partial"],
            ["RBI Q-SAFE", "planned"],
            ["DPDP Act 2023", "monitor"],
          ].map(([k, v]) => (
            <li key={k} className="flex items-center justify-between border-b border-rule pb-2">
              <span className="text-ink">{k}</span>
              <StatusChip value={v} />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

const PANELS = [
  {
    n: "01",
    title: "Discover",
    body: "Point SeQr at a domain, mail server, SSH host or database. It actively probes TLS and certificates, finds origins hiding behind the CDN, and installs nothing.",
    figure: <Discover />,
  },
  {
    n: "02",
    title: "Inventory",
    body: "Every finding becomes a Cryptographic Bill of Materials in CycloneDX 1.6, the machine-readable inventory PCI DSS 12.3.3 and SEBI CSCRF now expect auditors to see.",
    figure: <Inventory />,
  },
  {
    n: "03",
    title: "Prioritise",
    body: "See what to fix first for the hours you have, mapped to PCI DSS, SEBI CSCRF, RBI Q-SAFE and the DST roadmap, with the post-quantum replacement for each algorithm.",
    figure: <Prioritise />,
  },
];

export function HowItWorks() {
  const root = useRef<HTMLElement>(null);
  const track = useRef<HTMLDivElement>(null);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(`${MOTION_QUERIES.full} and (min-width: 1024px)`, () => {
        const panels = gsap.utils.toArray<HTMLElement>(".how-panel");
        const distance = () => (track.current ? track.current.scrollWidth - window.innerWidth : 0);
        const scrollTween = gsap.to(track.current, {
          x: () => -distance(),
          ease: "none",
          scrollTrigger: {
            trigger: root.current,
            start: "top top",
            end: () => `+=${distance()}`,
            pin: true,
            scrub: 0.8,
            invalidateOnRefresh: true,
            anticipatePin: 1,
          },
        });
        gsap.to(".how-progress", {
          scaleX: 1,
          ease: "none",
          scrollTrigger: { trigger: root.current, start: "top top", end: () => `+=${distance()}`, scrub: true },
        });
        panels.forEach((p) => {
          gsap.from(p.querySelectorAll(".how-row, .how-step"), {
            opacity: 0,
            x: 16,
            stagger: 0.06,
            duration: 0.5,
            scrollTrigger: { trigger: p, containerAnimation: scrollTween, start: "left 70%" },
          });
        });
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  return (
    <section id="how" ref={root} className="relative overflow-hidden border-b border-ink lg:h-dvh">
      <div className="absolute inset-x-0 top-0 hidden h-px bg-rule lg:block">
        <span className="how-progress absolute inset-0 origin-left scale-x-0 bg-ink" />
      </div>
      <div className="mx-auto max-w-page px-5 pt-24 sm:px-8 lg:absolute lg:inset-x-0 lg:top-0 lg:z-10 lg:pt-20">
        <p className="eyebrow">How it works · 03</p>
      </div>
      <div ref={track} className="flex flex-col lg:h-full lg:w-max lg:flex-row">
        {PANELS.map((p) => (
          <article key={p.n} className="how-panel flex w-full flex-col justify-center gap-10 px-5 py-14 sm:px-8 lg:h-full lg:w-[100vw] lg:max-w-none lg:flex-row lg:items-center lg:gap-16 lg:px-[max(2rem,calc((100vw-1320px)/2+2rem))] lg:py-0">
            <div className="lg:w-[34%]">
              <p className="font-display text-[5rem] leading-none text-ink-3/50 tabular">{p.n}</p>
              <h3 className="mt-2 font-display text-[clamp(2.2rem,4vw,3.5rem)] leading-none text-ink">{p.title}</h3>
              <p className="mt-5 max-w-md text-[16px] leading-relaxed text-ink-2">{p.body}</p>
            </div>
            <div className="min-w-0 lg:flex-1">{p.figure}</div>
          </article>
        ))}
      </div>
    </section>
  );
}
