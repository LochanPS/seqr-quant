"use client";

import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { paper } from "@/lib/marketing-tokens";

const RESEARCH_URL = "https://github.com/LochanPS/seqr-labs-research";
const EASE = [0.22, 1, 0.36, 1] as const;
const CREAM = "#F4F1E9";
const CREAM_MUTED = "rgba(244, 241, 233, 0.68)";
const CREAM_FAINT = "rgba(244, 241, 233, 0.42)";
const DARK_LINE = "rgba(244, 241, 233, 0.12)";
const SAFE = "#10b981";
const ROSE = "#f43f5e";

function Node({
  x,
  y,
  w,
  h,
  title,
  sub,
  badge,
  tone,
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  sub: string;
  badge: string;
  tone: string;
}) {
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={w}
        height={h}
        rx={12}
        fill="rgba(20,18,16,0.9)"
        stroke={tone}
        strokeWidth={1.25}
        strokeOpacity={0.6}
      />
      <text x={x + 18} y={y + 29} fill={CREAM} fontSize={14.5} fontWeight={600} fontFamily="var(--font-display, ui-sans-serif)">
        {title}
      </text>
      <text x={x + 18} y={y + 49} fill={CREAM_FAINT} fontSize={11} fontFamily="ui-monospace, monospace">
        {sub}
      </text>
      <text x={x + 18} y={y + h - 15} fill={tone} fontSize={11} fontWeight={700} fontFamily="ui-monospace, monospace">
        {badge}
      </text>
    </g>
  );
}

// Small filled nub where a connector meets a box side.
function Nub({ cx, cy, color }: { cx: number; cy: number; color: string }) {
  return <circle cx={cx} cy={cy} r={3.5} fill={color} />;
}

function Diagram() {
  return (
    <svg viewBox="0 0 760 380" className="w-full" style={{ maxHeight: 430 }} role="img" aria-label="Client reaches a quantum-safe CDN edge, while a second route bypasses the edge to a classical exposed origin.">
      {/* ── connectors: side-to-side, never through a box ─────── */}
      {/* client right → CDN edge left */}
      <path d="M156,182 C 214,182 250,106 300,106" fill="none" stroke={SAFE} strokeWidth={2} strokeOpacity={0.7} />
      {/* CDN edge right → what scanners see left */}
      <path d="M496,106 L548,106" fill="none" stroke={SAFE} strokeWidth={2} strokeOpacity={0.7} />
      {/* client right → exposed origin left (bypass) */}
      <path d="M156,214 C 268,214 420,296 520,296" fill="none" stroke={ROSE} strokeWidth={2} strokeOpacity={0.65} strokeDasharray="7 7" />

      {/* connection nubs */}
      <Nub cx={156} cy={182} color={SAFE} />
      <Nub cx={300} cy={106} color={SAFE} />
      <Nub cx={496} cy={106} color={SAFE} />
      <Nub cx={548} cy={106} color={SAFE} />
      <Nub cx={156} cy={214} color={ROSE} />
      <Nub cx={520} cy={296} color={ROSE} />

      {/* ── nodes ────────────────────────────────────────────── */}
      <Node x={24} y={160} w={132} h={76} title="Client" sub="TLS 1.3 handshake" badge="asks for PQC" tone={CREAM_FAINT} />
      <Node x={300} y={64} w={196} h={84} title="CDN edge" sub="CloudFront · Cloudflare" badge="X25519MLKEM768 · hybrid" tone={SAFE} />
      <Node x={548} y={64} w={196} h={84} title="What scanners see" sub="edge-terminated TLS" badge="✓ quantum-safe" tone={SAFE} />
      <Node x={520} y={254} w={216} h={86} title="Exposed origin" sub="origin.examplebank.in · 13.x.x.x" badge="RSA-2048 · X25519 · classical" tone={ROSE} />
    </svg>
  );
}

export function EdgeVsOrigin() {
  const ref = useRef<HTMLDivElement>(null);
  const run = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section id="origin-bypass" className="px-6" style={{ background: paper.bg }}>
      <div ref={ref} className="mx-auto max-w-6xl pb-28">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={run ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5, ease: EASE }}
          className="font-mono text-[0.82rem] font-semibold uppercase tracking-[0.18em]"
          style={{ color: paper.accent }}
        >
          ↳ The origin bypass
        </motion.p>
        <motion.h2
          initial={{ opacity: 0, y: 16 }}
          animate={run ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.05, ease: EASE }}
          className="font-display mt-5 max-w-[22ch] font-bold tracking-tight"
          style={{ fontSize: "clamp(1.9rem, 4.6vw, 3.1rem)", color: paper.ink, lineHeight: 1.04 }}
        >
          The edge is armored. The origin is not.
        </motion.h2>
        <motion.p
          initial={{ opacity: 0 }}
          animate={run ? { opacity: 1 } : {}}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="mt-6 max-w-[62ch] text-lg leading-relaxed"
          style={{ color: paper.inkMuted }}
        >
          The hybrid post-quantum handshake happens at the CDN edge — and that is all a scanner
          sees. But the origin server behind it answers on its own address, over classical RSA and
          ECDH, and anything that routes straight to it skips the protection entirely.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 22 }}
          animate={run ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.25, ease: EASE }}
          className="mt-12 rounded-2xl p-6 md:p-9"
          style={{ background: paper.ink, border: `1px solid ${DARK_LINE}`, boxShadow: "0 24px 60px rgba(23,21,18,0.28)" }}
        >
          <Diagram />

          {/* legend */}
          <div className="mt-6 flex flex-wrap items-center gap-x-8 gap-y-3 border-t pt-5" style={{ borderColor: DARK_LINE }}>
            <span className="flex items-center gap-2 text-sm" style={{ color: CREAM_MUTED }}>
              <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: SAFE }} />
              Edge path — hybrid ML-KEM, quantum-safe
            </span>
            <span className="flex items-center gap-2 text-sm" style={{ color: CREAM_MUTED }}>
              <span className="inline-block h-2.5 w-6 rounded-full" style={{ background: `repeating-linear-gradient(90deg, ${ROSE} 0 7px, transparent 7px 12px)` }} />
              Origin bypass — classical, quantum-vulnerable
            </span>
          </div>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={run ? { opacity: 1 } : {}}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="mt-10 max-w-[62ch] text-lg leading-relaxed"
          style={{ color: paper.ink }}
        >
          <span className="font-display font-bold" style={{ color: paper.accent }}>51% of the firms we measured</span>{" "}
          expose a reachable origin outside the CDN — api., dev., sftp. and mail. subdomains on raw
          IPs. SeQr probes for them, so the inventory reflects the whole attack surface, not just the
          edge the auditor was shown.
        </motion.p>

        <motion.a
          href={RESEARCH_URL}
          target="_blank"
          rel="noopener noreferrer"
          initial={{ opacity: 0 }}
          animate={run ? { opacity: 1 } : {}}
          transition={{ duration: 0.6, delay: 0.72 }}
          className="mt-6 inline-flex items-center gap-2 font-mono text-[0.82rem] font-medium transition-opacity hover:opacity-60"
          style={{ color: paper.accent }}
        >
          Source — measurement paper §4.6, Origin exposure (n = 118, 95% CI 42–60) →
        </motion.a>
      </div>
    </section>
  );
}
