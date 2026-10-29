"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

// A 240 degree instrument dial. Ticks draw in, then the needle sweeps to the value,
// overshoots about 3 degrees and settles. Re-sweeps from the previous value on change.

const START = -210; // degrees, measured from +x axis
const SWEEP = 240;
const R = 64;

function polar(deg: number, r: number) {
  const rad = (deg * Math.PI) / 180;
  return { x: 80 + r * Math.cos(rad), y: 80 + r * Math.sin(rad) };
}

export function Dial({
  value,
  max = 100,
  label,
  tone = "ink",
  size = 160,
}: {
  value: number;
  max?: number;
  label?: string;
  tone?: "ink" | "immediate" | "urgent" | "planned" | "safe";
  size?: number;
}) {
  const root = useRef<SVGSVGElement>(null);
  const prev = useRef(0);
  const frac = Math.max(0, Math.min(1, max ? value / max : 0));
  const angle = START + SWEEP * frac;

  useGSAP(
    () => {
      const needle = root.current?.querySelector(".dial-needle");
      if (!needle) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.from(".dial-tick", { drawSVG: "0%", duration: 0.5, stagger: 0.015, ease: "instrument" });
        gsap.fromTo(
          needle,
          { rotate: START + SWEEP * prev.current + 90, svgOrigin: "80 80" },
          { rotate: angle + 90, svgOrigin: "80 80", duration: 1.1, ease: "needle", delay: 0.15 }
        );
      });
      mm.add(MOTION_QUERIES.reduced, () => {
        gsap.set(needle, { rotate: angle + 90, svgOrigin: "80 80" });
      });
      prev.current = frac;
      return () => mm.revert();
    },
    { scope: root, dependencies: [angle], revertOnUpdate: true }
  );

  const color = tone === "ink" ? "rgb(var(--ink))" : `rgb(var(--${tone}))`;
  const ticks = Array.from({ length: 25 }, (_, i) => i);
  const arcEnd = polar(START + SWEEP * frac, R);
  const arcStart = polar(START, R);
  const large = SWEEP * frac > 180 ? 1 : 0;

  return (
    <svg
      ref={root}
      viewBox="0 0 160 136"
      width={size}
      height={(size * 136) / 160}
      role="img"
      aria-label={`${label ?? "Value"}: ${Math.round(value)} of ${max}`}
    >
      {ticks.map((i) => {
        const deg = START + (SWEEP * i) / 24;
        const major = i % 6 === 0;
        const a = polar(deg, R + 6);
        const b = polar(deg, R + (major ? 14 : 10));
        return (
          <line
            key={i}
            className="dial-tick"
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke={major ? "rgb(var(--ink))" : "rgb(var(--ink-3))"}
            strokeWidth={major ? 1.5 : 1}
          />
        );
      })}
      <path
        d={`M ${arcStart.x} ${arcStart.y} A ${R} ${R} 0 ${SWEEP > 180 ? 1 : 0} 1 ${polar(START + SWEEP, R).x} ${polar(START + SWEEP, R).y}`}
        fill="none"
        stroke="rgb(var(--rule))"
        strokeWidth={2}
      />
      {frac > 0 && (
        <path d={`M ${arcStart.x} ${arcStart.y} A ${R} ${R} 0 ${large} 1 ${arcEnd.x} ${arcEnd.y}`} fill="none" stroke={color} strokeWidth={2} />
      )}
      <g className="dial-needle" style={{ transform: `rotate(${angle + 90}deg)`, transformOrigin: "80px 80px" }}>
        <line x1={80} y1={84} x2={80} y2={80 - R + 6} stroke={color} strokeWidth={2} />
      </g>
      <rect x={76} y={76} width={8} height={8} fill="rgb(var(--ink))" />
      <text x={80} y={124} textAnchor="middle" className="fill-ink-3 font-mono" style={{ fontSize: 9, letterSpacing: "0.08em" }}>
        0 · {max}
      </text>
    </svg>
  );
}
