"use client";

import { useRef, useState } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

/**
 * Step-free line chart for "y vs x" series (risk removed vs budget). Axes fade in first,
 * then the line draws with DrawSVG and the marker drops onto the chosen x.
 */
export function Curve({
  points,
  markX,
  xLabel,
  yLabel,
  yMax = 100,
  ySuffix = "%",
  height = 240,
}: {
  points: { x: number; y: number }[];
  markX?: number;
  xLabel: string;
  yLabel: string;
  yMax?: number;
  ySuffix?: string;
  height?: number;
}) {
  const root = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const W = 640;
  const H = height;
  const pad = { l: 44, r: 16, t: 14, b: 34 };
  const xs = points.map((p) => p.x);
  const xMin = Math.min(...xs, 0);
  const xMax = Math.max(...xs, 1);
  const sx = (x: number) => pad.l + ((x - xMin) / (xMax - xMin || 1)) * (W - pad.l - pad.r);
  const sy = (y: number) => H - pad.b - (y / (yMax || 1)) * (H - pad.t - pad.b);
  const sorted = [...points].sort((a, b) => a.x - b.x);
  const d = sorted.map((p, i) => `${i ? "L" : "M"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
  const mark = markX != null ? sorted.reduce((best, p) => (Math.abs(p.x - markX) < Math.abs(best.x - markX) ? p : best), sorted[0]) : null;
  const key = d + String(markX);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const tl = gsap.timeline();
        tl.from(".cv-axis", { opacity: 0, duration: 0.3 })
          .from(".cv-line", { drawSVG: "0%", duration: 1.2, ease: "instrument" }, 0.1)
          .from(".cv-pt", { scale: 0, transformOrigin: "50% 50%", stagger: 0.02, duration: 0.25 }, 0.5)
          .from(".cv-mark", { opacity: 0, y: -10, duration: 0.4, ease: "press" }, 1.0);
      });
      return () => mm.revert();
    },
    { scope: root, dependencies: [key], revertOnUpdate: true }
  );

  if (!sorted.length) return <p className="text-sm text-ink-3">No curve data.</p>;
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);
  const xTicks = Array.from(new Set(sorted.map((p) => p.x))).filter((_, i, a) => a.length <= 8 || i % Math.ceil(a.length / 8) === 0);
  const hp = hover != null ? sorted[hover] : null;

  return (
    <div className="relative">
      <svg ref={root} viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`${yLabel} against ${xLabel}`}>
        <g className="cv-axis">
          {yTicks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={W - pad.r} y1={sy(t)} y2={sy(t)} stroke="rgb(var(--rule))" strokeDasharray={t === 0 ? undefined : "2 4"} />
              <text x={pad.l - 8} y={sy(t) + 3} textAnchor="end" className="fill-ink-3 font-mono" style={{ fontSize: 10 }}>
                {Math.round(t)}
                {ySuffix}
              </text>
            </g>
          ))}
          {xTicks.map((x) => (
            <text key={x} x={sx(x)} y={H - pad.b + 16} textAnchor="middle" className="fill-ink-3 font-mono" style={{ fontSize: 10 }}>
              {x}
            </text>
          ))}
          <text x={W - pad.r} y={H - 4} textAnchor="end" className="fill-ink-3 font-mono" style={{ fontSize: 10, letterSpacing: "0.08em" }}>
            {xLabel.toUpperCase()}
          </text>
        </g>
        <path className="cv-line" d={d} fill="none" stroke="rgb(var(--ink))" strokeWidth={1.75} />
        {sorted.map((p, i) => (
          <rect key={i} className="cv-pt" x={sx(p.x) - 2.5} y={sy(p.y) - 2.5} width={5} height={5} fill="rgb(var(--ink))" />
        ))}
        {mark && (
          <g className="cv-mark">
            <line x1={sx(mark.x)} x2={sx(mark.x)} y1={pad.t} y2={H - pad.b} stroke="rgb(var(--accent))" strokeWidth={1} />
            <rect x={sx(mark.x) - 4} y={sy(mark.y) - 4} width={8} height={8} fill="rgb(var(--accent))" />
            <text x={sx(mark.x) + 8} y={pad.t + 10} className="fill-accent font-mono" style={{ fontSize: 10 }}>
              BUDGET {mark.x}
            </text>
          </g>
        )}
        {sorted.map((p, i) => {
          const left = i === 0 ? pad.l : (sx(sorted[i - 1].x) + sx(p.x)) / 2;
          const right = i === sorted.length - 1 ? W - pad.r : (sx(p.x) + sx(sorted[i + 1].x)) / 2;
          return (
            <rect
              key={`h${i}`}
              x={left}
              y={pad.t}
              width={Math.max(1, right - left)}
              height={H - pad.t - pad.b}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            />
          );
        })}
        {hp && <line x1={sx(hp.x)} x2={sx(hp.x)} y1={pad.t} y2={H - pad.b} stroke="rgb(var(--ink-3))" strokeDasharray="2 3" pointerEvents="none" />}
      </svg>
      {hp && (
        <div
          className="pointer-events-none absolute top-2 bg-ink px-2 py-1 font-mono text-[11px] text-bg"
          style={{ left: `${(sx(hp.x) / W) * 100}%`, transform: "translateX(-50%)" }}
        >
          {xLabel} {hp.x} · {yLabel} {hp.y.toFixed(1)}
          {ySuffix}
        </div>
      )}
    </div>
  );
}
