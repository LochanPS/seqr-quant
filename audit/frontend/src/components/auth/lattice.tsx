"use client";

import { useRef } from "react";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";

// An engraved lattice: two skewed basis vectors repeated into a grid of points, with the
// short basis drawn in. Lattices are the mathematics under ML-KEM, so this is the one
// decorative image the auth pages carry. It draws itself, then rotates very slowly.

const N = 9;
const B1 = { x: 46, y: 12 };
const B2 = { x: 18, y: 44 };

function points() {
  const pts: { x: number; y: number; i: number; j: number }[] = [];
  for (let i = -N; i <= N; i++) {
    for (let j = -N; j <= N; j++) {
      const x = i * B1.x + j * B2.x;
      const y = i * B1.y + j * B2.y;
      if (Math.hypot(x, y) < 300) pts.push({ x, y, i, j });
    }
  }
  return pts;
}

export function Lattice() {
  const root = useRef<SVGSVGElement>(null);
  const pts = points();

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        const tl = gsap.timeline();
        tl.from(".lat-ring", { drawSVG: "0%", duration: 1.6, stagger: 0.12, ease: "instrument" })
          .from(".lat-line", { drawSVG: "0%", duration: 1.1, stagger: 0.015, ease: "instrument" }, 0.2)
          .from(".lat-pt", { scale: 0, transformOrigin: "50% 50%", duration: 0.4, stagger: { each: 0.004, from: "center" } }, 0.4)
          .from(".lat-basis", { drawSVG: "0%", duration: 0.9, stagger: 0.2, ease: "instrument" }, 1.1);
        gsap.to(".lat-spin", { rotate: 360, duration: 240, repeat: -1, ease: "none", transformOrigin: "50% 50%" });
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  return (
    <svg ref={root} viewBox="-320 -320 640 640" className="h-full w-full" role="img" aria-label="A two-dimensional lattice">
      <g className="lat-spin">
        {[120, 200, 280].map((r) => (
          <circle key={r} className="lat-ring" r={r} fill="none" stroke="rgb(var(--rule))" strokeWidth={1} />
        ))}
        {Array.from({ length: 2 * N + 1 }).map((_, k) => {
          const i = k - N;
          return (
            <g key={i}>
              <line
                className="lat-line"
                x1={i * B1.x - N * B2.x}
                y1={i * B1.y - N * B2.y}
                x2={i * B1.x + N * B2.x}
                y2={i * B1.y + N * B2.y}
                stroke="rgb(var(--rule))"
                strokeWidth={0.75}
              />
              <line
                className="lat-line"
                x1={-N * B1.x + i * B2.x}
                y1={-N * B1.y + i * B2.y}
                x2={N * B1.x + i * B2.x}
                y2={N * B1.y + i * B2.y}
                stroke="rgb(var(--rule))"
                strokeWidth={0.75}
              />
            </g>
          );
        })}
        {pts.map((p) => (
          <rect
            key={`${p.i}:${p.j}`}
            className="lat-pt"
            x={p.x - 1.75}
            y={p.y - 1.75}
            width={3.5}
            height={3.5}
            fill={p.i === 0 && p.j === 0 ? "rgb(var(--accent))" : "rgb(var(--ink-3))"}
          />
        ))}
        <line className="lat-basis" x1={0} y1={0} x2={B1.x} y2={B1.y} stroke="rgb(var(--accent))" strokeWidth={2} />
        <line className="lat-basis" x1={0} y1={0} x2={B2.x} y2={B2.y} stroke="rgb(var(--ink))" strokeWidth={2} />
      </g>
    </svg>
  );
}
