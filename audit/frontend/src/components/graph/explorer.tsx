"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "motion/react";
import { loadGraphModel, type GraphModel, type GraphNode, type QuantumRollup } from "@/lib/graph/model";
import { layoutGraph, NODE_H, NODE_W } from "@/lib/graph/layout";
import { cn, errMsg, humanize } from "@/lib/utils";
import { ruleLabel } from "@/lib/domain";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/feedback";
import { Chip, StatusChip, Swatch, toneFor, type Tone } from "@/components/ui/marks";
import { Tip } from "@/components/ui/overlay";
import { IconClose, IconFit, IconZoomIn, IconZoomOut, IconWarning } from "@/components/icons";

type View = { x: number; y: number; k: number };
type Filters = { quantum: QuantumRollup | "all"; type: string; source: string };
const MIN_K = 0.25;
const MAX_K = 2.2;

const Q_TONE: Record<QuantumRollup, Tone> = { vulnerable: "immediate", mixed: "urgent", hybrid: "hybrid", safe: "safe", unknown: "neutral" };
const Q_STROKE: Record<QuantumRollup, string> = {
  vulnerable: "rgb(var(--immediate))",
  mixed: "rgb(var(--urgent))",
  hybrid: "rgb(var(--hybrid))",
  safe: "rgb(var(--safe))",
  unknown: "rgb(var(--ink-3))",
};

function applyFilters(m: GraphModel, f: Filters): GraphModel {
  const nodes = m.nodes.filter(
    (n) => (f.quantum === "all" || n.quantumStatus === f.quantum) && (f.type === "all" || n.type === f.type) && (f.source === "all" || n.provenance === f.source)
  );
  const ids = new Set(nodes.map((n) => n.id));
  return { nodes, links: m.links.filter((l) => ids.has(l.source) && ids.has(l.target)) };
}

export function GraphExplorer({ initialNode }: { initialNode?: string | null }) {
  const query = useQuery({ queryKey: ["graph-model"], queryFn: () => loadGraphModel(), staleTime: 60_000 });
  const [filters, setFilters] = useState<Filters>({ quantum: "all", type: "all", source: "all" });
  const [selected, setSelected] = useState<string | null>(initialNode ?? null);
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const viewRef = useRef(view);
  viewRef.current = view;
  const box = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [size, setSize] = useState({ w: 1000, h: 600 });
  const pan = useRef<{ px: number; py: number; ox: number; oy: number; moved: boolean } | null>(null);
  const tween = useRef<gsap.core.Tween | null>(null);

  const model = query.data;
  const filtered = useMemo(() => (model ? applyFilters(model, filters) : { nodes: [], links: [] }), [model, filters]);
  const key = useMemo(() => filtered.nodes.map((n) => n.id).join(",") + "|" + filtered.links.map((l) => l.id).join(","), [filtered]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const pos = useMemo(() => layoutGraph(filtered), [key]);
  const bounds = useMemo(() => {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    pos.forEach((p) => {
      x0 = Math.min(x0, p.x);
      y0 = Math.min(y0, p.y);
      x1 = Math.max(x1, p.x + NODE_W);
      y1 = Math.max(y1, p.y + NODE_H);
    });
    return Number.isFinite(x0) ? { x0, y0, w: x1 - x0, h: y1 - y0 } : { x0: 0, y0: 0, w: 0, h: 0 };
  }, [pos]);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [query.isSuccess]);

  /** Animate the camera to a target view on the instrument ease. */
  const animateTo = useCallback((target: View, duration = 0.7) => {
    tween.current?.kill();
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setView(target);
      return;
    }
    const s = { ...viewRef.current };
    tween.current = gsap.to(s, { ...target, duration, ease: "instrument", onUpdate: () => setView({ ...s }) });
  }, []);

  const fit = useCallback(
    (animate = true) => {
      if (!bounds.w || !size.w) return;
      const pad = 80;
      const k = Math.max(MIN_K, Math.min(MAX_K, Math.min((size.w - pad) / bounds.w, (size.h - pad) / bounds.h)));
      const t = { k, x: (size.w - bounds.w * k) / 2 - bounds.x0 * k, y: (size.h - bounds.h * k) / 2 - bounds.y0 * k };
      if (animate) animateTo(t);
      else setView(t);
    },
    [bounds, size, animateTo]
  );

  useEffect(() => {
    fit(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, size.w, size.h]);

  // Selecting a node moves the camera so the node sits left of the detail panel.
  const focusNode = useCallback(
    (id: string | null) => {
      setSelected(id);
      if (!id) return;
      const p = pos.get(id);
      if (!p) return;
      const k = Math.max(viewRef.current.k, 1);
      const panelW = size.w > 900 ? 380 : 0;
      animateTo({ k, x: (size.w - panelW) / 2 - (p.x + NODE_W / 2) * k, y: size.h / 2 - (p.y + NODE_H / 2) * k });
    },
    [pos, size, animateTo]
  );

  useEffect(() => {
    if (initialNode && pos.has(initialNode)) focusNode(initialNode);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialNode, pos.size]);

  const zoomBy = (f: number) => {
    const v = viewRef.current;
    const k = Math.max(MIN_K, Math.min(MAX_K, v.k * f));
    const cx = size.w / 2, cy = size.h / 2;
    animateTo({ k, x: cx - ((cx - v.x) / v.k) * k, y: cy - ((cy - v.y) / v.k) * k }, 0.35);
  };

  // Wheel zoom needs a non-passive listener to prevent page scroll.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      tween.current?.kill();
      const r = el.getBoundingClientRect();
      const cx = e.clientX - r.left, cy = e.clientY - r.top;
      setView((v) => {
        const k = Math.max(MIN_K, Math.min(MAX_K, v.k * (e.deltaY < 0 ? 1.1 : 1 / 1.1)));
        return { k, x: cx - ((cx - v.x) / v.k) * k, y: cy - ((cy - v.y) / v.k) * k };
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [query.isSuccess, filtered.nodes.length]);

  // Arrow keys walk to the nearest node in that direction.
  const onKey = (e: React.KeyboardEvent) => {
    const dirs: Record<string, [number, number]> = { ArrowRight: [1, 0], ArrowLeft: [-1, 0], ArrowDown: [0, 1], ArrowUp: [0, -1] };
    if (e.key === "Escape") return setSelected(null);
    if (e.key === "+" || e.key === "=") return zoomBy(1.2);
    if (e.key === "-") return zoomBy(1 / 1.2);
    if (e.key === "0") return fit();
    const d = dirs[e.key];
    if (!d) return;
    e.preventDefault();
    const ids = filtered.nodes.map((n) => n.id);
    if (!selected) return focusNode(ids[0] ?? null);
    const from = pos.get(selected);
    if (!from) return;
    let best: string | null = null;
    let bestScore = Infinity;
    for (const id of ids) {
      if (id === selected) continue;
      const p = pos.get(id)!;
      const dx = p.x - from.x, dy = p.y - from.y;
      const along = dx * d[0] + dy * d[1];
      if (along <= 0) continue;
      const across = Math.abs(dx * d[1]) + Math.abs(dy * d[0]);
      const s = along + across * 2;
      if (s < bestScore) {
        bestScore = s;
        best = id;
      }
    }
    if (best) focusNode(best);
  };

  const root = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      if (!query.isSuccess) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.from(".g-edge", { drawSVG: "0%", duration: 0.9, stagger: 0.04, ease: "instrument", delay: 0.2 });
        gsap.from(".g-node", { opacity: 0, y: 8, duration: 0.5, stagger: 0.03, ease: "instrument" });
      });
      return () => mm.revert();
    },
    { scope: root, dependencies: [query.isSuccess, key], revertOnUpdate: true }
  );

  const facets = useMemo(() => {
    const t = new Set<string>(), s = new Set<string>();
    model?.nodes.forEach((n) => {
      t.add(n.type);
      s.add(n.provenance);
    });
    return { types: Array.from(t).sort(), sources: Array.from(s).sort() };
  }, [model]);

  const node = useMemo(() => model?.nodes.find((n) => n.id === selected) ?? null, [model, selected]);
  const neighbours = useMemo(() => {
    if (!model || !selected) return [];
    return model.links
      .filter((l) => l.source === selected || l.target === selected)
      .map((l) => ({ link: l, other: model.nodes.find((n) => n.id === (l.source === selected ? l.target : l.source)) }))
      .filter((x): x is { link: (typeof model.links)[number]; other: GraphNode } => !!x.other);
  }, [model, selected]);

  if (query.isLoading) return <Skeleton className="h-[70dvh] w-full" />;
  if (query.isError) return <ErrorState message={errMsg(query.error)} onRetry={() => query.refetch()} />;
  if (!model?.nodes.length)
    return <EmptyState title="The graph is empty" body="Add and scan assets, or connect a discovery agent, to populate it." action={{ label: "Add an asset", href: "/dashboard/assets?new=1" }} />;

  return (
    <div ref={root} className="space-y-4">
      <div className="flex flex-wrap items-end gap-3 border-y border-rule py-3">
        <label className="block">
          <span className="eyebrow mb-1 block">Quantum</span>
          <Select value={filters.quantum} onChange={(e) => setFilters({ ...filters, quantum: e.target.value as Filters["quantum"] })} className="h-9 w-36">
            {["all", "vulnerable", "mixed", "hybrid", "safe", "unknown"].map((q) => (
              <option key={q} value={q}>
                {q}
              </option>
            ))}
          </Select>
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">Type</span>
          <Select value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })} className="h-9 w-40">
            <option value="all">all</option>
            {facets.types.map((t) => (
              <option key={t} value={t}>
                {humanize(t)}
              </option>
            ))}
          </Select>
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">Source</span>
          <Select value={filters.source} onChange={(e) => setFilters({ ...filters, source: e.target.value })} className="h-9 w-40">
            <option value="all">all</option>
            {facets.sources.map((t) => (
              <option key={t} value={t}>
                {humanize(t)}
              </option>
            ))}
          </Select>
        </label>
        <span className="pb-2 font-mono text-xs text-ink-3 tabular">
          {filtered.nodes.length} of {model.nodes.length} nodes · {filtered.links.length} edges
        </span>
        <div className="ml-auto flex flex-wrap gap-3 pb-2">
          {(["vulnerable", "mixed", "hybrid", "safe", "unknown"] as QuantumRollup[]).map((q) => (
            <span key={q} className="inline-flex items-center gap-1.5 font-mono text-[11px] text-ink-2">
              <Swatch tone={Q_TONE[q]} /> {q}
            </span>
          ))}
        </div>
      </div>

      <div className="relative h-[68dvh] min-h-[440px] border border-ink">
        <div
          ref={box}
          tabIndex={0}
          role="application"
          aria-label="Crypto-asset graph. Arrow keys move between nodes, plus and minus zoom, zero fits, Escape clears."
          onKeyDown={onKey}
          className="absolute inset-0 overflow-hidden bg-surface focus-visible:outline-offset-[-2px]"
        >
          {filtered.nodes.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-ink-2">
              No nodes match these filters.
              <Button variant="secondary" size="sm" onClick={() => setFilters({ quantum: "all", type: "all", source: "all" })}>
                Clear filters
              </Button>
            </div>
          ) : (
            <svg
              ref={svgRef}
              className="h-full w-full touch-none select-none"
              style={{ cursor: pan.current ? "grabbing" : "grab" }}
              onPointerDown={(e) => {
                if ((e.target as Element).closest("[data-node]")) return;
                tween.current?.kill();
                pan.current = { px: e.clientX, py: e.clientY, ox: view.x, oy: view.y, moved: false };
                (e.currentTarget as Element).setPointerCapture(e.pointerId);
              }}
              onPointerMove={(e) => {
                const p = pan.current;
                if (!p) return;
                const dx = e.clientX - p.px, dy = e.clientY - p.py;
                if (Math.abs(dx) + Math.abs(dy) > 3) p.moved = true;
                setView((v) => ({ ...v, x: p.ox + dx, y: p.oy + dy }));
              }}
              onPointerUp={() => {
                if (pan.current && !pan.current.moved) setSelected(null);
                pan.current = null;
              }}
              onPointerCancel={() => (pan.current = null)}
            >
              <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
                {filtered.links.map((l) => {
                  const s = pos.get(l.source), t = pos.get(l.target);
                  if (!s || !t) return null;
                  const sx = s.x + NODE_W, sy = s.y + NODE_H / 2, tx = t.x, ty = t.y + NODE_H / 2;
                  const mid = (sx + tx) / 2;
                  const d = `M${sx},${sy} H${mid} V${ty} H${tx}`;
                  const lit = selected && (l.source === selected || l.target === selected);
                  const show = lit || hoverEdge === l.id;
                  return (
                    <g key={l.id} onPointerEnter={() => setHoverEdge(l.id)} onPointerLeave={() => setHoverEdge(null)}>
                      <path d={d} fill="none" stroke="transparent" strokeWidth={12} />
                      <path
                        className="g-edge"
                        d={d}
                        fill="none"
                        stroke={lit ? "rgb(var(--ink))" : "rgb(var(--ink-3))"}
                        strokeWidth={lit ? 1.5 : 1}
                        strokeDasharray={l.confidence < 0.8 ? "4 4" : undefined}
                        opacity={selected && !lit ? 0.35 : 1}
                      />
                      <rect x={tx - 6} y={ty - 3} width={6} height={6} fill={lit ? "rgb(var(--ink))" : "rgb(var(--ink-3))"} />
                      {show && (
                        <g>
                          <rect x={mid - 52} y={(sy + ty) / 2 - 10} width={104} height={20} fill="rgb(var(--ink))" />
                          <text x={mid} y={(sy + ty) / 2 + 4} textAnchor="middle" className="fill-bg font-mono" style={{ fontSize: 10 }}>
                            {humanize(l.relation)}
                          </text>
                        </g>
                      )}
                    </g>
                  );
                })}
                {filtered.nodes.map((n) => {
                  const p = pos.get(n.id);
                  if (!p) return null;
                  const on = selected === n.id;
                  const dim = selected && !on && !neighbours.some((x) => x.other.id === n.id);
                  return (
                    <g
                      key={n.id}
                      data-node
                      className="g-node cursor-pointer"
                      transform={`translate(${p.x} ${p.y})`}
                      opacity={dim ? 0.4 : 1}
                      onClick={(e) => {
                        e.stopPropagation();
                        focusNode(on ? null : n.id);
                      }}
                    >
                      <rect width={NODE_W} height={NODE_H} fill={on ? "rgb(var(--ink))" : "rgb(var(--bg))"} stroke={on ? "rgb(var(--ink))" : "rgb(var(--rule))"} />
                      <rect x={14} y={15} width={8} height={8} fill={Q_STROKE[n.quantumStatus]} />
                      <text x={30} y={24} className={cn("font-sans", on ? "fill-bg" : "fill-ink")} style={{ fontSize: 13 }}>
                        {(n.name || n.identifier).slice(0, 22)}
                      </text>
                      <text x={14} y={46} className={cn("font-mono", on ? "fill-bg" : "fill-ink-3")} style={{ fontSize: 10, letterSpacing: "0.06em" }}>
                        {humanize(n.type).toUpperCase().slice(0, 18)} · {n.quantumStatus.toUpperCase()}
                      </text>
                      {n.violations.length > 0 && (
                        <g transform={`translate(${NODE_W - 26} 8)`}>
                          <rect width={18} height={16} fill={n.worstSeverity ? `rgb(var(--${n.worstSeverity}))` : "rgb(var(--ink-3))"} />
                          <text x={9} y={12} textAnchor="middle" className="fill-bg font-mono" style={{ fontSize: 10 }}>
                            {n.violations.length}
                          </text>
                        </g>
                      )}
                    </g>
                  );
                })}
              </g>
            </svg>
          )}
        </div>

        <div className="absolute bottom-3 left-3 flex flex-col border border-ink bg-bg">
          <Tip label="Zoom in" side="right">
            <button onClick={() => zoomBy(1.2)} aria-label="Zoom in" className="inline-flex h-9 w-9 items-center justify-center text-ink transition-colors duration-micro hover:bg-ink hover:text-bg">
              <IconZoomIn size={16} />
            </button>
          </Tip>
          <Tip label="Zoom out" side="right">
            <button onClick={() => zoomBy(1 / 1.2)} aria-label="Zoom out" className="inline-flex h-9 w-9 items-center justify-center border-t border-rule text-ink transition-colors duration-micro hover:bg-ink hover:text-bg">
              <IconZoomOut size={16} />
            </button>
          </Tip>
          <Tip label="Fit to view" side="right">
            <button onClick={() => fit()} aria-label="Fit graph to view" className="inline-flex h-9 w-9 items-center justify-center border-t border-rule text-ink transition-colors duration-micro hover:bg-ink hover:text-bg">
              <IconFit size={16} />
            </button>
          </Tip>
        </div>
        <span className="absolute bottom-3 right-3 font-mono text-[10px] text-ink-3 tabular">{Math.round(view.k * 100)}%</span>

        <AnimatePresence>
          {node && (
            <motion.aside
              key="panel"
              initial={{ x: 24, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 24, opacity: 0 }}
              transition={{ type: "spring", stiffness: 380, damping: 36 }}
              className="absolute inset-y-0 right-0 z-10 flex w-full max-w-[380px] flex-col border-l border-ink bg-bg"
              aria-label="Node details"
            >
              <NodePanel node={node} neighbours={neighbours} onSelect={focusNode} onClose={() => setSelected(null)} />
            </motion.aside>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

function NodePanel({
  node,
  neighbours,
  onSelect,
  onClose,
}: {
  node: GraphNode;
  neighbours: { link: { id: string; relation: string; source: string }; other: GraphNode }[];
  onSelect: (id: string) => void;
  onClose: () => void;
}) {
  return (
    <>
      <div className="flex items-start justify-between gap-3 border-b border-rule p-5">
        <div className="min-w-0">
          <p className="eyebrow">{humanize(node.type)}</p>
          <p className="mt-1 truncate font-display text-xl text-ink">{node.name || node.identifier}</p>
          <p className="truncate font-mono text-[11px] text-ink-3">{node.identifier}</p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <Chip tone={Q_TONE[node.quantumStatus]}>{node.quantumStatus}</Chip>
            <Chip>{humanize(node.provenance)}</Chip>
            {node.hasConflict && <Chip tone="urgent">state conflict</Chip>}
          </div>
        </div>
        <button onClick={onClose} aria-label="Close details" className="inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink">
          <IconClose size={16} />
        </button>
      </div>
      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto p-5">
        <section>
          <h3 className="eyebrow mb-2">Component state</h3>
          {node.states.length === 0 ? (
            <p className="text-sm text-ink-3">No observed component state.</p>
          ) : (
            <ul className="border-t border-rule">
              {node.states.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-3 border-b border-rule py-2">
                  <span className="min-w-0">
                    <span className="block font-mono text-xs text-ink-3">{s.slot_key}</span>
                    <span className="block font-mono text-sm text-ink">{s.algorithm ?? "n/a"}</span>
                  </span>
                  <StatusChip value={s.quantum_status} />
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3 className="eyebrow mb-2">Policy</h3>
          {node.violations.length === 0 ? (
            <p className="text-sm text-safe">Policy satisfied.</p>
          ) : (
            <ul className="space-y-2">
              {node.violations.map((v) => (
                <li key={v.id} className="border border-rule p-3">
                  <div className="flex items-center gap-2">
                    <IconWarning size={14} className={toneFor(v.severity) === "immediate" ? "text-immediate" : "text-urgent"} />
                    <StatusChip value={v.severity} />
                  </div>
                  <p className="mt-1.5 text-sm text-ink">{ruleLabel(v.rule_key)}</p>
                  <p className="mt-1 font-mono text-[11px] text-ink-3">
                    {v.actual ?? "n/a"} to {v.target_state ?? "n/a"}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3 className="eyebrow mb-2">Linked assets</h3>
          {neighbours.length === 0 ? (
            <p className="text-sm text-ink-3">No linked assets.</p>
          ) : (
            <ul className="border-t border-rule">
              {neighbours.map(({ link, other }) => (
                <li key={link.id}>
                  <button onClick={() => onSelect(other.id)} className="flex w-full items-center justify-between gap-3 border-b border-rule py-2 text-left transition-colors duration-micro hover:bg-surface">
                    <span className="min-w-0">
                      <span className="block truncate text-sm text-ink">{other.name || other.identifier}</span>
                      <span className="block font-mono text-[11px] text-ink-3">
                        {link.source === node.id ? "to" : "from"} · {humanize(link.relation)}
                      </span>
                    </span>
                    <Swatch tone={Q_TONE[other.quantumStatus]} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <div className="border-t border-rule p-4">
        <Button asChild className="w-full justify-center">
          <Link href={`/dashboard/assets/${node.id}`}>Open asset</Link>
        </Button>
      </div>
    </>
  );
}
