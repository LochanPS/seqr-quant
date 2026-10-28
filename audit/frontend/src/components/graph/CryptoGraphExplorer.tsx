"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Globe, Server, Network, HardDrive, KeyRound, ShieldAlert, Boxes,
  Plus, Minus, Maximize2, type LucideIcon,
} from "lucide-react";

import { loadGraphModel, type GraphModel, type GraphNode, type QuantumRollup, type Severity } from "@/lib/graph/model";
import { layoutGraph, NODE_W, NODE_H, type PositionedNode } from "@/lib/graph/layout";
import { NodeDetailPanel } from "./NodeDetailPanel";
import { GraphFilters, DEFAULT_FILTERS, type GraphFilterState } from "./GraphFilters";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/shared/States";
import { cn } from "@/lib/utils";

// ── visual mappings ─────────────────────────────────────────────────────────
const TYPE_ICON: Record<string, LucideIcon> = {
  tls_endpoint: Globe, origin: HardDrive, load_balancer: Network, host: Server, hsm: KeyRound,
};
const QUANTUM_RING: Record<QuantumRollup, string> = {
  hybrid: "border-safe/60", safe: "border-safe/60", vulnerable: "border-vulnerable/70",
  mixed: "border-urgent/70", unknown: "border-border",
};
const QUANTUM_DOT: Record<QuantumRollup, string> = {
  hybrid: "bg-safe", safe: "bg-safe", vulnerable: "bg-vulnerable", mixed: "bg-urgent", unknown: "bg-muted-foreground",
};
const SEV_TONE: Record<Severity, string> = {
  immediate: "bg-vulnerable text-white", urgent: "bg-urgent text-white", planned: "bg-planned text-white",
};
const LEGEND: { label: string; className: string }[] = [
  { label: "Hybrid / safe", className: "bg-safe" },
  { label: "Vulnerable", className: "bg-vulnerable" },
  { label: "Mixed", className: "bg-urgent" },
  { label: "Unknown", className: "bg-muted-foreground" },
];

function applyFilters(model: GraphModel, f: GraphFilterState): GraphModel {
  const nodes = model.nodes.filter((n) => {
    if (f.quantum !== "all" && n.quantumStatus !== f.quantum) return false;
    if (f.type !== "all" && n.type !== f.type) return false;
    if (f.provenance !== "all" && n.provenance !== f.provenance) return false;
    if (f.onlyViolations && n.violations.length === 0) return false;
    return true;
  });
  const keep = new Set(nodes.map((n) => n.id));
  const links = model.links.filter((l) => keep.has(l.source) && keep.has(l.target));
  return { nodes, links };
}

interface View { x: number; y: number; k: number; }
const MIN_K = 0.2, MAX_K = 2;

// Node card rendered inside an SVG <foreignObject> — reuses the Tailwind design system.
function NodeCard({ node, selected, onSelect }: { node: GraphNode; selected: boolean; onSelect: (id: string) => void }) {
  const Icon = TYPE_ICON[node.type] ?? Boxes;
  return (
    <div
      onClick={(e) => { e.stopPropagation(); onSelect(node.id); }}
      className={cn(
        "flex h-full w-full cursor-pointer items-center gap-2.5 rounded-xl border-2 bg-card px-3 py-2 shadow-sm transition-shadow hover:shadow-md",
        QUANTUM_RING[node.quantumStatus],
        selected && "ring-2 ring-quantum ring-offset-2 ring-offset-background"
      )}
    >
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-quantum/10 text-quantum">
        <Icon className="h-4.5 w-4.5" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate text-xs font-semibold" title={node.identifier}>{node.identifier}</p>
        <div className="mt-1 flex items-center gap-1.5">
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", QUANTUM_DOT[node.quantumStatus])} />
          <span className="truncate text-[0.6rem] uppercase tracking-wide text-muted-foreground">
            {node.type.replace(/_/g, " ")}
          </span>
        </div>
      </div>
      {node.worstSeverity && (
        <span className={cn("shrink-0 rounded px-1 py-0.5 text-[0.55rem] font-bold uppercase leading-none", SEV_TONE[node.worstSeverity])}>
          {node.violations.length}
        </span>
      )}
      {node.hasConflict && <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-urgent" aria-label="state conflict" />}
    </div>
  );
}

function ExplorerInner() {
  const [filters, setFilters] = useState<GraphFilterState>(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });

  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 1000, h: 500 });
  const panState = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null);

  const query = useQuery({
    queryKey: ["graph-model"],
    queryFn: () => loadGraphModel(),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const model = query.data;

  const filtered = useMemo(
    () => (model ? applyFilters(model, filters) : { nodes: [], links: [] }),
    [model, filters]
  );

  const structuralKey = useMemo(
    () => filtered.nodes.map((n) => n.id).sort().join(",") + "|" + filtered.links.map((l) => l.id).sort().join(","),
    [filtered]
  );

  const positions = useMemo(
    () => layoutGraph(filtered),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [structuralKey]
  );

  const bounds = useMemo(() => {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    positions.forEach((p: PositionedNode) => {
      minX = Math.min(minX, p.x); minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x + NODE_W); maxY = Math.max(maxY, p.y + NODE_H);
    });
    if (!isFinite(minX)) return { minX: 0, minY: 0, maxX: 0, maxY: 0, w: 0, h: 0 };
    return { minX, minY, maxX, maxY, w: maxX - minX, h: maxY - minY };
  }, [positions]);

  // Measure container without relying on ResizeObserver (read layout + window resize).
  useEffect(() => {
    const measure = () => {
      const el = containerRef.current;
      if (el) setSize({ w: el.clientWidth, h: el.clientHeight });
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  const fitToBounds = useCallback(() => {
    if (bounds.w === 0 || size.w === 0) return;
    const pad = 60;
    const k = Math.max(MIN_K, Math.min(MAX_K, Math.min((size.w - pad) / bounds.w, (size.h - pad) / bounds.h)));
    const x = (size.w - bounds.w * k) / 2 - bounds.minX * k;
    const y = (size.h - bounds.h * k) / 2 - bounds.minY * k;
    setView({ x, y, k });
  }, [bounds, size]);

  // Fit when the visible structure or container size changes.
  useEffect(() => {
    fitToBounds();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [structuralKey, size.w, size.h]);

  // ── pan / zoom ──────────────────────────────────────────────────────────
  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const cx = e.clientX - rect.left, cy = e.clientY - rect.top;
    setView((v) => {
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
      const k = Math.max(MIN_K, Math.min(MAX_K, v.k * factor));
      const gx = (cx - v.x) / v.k, gy = (cy - v.y) / v.k;
      return { k, x: cx - gx * k, y: cy - gy * k };
    });
  }, []);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest("[data-node-card]")) return; // let node clicks through
    panState.current = { px: e.clientX, py: e.clientY, ox: view.x, oy: view.y };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }, [view.x, view.y]);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!panState.current) return;
    const { px, py, ox, oy } = panState.current;
    setView((v) => ({ ...v, x: ox + (e.clientX - px), y: oy + (e.clientY - py) }));
  }, []);

  const endPan = useCallback(() => { panState.current = null; }, []);

  const zoomBy = (factor: number) =>
    setView((v) => {
      const k = Math.max(MIN_K, Math.min(MAX_K, v.k * factor));
      const cx = size.w / 2, cy = size.h / 2;
      const gx = (cx - v.x) / v.k, gy = (cy - v.y) / v.k;
      return { k, x: cx - gx * k, y: cy - gy * k };
    });

  // ── virtualization: only render nodes/edges intersecting the viewport ─────
  const nodesById = useMemo(() => new Map(filtered.nodes.map((n) => [n.id, n])), [filtered.nodes]);
  const visibleRect = useMemo(() => {
    const m = 100; // margin in graph units
    return {
      x0: (-view.x) / view.k - m, y0: (-view.y) / view.k - m,
      x1: (size.w - view.x) / view.k + m, y1: (size.h - view.y) / view.k + m,
    };
  }, [view, size]);

  const visibleNodes = useMemo(
    () => filtered.nodes.filter((n) => {
      const p = positions.get(n.id);
      if (!p) return false;
      return p.x < visibleRect.x1 && p.x + NODE_W > visibleRect.x0 && p.y < visibleRect.y1 && p.y + NODE_H > visibleRect.y0;
    }),
    [filtered.nodes, positions, visibleRect]
  );

  const edgePaths = useMemo(() => {
    const out: { id: string; d: string; label: string; mx: number; my: number }[] = [];
    for (const l of filtered.links) {
      const s = positions.get(l.source), t = positions.get(l.target);
      if (!s || !t) continue;
      // cull if both endpoints far outside viewport
      const sIn = s.x < visibleRect.x1 && s.x + NODE_W > visibleRect.x0 && s.y < visibleRect.y1 && s.y + NODE_H > visibleRect.y0;
      const tIn = t.x < visibleRect.x1 && t.x + NODE_W > visibleRect.x0 && t.y < visibleRect.y1 && t.y + NODE_H > visibleRect.y0;
      if (!sIn && !tIn) continue;
      const sx = s.x + NODE_W, sy = s.y + NODE_H / 2, tx = t.x, ty = t.y + NODE_H / 2;
      const dx = Math.max(30, Math.abs(tx - sx) / 2);
      out.push({
        id: l.id,
        d: `M${sx},${sy} C${sx + dx},${sy} ${tx - dx},${ty} ${tx},${ty}`,
        label: l.relation.replace(/_/g, " "),
        mx: (sx + tx) / 2, my: (sy + ty) / 2,
      });
    }
    return out;
  }, [filtered.links, positions, visibleRect]);

  const selectedNode: GraphNode | null = useMemo(
    () => model?.nodes.find((n) => n.id === selectedId) ?? null,
    [model, selectedId]
  );

  const facets = useMemo(() => {
    const types = new Set<string>(), provs = new Set<string>();
    model?.nodes.forEach((n) => { types.add(n.type); provs.add(n.provenance); });
    return { types: Array.from(types).sort(), provs: Array.from(provs).sort() };
  }, [model]);

  if (query.isLoading) return <Skeleton className="h-[70vh] w-full rounded-xl" />;
  if (query.isError) return <ErrorState message={(query.error as Error)?.message} onRetry={query.refetch} />;

  const tf = `translate(${view.x} ${view.y}) scale(${view.k})`;

  return (
    <div className="space-y-3">
      <GraphFilters
        filters={filters}
        types={facets.types}
        provenances={facets.provs}
        onChange={setFilters}
        counts={{ shown: filtered.nodes.length, total: model?.nodes.length ?? 0 }}
      />

      <div className="flex h-[68vh] overflow-hidden rounded-xl border bg-background">
        <div ref={containerRef} className="relative flex-1 overflow-hidden">
          {filtered.nodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              No assets match the current filters.
            </div>
          ) : (
            <svg
              className="h-full w-full touch-none select-none"
              style={{ cursor: panState.current ? "grabbing" : "grab", background: "hsl(var(--muted) / 0.15)" }}
              onWheel={onWheel}
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={endPan}
              onPointerLeave={endPan}
              onClick={(e) => { if (e.target === e.currentTarget || (e.target as Element).tagName === "svg") setSelectedId(null); }}
            >
              <defs>
                <marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M0,0 L10,5 L0,10 z" fill="hsl(var(--muted-foreground))" />
                </marker>
              </defs>
              <g transform={tf}>
                {/* edges */}
                {edgePaths.map((e) => (
                  <g key={e.id}>
                    <path d={e.d} fill="none" stroke="hsl(var(--muted-foreground) / 0.45)" strokeWidth={1.5} markerEnd="url(#graph-arrow)" />
                    {view.k > 0.6 && (
                      <text x={e.mx} y={e.my - 4} textAnchor="middle" className="fill-muted-foreground" style={{ fontSize: 9 }}>
                        {e.label}
                      </text>
                    )}
                  </g>
                ))}
                {/* nodes */}
                {visibleNodes.map((n) => {
                  const p = positions.get(n.id)!;
                  return (
                    <foreignObject key={n.id} x={p.x} y={p.y} width={NODE_W} height={NODE_H} data-node-card>
                      <NodeCard node={n} selected={n.id === selectedId} onSelect={setSelectedId} />
                    </foreignObject>
                  );
                })}
              </g>
            </svg>
          )}

          {/* zoom controls */}
          <div className="absolute bottom-3 right-3 z-10 flex flex-col gap-1">
            <button onClick={() => zoomBy(1.2)} className="flex h-8 w-8 items-center justify-center rounded-md border bg-card/80 backdrop-blur hover:bg-accent" aria-label="Zoom in"><Plus className="h-4 w-4" /></button>
            <button onClick={() => zoomBy(1 / 1.2)} className="flex h-8 w-8 items-center justify-center rounded-md border bg-card/80 backdrop-blur hover:bg-accent" aria-label="Zoom out"><Minus className="h-4 w-4" /></button>
            <button onClick={fitToBounds} className="flex h-8 w-8 items-center justify-center rounded-md border bg-card/80 backdrop-blur hover:bg-accent" aria-label="Fit view"><Maximize2 className="h-4 w-4" /></button>
          </div>

          {/* legend */}
          <div className="absolute bottom-3 left-3 z-10 flex flex-col gap-1 rounded-lg border bg-card/80 p-2 text-[0.6rem] backdrop-blur">
            {LEGEND.map((l) => (
              <span key={l.label} className="flex items-center gap-1.5 text-muted-foreground">
                <span className={`h-2 w-2 rounded-full ${l.className}`} />{l.label}
              </span>
            ))}
          </div>
        </div>

        {selectedNode && model && (
          <NodeDetailPanel node={selectedNode} model={model} onClose={() => setSelectedId(null)} onSelect={setSelectedId} />
        )}
      </div>
    </div>
  );
}

export function CryptoGraphExplorer() {
  return <ExplorerInner />;
}
