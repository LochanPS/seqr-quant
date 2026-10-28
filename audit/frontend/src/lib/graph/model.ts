// Crypto-asset graph — client-side model + adapter.
//
// Single source of truth is the existing /graph API. This module assembles a normalized
// { nodes, links } model from those endpoints and derives per-node display state (quantum
// status, worst violation severity, conflicts) so the renderer stays dumb.
//
// v1 has no bulk edges endpoint, so edges are fanned out per asset (one /graph/assets/{id}/edges
// call each) and deduped. The fetch surface is abstracted behind GraphSource: adding a future
// GET /graph/edges is a drop-in replacement of `edges()` — no renderer/model change.

import { api } from "@/lib/api";
import type {
  GraphAsset,
  GraphEdge,
  ComponentStateRow,
  ViolationRow,
} from "@/lib/api";

export type Severity = "immediate" | "urgent" | "planned";
const SEVERITY_RANK: Record<Severity, number> = { immediate: 3, urgent: 2, planned: 1 };

export type QuantumRollup = "hybrid" | "safe" | "vulnerable" | "mixed" | "unknown";

export interface GraphNode {
  id: string;
  identifier: string;
  name: string | null;
  type: string; // tls_endpoint | origin | load_balancer | host | hsm | ...
  provenance: string; // user_declared | discovered
  status: string;
  // derived, joined client-side by asset_id
  states: ComponentStateRow[];
  violations: ViolationRow[];
  worstSeverity: Severity | null;
  quantumStatus: QuantumRollup;
  hasConflict: boolean;
  degree: number; // edge count — used for sizing / clustering heuristics
}

export interface GraphLink {
  id: string;
  source: string; // src_asset_id
  target: string; // dst_asset_id
  relation: string;
  discoveredBy: string;
  confidence: number;
}

export interface GraphModel {
  nodes: GraphNode[];
  links: GraphLink[];
}

// Fetch surface — the seam where a bulk endpoint drops in later.
export interface GraphSource {
  assets(): Promise<GraphAsset[]>;
  componentStates(): Promise<ComponentStateRow[]>;
  violations(): Promise<ViolationRow[]>;
  edges(assetIds: string[]): Promise<GraphEdge[]>;
}

// v1 source: bulk for nodes/states/violations, fan-out for edges.
export const fanOutSource: GraphSource = {
  assets: () => api.graph.assets(),
  componentStates: () => api.graph.componentStates(),
  violations: () => api.graph.currentViolations(),
  async edges(assetIds) {
    const batches = await Promise.all(
      assetIds.map((id) => api.graph.assetEdges(id).catch(() => [] as GraphEdge[]))
    );
    // Dedupe: an edge is returned by both endpoints (src side and dst side).
    const seen = new Map<string, GraphEdge>();
    for (const batch of batches) for (const e of batch) seen.set(e.id, e);
    return Array.from(seen.values());
  },
};

// Future drop-in (kept here as the documented target; wire when /graph/edges ships):
//   export const bulkSource: GraphSource = { ...fanOutSource, edges: () => api.graph.edges() };

function rollupQuantum(states: ComponentStateRow[]): QuantumRollup {
  if (states.length === 0) return "unknown";
  const set = new Set(
    states.map((s) => {
      const q = s.quantum_status;
      if (q === "hybrid" || q === "safe") return q;
      if (q === "vulnerable") return "vulnerable";
      return "unknown";
    })
  );
  if (set.size === 1) return Array.from(set)[0] as QuantumRollup;
  return "mixed";
}

function worstSeverity(violations: ViolationRow[]): Severity | null {
  let worst: Severity | null = null;
  for (const v of violations) {
    const s = v.severity as Severity;
    if (SEVERITY_RANK[s] && (!worst || SEVERITY_RANK[s] > SEVERITY_RANK[worst])) worst = s;
  }
  return worst;
}

// Pure assembly — no I/O, unit-testable.
export function assembleGraph(
  assets: GraphAsset[],
  states: ComponentStateRow[],
  violations: ViolationRow[],
  edges: GraphEdge[]
): GraphModel {
  const statesByAsset = new Map<string, ComponentStateRow[]>();
  for (const s of states) {
    const arr = statesByAsset.get(s.asset_id) ?? [];
    arr.push(s);
    statesByAsset.set(s.asset_id, arr);
  }
  const violByAsset = new Map<string, ViolationRow[]>();
  for (const v of violations) {
    const arr = violByAsset.get(v.asset_id) ?? [];
    arr.push(v);
    violByAsset.set(v.asset_id, arr);
  }

  const assetIds = new Set(assets.map((a) => a.id));
  // Only keep edges whose endpoints are both present (guards against stale/temporal edges).
  const links: GraphLink[] = edges
    .filter((e) => assetIds.has(e.src_asset_id) && assetIds.has(e.dst_asset_id))
    .map((e) => ({
      id: e.id,
      source: e.src_asset_id,
      target: e.dst_asset_id,
      relation: e.relation,
      discoveredBy: e.discovered_by,
      confidence: e.confidence,
    }));

  const degree = new Map<string, number>();
  for (const l of links) {
    degree.set(l.source, (degree.get(l.source) ?? 0) + 1);
    degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
  }

  const nodes: GraphNode[] = assets.map((a) => {
    const st = statesByAsset.get(a.id) ?? [];
    const vi = violByAsset.get(a.id) ?? [];
    return {
      id: a.id,
      identifier: a.identifier,
      name: a.name,
      type: a.type,
      provenance: a.provenance,
      status: a.status,
      states: st,
      violations: vi,
      worstSeverity: worstSeverity(vi),
      quantumStatus: rollupQuantum(st),
      hasConflict: st.some((s) => s.conflict),
      degree: degree.get(a.id) ?? 0,
    };
  });

  return { nodes, links };
}

// Orchestrates the fetches through a GraphSource, then assembles.
export async function loadGraphModel(source: GraphSource = fanOutSource): Promise<GraphModel> {
  const [assets, states, violations] = await Promise.all([
    source.assets(),
    source.componentStates(),
    source.violations(),
  ]);
  const edges = await source.edges(assets.map((a) => a.id));
  return assembleGraph(assets, states, violations, edges);
}
