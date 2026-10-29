// Deterministic layered layout for the crypto-asset graph via dagre.
//
// Infra topology reads best as a left-to-right flow (edge to origin to load balancer to host to
// HSM), so we default to "LR". Layout is a pure function of the model, so callers can memoize
// on a structural key and skip recompute on pan/zoom/selection.

import dagre from "dagre";
import type { GraphModel } from "./model";

export const NODE_W = 190;
export const NODE_H = 64;

export interface PositionedNode {
  id: string;
  x: number;
  y: number;
}

export type LayoutDirection = "LR" | "TB";

export function layoutGraph(
  model: GraphModel,
  direction: LayoutDirection = "LR"
): Map<string, PositionedNode> {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep: 40, ranksep: 90, marginx: 24, marginy: 24 });

  for (const n of model.nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const l of model.links) {
    // dagre ignores edges to unknown nodes; model already filtered dangling edges.
    if (g.hasNode(l.source) && g.hasNode(l.target)) g.setEdge(l.source, l.target);
  }

  dagre.layout(g);

  const pos = new Map<string, PositionedNode>();
  for (const id of g.nodes()) {
    const n = g.node(id);
    if (!n) continue;
    // dagre gives center coords; React Flow wants top-left.
    pos.set(id, { id, x: n.x - NODE_W / 2, y: n.y - NODE_H / 2 });
  }
  return pos;
}
