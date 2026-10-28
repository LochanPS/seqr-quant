"use client";

import { X, ArrowRight, ArrowLeft } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import type { GraphModel, GraphNode, Severity } from "@/lib/graph/model";

const SEV_TONE: Record<Severity, string> = {
  immediate: "text-vulnerable",
  urgent: "text-urgent",
  planned: "text-planned",
};

function statusTone(q: string | null) {
  if (q === "hybrid" || q === "safe") return "text-safe";
  if (q === "vulnerable") return "text-vulnerable";
  return "text-muted-foreground";
}

interface Neighbor {
  node: GraphNode;
  relation: string;
  direction: "out" | "in";
}

function neighborsOf(node: GraphNode, model: GraphModel): Neighbor[] {
  const byId = new Map(model.nodes.map((n) => [n.id, n]));
  const out: Neighbor[] = [];
  for (const l of model.links) {
    if (l.source === node.id) {
      const n = byId.get(l.target);
      if (n) out.push({ node: n, relation: l.relation, direction: "out" });
    } else if (l.target === node.id) {
      const n = byId.get(l.source);
      if (n) out.push({ node: n, relation: l.relation, direction: "in" });
    }
  }
  return out;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</h3>
      {children}
    </div>
  );
}

export function NodeDetailPanel({
  node,
  model,
  onClose,
  onSelect,
}: {
  node: GraphNode | null;
  model: GraphModel;
  onClose: () => void;
  onSelect: (id: string) => void;
}) {
  if (!node) return null;
  const neighbors = neighborsOf(node, model);

  return (
    <aside className="flex h-full w-80 shrink-0 flex-col border-l bg-card/60 backdrop-blur">
      <div className="flex items-start justify-between gap-2 border-b p-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold" title={node.identifier}>
            {node.identifier}
          </p>
          <p className="mt-0.5 text-xs capitalize text-muted-foreground">
            {node.type.replace(/_/g, " ")} · {node.provenance.replace(/_/g, " ")}
          </p>
        </div>
        <button
          onClick={onClose}
          aria-label="Close panel"
          className="shrink-0 text-muted-foreground transition-colors hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-5 overflow-auto p-4">
        <Section title="Cryptographic state">
          {node.states.length === 0 ? (
            <p className="text-sm text-muted-foreground">No observed component state.</p>
          ) : (
            <div className="space-y-1.5">
              {node.states.map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-2 rounded-md border px-2 py-1.5">
                  <span className="font-mono text-xs">{s.slot_key}</span>
                  <span className={cn("font-mono text-xs", statusTone(s.quantum_status))}>
                    {s.algorithm ?? "?"}
                  </span>
                  {s.conflict && <span className="text-[0.6rem] text-urgent">conflict</span>}
                </div>
              ))}
            </div>
          )}
        </Section>

        <Section title={`Open violations (${node.violations.length})`}>
          {node.violations.length === 0 ? (
            <p className="text-sm text-safe">Policy satisfied.</p>
          ) : (
            <div className="space-y-1.5">
              {node.violations.map((v) => (
                <div key={v.id} className="rounded-md border p-2">
                  <span className={cn("font-mono text-[0.6rem] font-semibold uppercase", SEV_TONE[v.severity as Severity])}>
                    {v.severity}
                  </span>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {v.actual ?? "?"} → {v.target_state ?? "?"}
                  </p>
                  <p className="mt-0.5 font-mono text-[0.55rem] text-muted-foreground/60">{v.rule_key}</p>
                </div>
              ))}
            </div>
          )}
        </Section>

        <Section title={`Relationships (${neighbors.length})`}>
          {neighbors.length === 0 ? (
            <p className="text-sm text-muted-foreground">No linked assets.</p>
          ) : (
            <div className="space-y-1">
              {neighbors.map((nb, i) => (
                <button
                  key={`${nb.node.id}-${i}`}
                  onClick={() => onSelect(nb.node.id)}
                  className="flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left transition-colors hover:bg-accent"
                >
                  {nb.direction === "out" ? (
                    <ArrowRight className="h-3.5 w-3.5 shrink-0 text-quantum" />
                  ) : (
                    <ArrowLeft className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  )}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium">{nb.node.identifier}</span>
                    <span className="block text-[0.6rem] text-muted-foreground">{nb.relation.replace(/_/g, " ")}</span>
                  </span>
                </button>
              ))}
            </div>
          )}
        </Section>
      </div>

      <div className="border-t p-3">
        <Link
          href={`/dashboard/assets/${node.id}`}
          className="flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors hover:bg-accent"
        >
          Open asset details <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </aside>
  );
}
