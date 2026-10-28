"use client";

import { cn } from "@/lib/utils";
import type { QuantumRollup } from "@/lib/graph/model";

export interface GraphFilterState {
  quantum: QuantumRollup | "all";
  type: string | "all";
  provenance: string | "all";
  onlyViolations: boolean;
}

export const DEFAULT_FILTERS: GraphFilterState = {
  quantum: "all",
  type: "all",
  provenance: "all",
  onlyViolations: false,
};

const QUANTUM_OPTS: (QuantumRollup | "all")[] = ["all", "vulnerable", "mixed", "hybrid", "safe", "unknown"];

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border bg-card px-2 py-1 text-xs capitalize text-foreground"
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o.replace(/_/g, " ")}
          </option>
        ))}
      </select>
    </label>
  );
}

export function GraphFilters({
  filters,
  types,
  provenances,
  onChange,
  counts,
}: {
  filters: GraphFilterState;
  types: string[];
  provenances: string[];
  onChange: (next: GraphFilterState) => void;
  counts: { shown: number; total: number };
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-card/40 px-3 py-2">
      <Select
        label="Quantum"
        value={filters.quantum}
        options={QUANTUM_OPTS}
        onChange={(v) => onChange({ ...filters, quantum: v as GraphFilterState["quantum"] })}
      />
      <Select
        label="Type"
        value={filters.type}
        options={["all", ...types]}
        onChange={(v) => onChange({ ...filters, type: v })}
      />
      <Select
        label="Source"
        value={filters.provenance}
        options={["all", ...provenances]}
        onChange={(v) => onChange({ ...filters, provenance: v })}
      />
      <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <input
          type="checkbox"
          checked={filters.onlyViolations}
          onChange={(e) => onChange({ ...filters, onlyViolations: e.target.checked })}
          className="accent-quantum"
        />
        Only with violations
      </label>
      <span
        className={cn(
          "ml-auto text-xs tabular-nums",
          counts.shown < counts.total ? "text-quantum" : "text-muted-foreground"
        )}
      >
        {counts.shown} / {counts.total} nodes
      </span>
    </div>
  );
}
