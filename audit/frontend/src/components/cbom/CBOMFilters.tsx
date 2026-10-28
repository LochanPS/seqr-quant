"use client";

import { motion } from "framer-motion";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export interface Filters {
  quantum_status: string;
  algorithm_family: string;
  threat_timeline: string;
  migration_status: string;
  search: string;
}

const STATUS_PILLS = [
  { value: "", label: "All" },
  { value: "vulnerable", label: "Vulnerable" },
  { value: "safe", label: "Safe" },
  { value: "hybrid", label: "Hybrid" },
];

const FAMILIES = ["", "RSA", "ECC", "AES", "SHA", "DH", "other"];
const TIMELINES = ["", "IMMEDIATE", "URGENT", "PLANNED", "ROADMAP"];
const MIGRATIONS = ["", "not_started", "in_progress", "done", "false_positive"];

export function CBOMFilters({
  filters,
  onChange,
}: {
  filters: Filters;
  onChange: (f: Partial<Filters>) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex gap-1.5">
        {STATUS_PILLS.map((p) => (
          <motion.button
            key={p.label}
            whileTap={{ scale: 0.95 }}
            onClick={() => onChange({ quantum_status: p.value })}
            className={cn(
              "rounded-full border px-3 py-1.5 text-sm transition-colors",
              filters.quantum_status === p.value
                ? "border-quantum bg-quantum/10 text-quantum"
                : "hover:bg-accent"
            )}
          >
            {p.label}
          </motion.button>
        ))}
      </div>

      <Select
        value={filters.algorithm_family}
        onChange={(v) => onChange({ algorithm_family: v })}
        options={FAMILIES}
        placeholder="Algorithm family"
      />
      <Select
        value={filters.threat_timeline}
        onChange={(v) => onChange({ threat_timeline: v })}
        options={TIMELINES}
        placeholder="Timeline"
      />
      <Select
        value={filters.migration_status}
        onChange={(v) => onChange({ migration_status: v })}
        options={MIGRATIONS}
        placeholder="Migration"
        labelMap={(s) => s.replace(/_/g, " ")}
      />

      <div className="relative ml-auto min-w-[200px] flex-1 sm:max-w-xs">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={filters.search}
          onChange={(e) => onChange({ search: e.target.value })}
          placeholder="Filter by location…"
          className="pl-9"
        />
      </div>
    </div>
  );
}

function Select({
  value,
  onChange,
  options,
  placeholder,
  labelMap,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  placeholder: string;
  labelMap?: (s: string) => string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-10 rounded-md border border-input bg-background px-3 text-sm capitalize outline-none focus:ring-2 focus:ring-ring"
    >
      {options.map((o) => (
        <option key={o} value={o}>
          {o === "" ? placeholder : labelMap ? labelMap(o) : o}
        </option>
      ))}
    </select>
  );
}
