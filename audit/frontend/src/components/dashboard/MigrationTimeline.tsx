"use client";

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { tokens } from "@/lib/design";
import type { Roadmap } from "@/lib/types";

const ORDER = ["IMMEDIATE", "URGENT", "PLANNED", "ROADMAP"] as const;
const COLORS: Record<string, string> = {
  IMMEDIATE: tokens.vulnerable,
  URGENT: tokens.urgent,
  PLANNED: tokens.planned,
  ROADMAP: tokens.quantum,
};

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-lg border bg-popover px-3 py-2 text-xs shadow-md">
      <p className="font-semibold">{p.name}</p>
      <p className="text-muted-foreground">{p.count} components</p>
      <p className="text-muted-foreground">{p.label}</p>
    </div>
  );
}

export function MigrationTimeline({ roadmap }: { roadmap: Roadmap }) {
  const data = ORDER.map((k) => ({
    name: k,
    count: roadmap[k]?.count ?? 0,
    label: roadmap[k]?.label ?? "",
  }));

  return (
    <div className="h-[260px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ left: 8, right: 16, top: 8, bottom: 8 }}
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={86}
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 12, fill: "hsl(var(--muted-foreground))" }}
          />
          <Tooltip cursor={{ fill: "hsl(var(--muted) / 0.4)" }} content={<CustomTooltip />} />
          <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={26}>
            {data.map((d) => (
              <Cell key={d.name} fill={COLORS[d.name]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
