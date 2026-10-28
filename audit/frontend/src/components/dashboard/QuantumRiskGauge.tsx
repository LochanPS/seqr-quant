"use client";

import {
  RadialBar,
  RadialBarChart,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";
import { CountUp } from "@/components/shared/CountUp";
import { Badge } from "@/components/ui/badge";
import { riskColor } from "@/lib/design";
import { cn } from "@/lib/utils";

const labelVariant: Record<string, any> = {
  low: "safe",
  medium: "urgent",
  high: "vulnerable",
  critical: "vulnerable",
};

export function QuantumRiskGauge({
  score,
  label,
}: {
  score: number;
  label: string;
}) {
  const color = riskColor(score);
  const data = [{ name: "risk", value: score, fill: color }];

  return (
    <div className="relative flex flex-col items-center">
      {score > 70 && (
        <span
          className="pointer-events-none absolute left-1/2 top-[42%] h-28 w-28 -translate-x-1/2 -translate-y-1/2 rounded-full animate-pulse-ring"
          style={{ boxShadow: `0 0 0 2px ${color}55` }}
        />
      )}
      <div className="h-[150px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            innerRadius="78%"
            outerRadius="100%"
            data={data}
            startAngle={180}
            endAngle={0}
            barSize={14}
          >
            <PolarAngleAxis
              type="number"
              domain={[0, 100]}
              angleAxisId={0}
              tick={false}
            />
            <RadialBar
              background={{ fill: "hsl(var(--muted))" }}
              dataKey="value"
              cornerRadius={8}
              angleAxisId={0}
            />
          </RadialBarChart>
        </ResponsiveContainer>
      </div>
      <div className="-mt-12 flex flex-col items-center">
        <CountUp
          to={score}
          className="text-5xl font-semibold tabular-nums"
        />
        <Badge
          variant={labelVariant[label?.toLowerCase()] || "muted"}
          className={cn("mt-1 uppercase tracking-wide")}
        >
          {label || "—"}
        </Badge>
      </div>
    </div>
  );
}
