"use client";

import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { CountUp } from "@/components/shared/CountUp";
import { cn } from "@/lib/utils";

export function MetricCard({
  label,
  value,
  unit,
  icon: Icon,
  accent = "quantum",
  index = 0,
  children,
}: {
  label: string;
  value?: number;
  unit?: string;
  icon?: React.ComponentType<{ className?: string }>;
  accent?: "quantum" | "safe" | "vulnerable" | "urgent" | "planned";
  index?: number;
  children?: React.ReactNode;
}) {
  const accentText = {
    quantum: "text-quantum",
    safe: "text-safe",
    vulnerable: "text-vulnerable",
    urgent: "text-urgent",
    planned: "text-planned",
  }[accent];

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1, duration: 0.4, ease: "easeOut" }}
    >
      <Card className="glass relative overflow-hidden p-5">
        <div
          className={cn(
            "absolute -right-6 -top-6 h-20 w-20 rounded-full opacity-10 blur-2xl",
            {
              quantum: "bg-quantum",
              safe: "bg-safe",
              vulnerable: "bg-vulnerable",
              urgent: "bg-urgent",
              planned: "bg-planned",
            }[accent]
          )}
        />
        <div className="flex items-start justify-between">
          <p className="text-sm font-medium text-muted-foreground">{label}</p>
          {Icon && <Icon className={cn("h-4 w-4", accentText)} />}
        </div>

        {children ?? (
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-semibold tabular-nums">
              <CountUp to={value ?? 0} duration={1.2} />
            </span>
            {unit && (
              <span className="text-sm text-muted-foreground">{unit}</span>
            )}
          </div>
        )}
      </Card>
    </motion.div>
  );
}
