"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface LiveFinding {
  id: string;
  algorithm?: string;
  location?: string;
  risk?: string;
  message?: string;
}

const RISK_VARIANT: Record<string, any> = {
  vulnerable: "vulnerable",
  high: "vulnerable",
  safe: "safe",
  hybrid: "planned",
  medium: "urgent",
};

export function IndeterminateBar({ active }: { active: boolean }) {
  return (
    <div className="relative h-2 w-full overflow-hidden rounded-full bg-secondary">
      {active ? (
        <motion.div
          className="absolute inset-y-0 w-1/3 rounded-full bg-gradient-to-r from-transparent via-quantum to-transparent"
          animate={{ x: ["-100%", "320%"] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
        />
      ) : (
        <div className="h-full w-full bg-quantum" />
      )}
    </div>
  );
}

export function ScanRadar() {
  return (
    <div className="relative mx-auto h-28 w-28">
      <div className="absolute inset-0 rounded-full border border-quantum/30" />
      <div className="absolute inset-3 rounded-full border border-quantum/20" />
      <div className="absolute inset-6 rounded-full border border-quantum/10" />
      <motion.div
        className="absolute inset-0 origin-center"
        animate={{ rotate: 360 }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0deg, rgb(215 163 82 / 0.4) 60deg, transparent 90deg)",
          borderRadius: "9999px",
        }}
      />
      <span className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-quantum" />
    </div>
  );
}

export function FindingsPanel({ findings }: { findings: LiveFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center">
        <ScanRadar />
        <p className="mt-4 text-sm text-muted-foreground">
          Listening for findings…
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <AnimatePresence initial={false}>
        {findings.map((f) => (
          <motion.div
            key={f.id}
            layout
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="flex items-center justify-between rounded-lg border bg-card/60 px-4 py-2.5"
          >
            <div className="min-w-0">
              <p className="truncate font-mono text-sm">
                {f.algorithm || f.message || "Component"}
              </p>
              {f.location && (
                <p className="truncate text-xs text-muted-foreground">
                  {f.location}
                </p>
              )}
            </div>
            {f.risk && (
              <Badge variant={RISK_VARIANT[f.risk?.toLowerCase()] || "muted"}>
                {f.risk}
              </Badge>
            )}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

export function StepText({ text, active }: { text: string; active: boolean }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      {active && (
        <span className="flex gap-1">
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              className="h-1.5 w-1.5 rounded-full bg-quantum"
              animate={{ opacity: [0.3, 1, 0.3] }}
              transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
            />
          ))}
        </span>
      )}
      <span className={cn(active && "text-foreground")}>{text}</span>
    </div>
  );
}
