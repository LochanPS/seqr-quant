"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function ScanStatusBadge({ status }: { status: string }) {
  const s = status?.toLowerCase();
  const map: Record<string, { variant: any; label: string; pulse?: boolean }> = {
    queued: { variant: "muted", label: "Queued" },
    running: { variant: "quantum", label: "Running", pulse: true },
    complete: { variant: "safe", label: "Complete" },
    completed: { variant: "safe", label: "Complete" },
    failed: { variant: "vulnerable", label: "Failed" },
  };
  const cfg = map[s] || { variant: "muted", label: status || "—" };
  return (
    <Badge variant={cfg.variant} className="gap-1.5">
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full bg-current",
          cfg.pulse && "animate-pulse"
        )}
      />
      {cfg.label}
    </Badge>
  );
}

export function QuantumStatusBadge({ status }: { status: string }) {
  const map: Record<string, { variant: any; label: string }> = {
    vulnerable: { variant: "vulnerable", label: "Quantum Exposed" },
    safe: { variant: "safe", label: "Safe" },
    hybrid: { variant: "planned", label: "Hybrid" },
  };
  const cfg = map[status] || { variant: "muted", label: status || "Unknown" };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

export function TimelineBadge({ timeline }: { timeline?: string | null }) {
  if (!timeline) return <span className="text-muted-foreground">—</span>;
  const map: Record<string, any> = {
    IMMEDIATE: "vulnerable",
    URGENT: "urgent",
    PLANNED: "planned",
    ROADMAP: "quantum",
  };
  return <Badge variant={map[timeline] || "muted"}>{timeline}</Badge>;
}

export function ComplianceBadge({ status }: { status: string }) {
  const map: Record<string, any> = {
    PASS: "safe",
    FAIL: "vulnerable",
    MONITOR: "urgent",
    PARTIAL: "planned",
    PLANNED: "planned",
  };
  return <Badge variant={map[status] || "muted"}>{status}</Badge>;
}

export function HndlBadge({ exposure }: { exposure?: string | null }) {
  if (exposure === "high")
    return <Badge variant="urgent">YES</Badge>;
  return <Badge variant="muted">LOW</Badge>;
}
