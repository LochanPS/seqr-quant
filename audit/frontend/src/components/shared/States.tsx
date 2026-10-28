"use client";

import { motion } from "framer-motion";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function EmptyState({
  title,
  description,
  action,
  illustration = "grid",
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
  illustration?: "grid" | "scan" | "doc" | "shield";
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center rounded-xl border border-dashed py-16 text-center"
    >
      <Illustration kind={illustration} />
      <h3 className="mt-5 text-base font-semibold">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-sm text-sm text-muted-foreground">
          {description}
        </p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </motion.div>
  );
}

function Illustration({ kind }: { kind: string }) {
  return (
    <svg width="84" height="84" viewBox="0 0 84 84" fill="none" aria-hidden>
      <defs>
        <linearGradient id="emp-grad" x1="0" y1="0" x2="84" y2="84">
          <stop offset="0%" stopColor="#A65A16" />
          <stop offset="100%" stopColor="#8b5cf6" />
        </linearGradient>
      </defs>
      <rect
        x="6"
        y="6"
        width="72"
        height="72"
        rx="16"
        stroke="url(#emp-grad)"
        strokeWidth="1.5"
        strokeOpacity="0.4"
        fill="url(#emp-grad)"
        fillOpacity="0.05"
      />
      {kind === "grid" &&
        [22, 42, 62].map((x) =>
          [22, 42, 62].map((y) => (
            <circle
              key={`${x}-${y}`}
              cx={x}
              cy={y}
              r="3"
              fill="url(#emp-grad)"
              fillOpacity={(x + y) % 3 === 0 ? "0.8" : "0.25"}
            />
          ))
        )}
      {kind === "scan" && (
        <>
          <circle cx="42" cy="42" r="18" stroke="url(#emp-grad)" strokeWidth="2" />
          <line x1="42" y1="24" x2="42" y2="42" stroke="url(#emp-grad)" strokeWidth="2" />
        </>
      )}
      {kind === "doc" && (
        <>
          <rect x="28" y="22" width="28" height="40" rx="3" stroke="url(#emp-grad)" strokeWidth="2" />
          <line x1="34" y1="32" x2="50" y2="32" stroke="url(#emp-grad)" strokeWidth="2" />
          <line x1="34" y1="40" x2="50" y2="40" stroke="url(#emp-grad)" strokeWidth="2" />
          <line x1="34" y1="48" x2="44" y2="48" stroke="url(#emp-grad)" strokeWidth="2" />
        </>
      )}
      {kind === "shield" && (
        <path
          d="M42 24l14 5v11c0 9-6 15-14 18-8-3-14-9-14-18V29l14-5z"
          stroke="url(#emp-grad)"
          strokeWidth="2"
          fill="none"
        />
      )}
    </svg>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-vulnerable/30 bg-vulnerable/5 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-vulnerable/15 text-vulnerable">
        <RefreshCw className="h-5 w-5" />
      </div>
      <h3 className="mt-4 text-base font-semibold">Something went wrong</h3>
      {message && process.env.NODE_ENV === "development" && (
        <p className="mt-2 max-w-md break-all px-4 font-mono text-xs text-muted-foreground">
          {message}
        </p>
      )}
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          <RefreshCw className="h-4 w-4" /> Retry
        </Button>
      )}
    </div>
  );
}
