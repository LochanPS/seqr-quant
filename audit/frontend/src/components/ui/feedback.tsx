"use client";

import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "./button";
import { IconWarning } from "@/components/icons";

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <span aria-hidden className={cn("block animate-skeleton bg-surface-2", className)} style={style} />;
}

/** Skeleton shaped like a ledger table: a head rule and n ruled rows. */
export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div role="status" aria-label="Loading" className="w-full">
      <div className="flex gap-6 border-b border-ink py-3">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} className="h-2.5" style={{ width: `${40 + ((i * 23) % 50)}px` }} />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-6 border-b border-rule py-4">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton
              key={c}
              className="h-3"
              style={{ width: c === 0 ? `${120 + ((r * 37) % 90)}px` : `${50 + ((r * 13 + c * 29) % 70)}px` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Skeleton for a row of readouts (label, big numeral, footnote). */
export function ReadoutSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div role="status" aria-label="Loading" className="grid grid-cols-2 border-y border-rule lg:grid-cols-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="space-y-3 border-rule p-5 [&:not(:first-child)]:border-l">
          <Skeleton className="h-2.5 w-20" />
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-2.5 w-32" />
        </div>
      ))}
    </div>
  );
}

export function BlockSkeleton({ lines = 4, className }: { lines?: number; className?: string }) {
  return (
    <div role="status" aria-label="Loading" className={cn("space-y-3", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className="h-3" style={{ width: `${92 - ((i * 17) % 40)}%` }} />
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  body,
  action,
  className,
}: {
  title: string;
  body?: React.ReactNode;
  action?: { label: string; href?: string; onClick?: () => void };
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-start gap-3 border border-dashed border-rule px-6 py-10", className)}>
      <p className="font-display text-lg text-ink">{title}</p>
      {body && <p className="max-w-md text-sm text-ink-2">{body}</p>}
      {action &&
        (action.href ? (
          <Button asChild variant="secondary" size="sm" className="mt-1">
            <Link href={action.href}>{action.label}</Link>
          </Button>
        ) : (
          <Button variant="secondary" size="sm" className="mt-1" onClick={action.onClick}>
            {action.label}
          </Button>
        ))}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message?: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div role="alert" className={cn("flex flex-col items-start gap-3 border border-immediate/60 px-6 py-6", className)}>
      <p className="flex items-center gap-2 text-sm font-medium text-immediate">
        <IconWarning size={16} /> Could not load this section
      </p>
      {message && <p className="max-w-xl break-words font-mono text-xs text-ink-2">{message}</p>}
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

/** Small honest notice used where a backend feature is disabled or permission is missing. */
export function Notice({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="border border-rule bg-surface px-5 py-4">
      <p className="text-sm font-medium text-ink">{title}</p>
      {children && <div className="mt-1 text-sm text-ink-2">{children}</div>}
    </div>
  );
}
