"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api, isStatus } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ErrorState, ReadoutSkeleton } from "@/components/ui/feedback";

/** Renders children only for platform operators; everyone else sees a clear refusal. */
export function OperatorGate({ children }: { children: React.ReactNode }) {
  const stats = useQuery({ queryKey: ["admin-stats"], queryFn: api.admin.stats, retry: false });
  if (stats.isLoading) return <ReadoutSkeleton />;
  if (stats.isError) {
    if (isStatus(stats.error, 401, 403))
      return (
        <div className="max-w-xl border border-ink p-8">
          <p className="eyebrow">Restricted</p>
          <h1 className="mt-3 font-display text-3xl text-ink">Operator access required</h1>
          <p className="mt-3 text-ink-2">The operator console is for SeQr Labs staff. Your account is not on the operator list.</p>
          <Button asChild className="mt-6" variant="secondary">
            <Link href="/dashboard/posture">Back to the dashboard</Link>
          </Button>
        </div>
      );
    return <ErrorState message={errMsg(stats.error)} onRetry={() => stats.refetch()} />;
  }
  return <>{children}</>;
}
