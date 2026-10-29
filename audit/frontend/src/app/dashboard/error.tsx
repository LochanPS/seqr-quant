"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function DashboardError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="max-w-xl border border-immediate/60 p-8">
      <p className="eyebrow text-immediate">Error</p>
      <h1 className="mt-3 font-display text-3xl text-ink">This page failed to render</h1>
      <p className="mt-3 break-words font-mono text-xs text-ink-2">{error.message || "Unknown error"}</p>
      <div className="mt-6 flex gap-2">
        <Button onClick={reset}>Try again</Button>
        <Button asChild variant="secondary">
          <Link href="/dashboard/posture">Go to overview</Link>
        </Button>
      </div>
    </div>
  );
}
