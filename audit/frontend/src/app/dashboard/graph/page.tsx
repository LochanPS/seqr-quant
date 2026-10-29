"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/ui/page";
import { Skeleton } from "@/components/ui/feedback";
import { GraphExplorer } from "@/components/graph/explorer";

function GraphInner() {
  const node = useSearchParams().get("node");
  return <GraphExplorer initialNode={node} />;
}

export default function GraphPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Topology"
        title="Crypto-asset graph"
        description="Assets, the cryptography observed on each, the policy result, and how they connect. Drag to pan, scroll to zoom, select a node for detail."
      />
      <Suspense fallback={<Skeleton className="h-[70dvh] w-full" />}>
        <GraphInner />
      </Suspense>
    </div>
  );
}
