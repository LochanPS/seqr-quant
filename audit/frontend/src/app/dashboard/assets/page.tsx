"use client";

import { useQuery } from "@tanstack/react-query";
import { AnimatePresence } from "framer-motion";
import { api } from "@/lib/api";
import { AssetCard } from "@/components/assets/AssetCard";
import { AddAssetDialog } from "@/components/assets/AddAssetDialog";
import { EmptyState, ErrorState } from "@/components/shared/States";
import { Skeleton } from "@/components/ui/skeleton";

export default function AssetsPage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["assets"],
    queryFn: api.assets.list,
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Assets</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Every asset in your cryptographic inventory.
          </p>
        </div>
        <AddAssetDialog />
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-56" />
          ))}
        </div>
      ) : isError ? (
        <ErrorState message={(error as Error)?.message} onRetry={refetch} />
      ) : data && data.length > 0 ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          <AnimatePresence>
            {data.map((asset, i) => (
              <AssetCard key={asset.id} asset={asset} index={i} />
            ))}
          </AnimatePresence>
        </div>
      ) : (
        <EmptyState
          title="No assets yet"
          description="Add your first asset to build your cryptographic inventory."
          illustration="shield"
          action={<AddAssetDialog />}
        />
      )}
    </div>
  );
}
