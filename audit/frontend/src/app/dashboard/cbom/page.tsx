"use client";

import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Download } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { CBOMFilters, type Filters } from "@/components/cbom/CBOMFilters";
import { CBOMTable } from "@/components/cbom/CBOMTable";
import { EmptyState, ErrorState } from "@/components/shared/States";
import { useToast } from "@/components/ui/toast";
import { downloadWithAuth } from "@/lib/download";

const PAGE_SIZE = 50;
const EXPORTS = [
  { format: "json", label: "JSON", ext: "json" },
  { format: "csv", label: "CSV", ext: "csv" },
  { format: "cyclonedx", label: "CycloneDX", ext: "json" },
];

function CBOMInner() {
  const params = useSearchParams();
  const { toast } = useToast();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<Filters>({
    quantum_status: params.get("quantum_status") || "",
    algorithm_family: "",
    threat_timeline: "",
    migration_status: "",
    search: "",
  });

  const update = (f: Partial<Filters>) => {
    setFilters((prev) => ({ ...prev, ...f }));
    setPage(1);
  };

  const query = useQuery({
    queryKey: ["cbom", filters, page],
    queryFn: () =>
      api.cbom.list({
        quantum_status: filters.quantum_status,
        algorithm_family: filters.algorithm_family,
        threat_timeline: filters.threat_timeline,
        migration_status: filters.migration_status,
        page: String(page),
        page_size: String(PAGE_SIZE),
      }),
    placeholderData: keepPreviousData,
  });

  const items = useMemo(() => {
    const all = query.data?.items ?? [];
    if (!filters.search) return all;
    const q = filters.search.toLowerCase();
    return all.filter((c) => c.location_detail?.toLowerCase().includes(q));
  }, [query.data, filters.search]);

  const total = query.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function doExport(format: string, ext: string) {
    try {
      await downloadWithAuth(api.cbom.exportUrl(format), `cbom-${format}.${ext}`);
    } catch (e) {
      toast({
        title: "Export failed",
        description: (e as Error).message,
        variant: "error",
      });
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-tight">
            Cryptographic Bill of Materials
            <Badge variant="quantum">{total}</Badge>
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Every cryptographic component discovered across your assets.
          </p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button>
              <Download className="h-4 w-4" /> Export
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {EXPORTS.map((e) => (
              <DropdownMenuItem
                key={e.format}
                onClick={() => doExport(e.format, e.ext)}
              >
                {e.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <CBOMFilters filters={filters} onChange={update} />

      <Card>
        <CardContent className="p-0">
          {query.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : query.isError ? (
            <div className="p-4">
              <ErrorState
                message={(query.error as Error)?.message}
                onRetry={query.refetch}
              />
            </div>
          ) : items.length === 0 ? (
            <div className="p-4">
              <EmptyState
                title="No components found"
                description="No cryptographic components match the current filters."
                illustration="grid"
              />
            </div>
          ) : (
            <CBOMTable items={items} />
          )}
        </CardContent>
      </Card>

      {/* pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-4 w-4" /> Prev
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function CBOMPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <CBOMInner />
    </Suspense>
  );
}
