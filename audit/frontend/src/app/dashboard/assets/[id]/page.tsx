"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Globe, Loader2, ScanLine } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScanStatusBadge } from "@/components/shared/StatusBadges";
import { EmptyState, ErrorState } from "@/components/shared/States";
import { useToast } from "@/components/ui/toast";
import { formatDate, formatRelative } from "@/lib/utils";

// Scan-era workflow retired for the graph-native experience. An asset's cryptographic state
// comes from graph observations, not a user-run scan. The scan mutation, /scans API, and scan
// history UI are all kept intact behind this flag (no code/route/API removed), just not exposed.
const SCAN_UI_ENABLED = true;

export default function AssetDetailPage({
  params,
}: {
  params: { id: string };
}) {
  const { id } = params;
  const router = useRouter();
  const qc = useQueryClient();
  const { toast } = useToast();

  const asset = useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.assets.get(id),
  });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans.list });

  const scanMut = useMutation({
    mutationFn: () => api.assets.scan(id),
    onSuccess: (res) => {
      toast({ title: "Scan started", variant: "success" });
      qc.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/dashboard/scans/${res.scan_id}`);
    },
    onError: (e) =>
      toast({
        title: "Scan failed",
        description: (e as Error).message,
        variant: "error",
      }),
  });

  const assetScans =
    scans.data?.filter((s) => s.asset_id === id) ?? [];

  if (asset.isError) {
    return (
      <ErrorState
        message={(asset.error as Error)?.message}
        onRetry={asset.refetch}
      />
    );
  }

  return (
    <div className="space-y-6">
      <Link
        href="/dashboard/assets"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to assets
      </Link>

      <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-3">
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-quantum/10 text-quantum">
            <Globe className="h-6 w-6" />
          </span>
          <div>
            {asset.isLoading ? (
              <Skeleton className="h-7 w-48" />
            ) : (
              <h1 className="text-2xl font-semibold tracking-tight">
                {asset.data?.identifier}
              </h1>
            )}
            <p className="text-sm text-muted-foreground">
              {asset.data?.name || "Domain asset"}
            </p>
          </div>
        </div>
        {SCAN_UI_ENABLED && (
          <Button onClick={() => scanMut.mutate()} disabled={scanMut.isPending}>
            {scanMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <>
                <ScanLine className="h-4 w-4" /> Scan now
              </>
            )}
          </Button>
        )}
      </div>

      {/* meta */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Meta label="Type" value={asset.data?.type} loading={asset.isLoading} />
        <Meta
          label="Sensitivity"
          value={asset.data?.data_sensitivity}
          loading={asset.isLoading}
        />
        <Meta
          label="Schedule"
          value={asset.data?.scan_schedule}
          loading={asset.isLoading}
        />
        <Meta
          label="Last observed"
          value={formatRelative(asset.data?.last_scanned_at)}
          loading={asset.isLoading}
        />
      </div>

      {/* scan history — gated with the retired scan workflow (code preserved) */}
      {SCAN_UI_ENABLED && (
      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        <CardContent>
          {scans.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : assetScans.length === 0 ? (
            <EmptyState
              title="No scans for this asset"
              description="Run a scan to discover its cryptographic components."
              illustration="scan"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Components</TableHead>
                  <TableHead className="text-right">Vulnerable</TableHead>
                  <TableHead className="text-right">Started</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assetScans.map((s) => (
                  <TableRow
                    key={s.id}
                    className="cursor-pointer"
                    onClick={() => router.push(`/dashboard/scans/${s.id}`)}
                  >
                    <TableCell>
                      <ScanStatusBadge status={s.status} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {s.components_found}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-vulnerable">
                      {s.vulnerable_found}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">
                      {formatDate(s.created_at)}
                    </TableCell>
                    <TableCell className="text-right text-xs text-quantum">
                      View →
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      )}
    </div>
  );
}

function Meta({
  label,
  value,
  loading,
}: {
  label: string;
  value?: string | null;
  loading?: boolean;
}) {
  return (
    <Card className="p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      {loading ? (
        <Skeleton className="mt-2 h-5 w-20" />
      ) : (
        <p className="mt-1 font-medium capitalize">{value || "—"}</p>
      )}
    </Card>
  );
}
