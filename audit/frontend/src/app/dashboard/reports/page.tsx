"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileBarChart, FileText, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/shared/States";
import { useToast } from "@/components/ui/toast";
import { openWithAuth } from "@/lib/download";
import { formatDate } from "@/lib/utils";

const TYPES = [
  {
    type: "executive_summary",
    icon: FileText,
    title: "Executive Summary",
    pages: "2–4 pages",
    audience: "For board & leadership",
  },
  {
    type: "technical_audit",
    icon: FileBarChart,
    title: "Technical Audit",
    pages: "Full CBOM + roadmap",
    audience: "For the engineering team",
  },
];

const STATUS_VARIANT: Record<string, any> = {
  complete: "safe",
  generating: "urgent",
  failed: "vulnerable",
};

export default function ReportsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [pendingType, setPendingType] = useState<string | null>(null);

  const reports = useQuery({ queryKey: ["reports"], queryFn: api.reports.list });

  const gen = useMutation({
    mutationFn: (type: string) => api.reports.generate(type),
    onMutate: (type) => setPendingType(type),
    onSuccess: () => {
      toast({ title: "Report generated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (e) =>
      toast({
        title: "Generation failed",
        description: (e as Error).message,
        variant: "error",
      }),
    onSettled: () => setPendingType(null),
  });

  async function download(id: string) {
    try {
      await openWithAuth(api.reports.downloadUrl(id));
    } catch (e) {
      toast({
        title: "Download failed",
        description: (e as Error).message,
        variant: "error",
      });
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Reports</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Generate board-ready and engineering-grade audit reports.
        </p>
      </div>

      {/* generate cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {TYPES.map((t, i) => {
          const Icon = t.icon;
          const busy = pendingType === t.type;
          return (
            <motion.div
              key={t.type}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
            >
              <Card className="flex h-full flex-col p-6">
                <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-quantum/10 text-quantum">
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-lg font-semibold">{t.title}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t.pages}</p>
                <p className="text-sm text-muted-foreground">{t.audience}</p>
                <div className="mt-5">
                  <Button
                    onClick={() => gen.mutate(t.type)}
                    disabled={busy}
                  >
                    {busy ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" /> Building your
                        report…
                      </>
                    ) : (
                      "Generate report"
                    )}
                  </Button>
                </div>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* reports list */}
      <Card>
        <CardHeader>
          <CardTitle>Generated reports</CardTitle>
        </CardHeader>
        <CardContent>
          {reports.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : reports.isError ? (
            <ErrorState
              message={(reports.error as Error)?.message}
              onRetry={reports.refetch}
            />
          ) : !reports.data || reports.data.length === 0 ? (
            <EmptyState
              title="No reports yet"
              description="Generate your first report above."
              illustration="doc"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Generated</TableHead>
                  <TableHead className="text-right">Components</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Download</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.data.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium capitalize">
                      {r.type.replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(r.generated_at || r.created_at)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.component_count ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={STATUS_VARIANT[r.status] || "muted"}>
                        {r.status === "generating" && (
                          <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                        )}
                        {r.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={r.status !== "complete"}
                        onClick={() => download(r.id)}
                      >
                        <Download className="h-4 w-4" /> PDF
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
