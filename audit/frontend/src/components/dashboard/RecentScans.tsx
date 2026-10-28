"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScanStatusBadge } from "@/components/shared/StatusBadges";
import { EmptyState } from "@/components/shared/States";
import { Button } from "@/components/ui/button";
import { formatRelative } from "@/lib/utils";
import type { Scan, Asset } from "@/lib/types";

export function RecentScans({
  scans,
  assets,
}: {
  scans: Scan[];
  assets: Asset[];
}) {
  const router = useRouter();
  const assetName = (id: string | null) =>
    assets.find((a) => a.id === id)?.identifier || "—";

  if (scans.length === 0) {
    return (
      <EmptyState
        title="No scans yet"
        description="Add your first asset and run a scan to populate this view."
        illustration="scan"
        action={
          <Button asChild>
            <Link href="/dashboard/assets">Add your first asset</Link>
          </Button>
        }
      />
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Domain</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Components</TableHead>
          <TableHead className="text-right">Vulnerable</TableHead>
          <TableHead className="text-right">When</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.slice(0, 6).map((s, i) => (
          <motion.tr
            key={s.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04 }}
            onClick={() => router.push(`/dashboard/scans/${s.id}`)}
            className="cursor-pointer border-b transition-colors hover:bg-muted/40"
          >
            <TableCell className="font-medium">{assetName(s.asset_id)}</TableCell>
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
              {formatRelative(s.created_at)}
            </TableCell>
          </motion.tr>
        ))}
      </TableBody>
    </Table>
  );
}
