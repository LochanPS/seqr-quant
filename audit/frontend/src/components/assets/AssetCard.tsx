"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Globe, Loader2, MoreHorizontal, ScanLine, Trash2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";

// The active-scan workflow is retired in favour of the graph-native experience: an asset's
// cryptographic state is populated from graph observations, not a user-triggered scan. The
// scan mutation + API are kept intact behind this flag (no code/route/API removed) so the
// workflow can be re-enabled, but no scan-era control is exposed to customers today.
const SCAN_UI_ENABLED = true;

export function AssetCard({ asset, index = 0 }: { asset: Asset; index?: number }) {
  const router = useRouter();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [scanning, setScanning] = useState(false);

  const scanMut = useMutation({
    mutationFn: () => api.assets.scan(asset.id),
    onMutate: () => setScanning(true),
    onSuccess: (res) => {
      toast({ title: "Scan started", variant: "success" });
      qc.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/dashboard/scans/${res.scan_id}`);
    },
    onError: (e) => {
      setScanning(false);
      toast({
        title: "Scan failed to start",
        description: (e as Error).message,
        variant: "error",
      });
    },
  });

  const delMut = useMutation({
    mutationFn: () => api.assets.delete(asset.id),
    onSuccess: () => {
      toast({ title: "Asset removed", variant: "success" });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });

  const sensitivityColor =
    asset.data_sensitivity === "regulated" || asset.data_sensitivity === "secret"
      ? "vulnerable"
      : asset.data_sensitivity === "confidential"
        ? "urgent"
        : "muted";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ delay: index * 0.05, duration: 0.25 }}
      whileHover={{ y: -3 }}
    >
      <Card className="group flex h-full flex-col p-5 transition-shadow hover:shadow-xl">
        <div className="flex items-start justify-between">
          <Link
            href={`/dashboard/assets/${asset.id}`}
            className="flex items-center gap-2.5"
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-quantum/10 text-quantum">
              <Globe className="h-4.5 w-4.5" />
            </span>
            <span className="font-medium hover:text-quantum">
              {asset.identifier}
            </span>
          </Link>
          <Badge variant="muted" className="uppercase">
            {asset.type}
          </Badge>
        </div>

        <div className="mt-4 space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Sensitivity</span>
            <Badge variant={sensitivityColor as any} className="capitalize">
              {asset.data_sensitivity}
            </Badge>
          </div>
        </div>

        <div className="mt-5 flex items-center gap-2">
          {SCAN_UI_ENABLED ? (
            <Button
              size="sm"
              className="flex-1"
              disabled={scanning}
              onClick={() => scanMut.mutate()}
            >
              {scanning ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <ScanLine className="h-4 w-4" /> Scan now
                </>
              )}
            </Button>
          ) : (
            <Button asChild size="sm" variant="outline" className="flex-1">
              <Link href={`/dashboard/assets/${asset.id}`}>View details</Link>
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="icon" variant="outline">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link href={`/dashboard/assets/${asset.id}`}>View details</Link>
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-vulnerable focus:text-vulnerable"
                onClick={() => delMut.mutate()}
              >
                <Trash2 className="h-4 w-4" /> Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </Card>
    </motion.div>
  );
}
