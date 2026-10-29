"use client";

import { useRouter } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type GraphAsset } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { errMsg } from "@/lib/utils";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";

/** Scan and delete with the toasts, confirms and cache updates every caller needs. */
export function useAssetActions() {
  const router = useRouter();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();

  const scan = useMutation({
    mutationFn: (id: string) => api.assets.scan(id),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/dashboard/scans/${r.scan_id}`);
    },
    onError: (e) => toast({ title: "Could not start the scan", description: errMsg(e), tone: "error" }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.assets.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["graph-assets"] });
      qc.invalidateQueries({ queryKey: ["pipeline"] });
      toast({ title: "Asset deleted", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not delete the asset", description: errMsg(e), tone: "error" }),
  });

  const confirmDelete = async (a: Pick<Asset | GraphAsset, "id" | "name" | "identifier">, after?: () => void) => {
    const ok = await confirm({
      title: "Delete this asset?",
      subject: a.name || a.identifier,
      body: "Its scan history and findings are removed from the inventory. This cannot be undone.",
      confirmLabel: "Delete asset",
    });
    if (!ok) return;
    remove.mutate(a.id, { onSuccess: () => after?.() });
  };

  return { scan, remove, confirmDelete };
}
