"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { api, type AdminOrg } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";

const PLANS = ["trial", "small", "mid", "large", "enterprise"];

function fmtDate(s: string | null) {
  return s ? new Date(s).toLocaleDateString() : "—";
}

export default function AdminPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const stats = useQuery({ queryKey: ["admin-stats"], queryFn: api.admin.stats });
  const orgs = useQuery({ queryKey: ["admin-orgs"], queryFn: api.admin.orgs });

  const mut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { plan?: string; status?: string } }) =>
      api.admin.updateOrg(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-orgs"] });
      qc.invalidateQueries({ queryKey: ["admin-stats"] });
      toast({ title: "Organisation updated", variant: "success" });
    },
    onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
  });

  // Operator-gating: the backend returns 403 for non-operators.
  if (orgs.isError) {
    const msg = (orgs.error as Error)?.message || "";
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <h1 className="text-xl font-semibold">Operator access required</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {msg.includes("Operator") ? "This area is for SeQr Labs staff." : msg}
        </p>
        <Link href="/dashboard" className="mt-4 inline-block text-sm underline">← Back to dashboard</Link>
      </div>
    );
  }

  const s = stats.data;
  const statCards = [
    { label: "Organisations", value: s?.total_orgs },
    { label: "Users", value: s?.total_users },
    { label: "Assets", value: s?.total_assets },
    { label: "Scans", value: s?.total_scans },
    { label: "Suspended", value: s?.suspended_orgs },
  ];

  return (
    <div className="mx-auto max-w-7xl px-6 py-10">
      <div className="mb-2 flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Operator Console</h1>
        <div className="flex gap-3 text-sm">
          <Link href="/admin/blog" className="underline">Blog / CMS →</Link>
          <Link href="/dashboard" className="text-muted-foreground underline">Dashboard</Link>
        </div>
      </div>
      <p className="mb-6 text-sm text-muted-foreground">Platform-wide view. SeQr Labs staff only.</p>

      <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-5">
        {statCards.map((c) => (
          <Card key={c.label}>
            <CardContent className="p-4">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">{c.label}</div>
              <div className="mt-1 text-2xl font-bold">{c.value ?? "—"}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle>Organisations</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Plan</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Users</TableHead>
                <TableHead className="text-right">Assets</TableHead>
                <TableHead className="text-right">Scans</TableHead>
                <TableHead>Last scan</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(orgs.data ?? []).map((o: AdminOrg) => (
                <TableRow key={o.id}>
                  <TableCell className="font-medium">{o.name}</TableCell>
                  <TableCell>
                    <select
                      value={o.plan}
                      onChange={(e) => mut.mutate({ id: o.id, data: { plan: e.target.value } })}
                      className="rounded border bg-transparent px-2 py-1 text-sm"
                    >
                      {PLANS.map((p) => <option key={p} value={p}>{p}</option>)}
                    </select>
                  </TableCell>
                  <TableCell>
                    <Badge variant={o.status === "suspended" ? "vulnerable" : "safe"}>
                      {o.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">{o.user_count}</TableCell>
                  <TableCell className="text-right">{o.asset_count}</TableCell>
                  <TableCell className="text-right">{o.scan_count}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{fmtDate(o.last_scan_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant={o.status === "suspended" ? "outline" : "destructive"}
                      disabled={mut.isPending}
                      onClick={() =>
                        mut.mutate({ id: o.id, data: { status: o.status === "suspended" ? "active" : "suspended" } })
                      }
                    >
                      {o.status === "suspended" ? "Reactivate" : "Suspend"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
