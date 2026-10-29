"use client";

import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { PageHeader, RelTime, Section } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/feedback";
import { StatusChip } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { DistributionBars } from "@/components/viz/bars";
import { OperatorGate } from "@/components/admin/operator-gate";

const PLANS = ["trial", "starter", "professional", "enterprise", "onprem"];

function Console() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const stats = useQuery({ queryKey: ["admin-stats"], queryFn: api.admin.stats });
  const orgs = useQuery({ queryKey: ["admin-orgs"], queryFn: api.admin.orgs });

  const update = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { plan?: string; status?: string } }) => api.admin.updateOrg(id, data),
    onSuccess: (o) => {
      qc.invalidateQueries({ queryKey: ["admin-orgs"] });
      qc.invalidateQueries({ queryKey: ["admin-stats"] });
      toast({ title: `${o.name} updated`, description: `${o.plan} plan, ${o.status}.`, tone: "success" });
    },
    onError: (e) => toast({ title: "Update failed", description: errMsg(e), tone: "error" }),
  });

  const s = stats.data!;
  const planOptions = Array.from(new Set([...PLANS, ...(orgs.data ?? []).map((o) => o.plan)]));

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="SeQr Labs staff"
        title="Operator console"
        description="Every organisation on this deployment, with plan and status controls."
        actions={
          <>
            <Button asChild variant="secondary">
              <Link href="/admin/blog">Blog and CMS</Link>
            </Button>
            <Button asChild variant="ghost">
              <Link href="/dashboard/posture">Dashboard</Link>
            </Button>
          </>
        }
      />
      <ReadoutStrip cols={5}>
        <Readout label="Organisations" value={<CountUp value={s.total_orgs} />} />
        <Readout label="Users" value={<CountUp value={s.total_users} />} />
        <Readout label="Assets" value={<CountUp value={s.total_assets} />} />
        <Readout label="Scans" value={<CountUp value={s.total_scans} />} />
        <Readout label="Suspended" value={<CountUp value={s.suspended_orgs} />} tone={s.suspended_orgs ? "immediate" : undefined} />
      </ReadoutStrip>
      <Section index="01" title="Organisations by plan">
        <DistributionBars data={Object.entries(s.orgs_by_plan).map(([label, value]) => ({ label, value }))} className="max-w-2xl" />
      </Section>
      <Section index="02" title="Organisations">
        {orgs.isLoading ? (
          <TableSkeleton cols={8} />
        ) : orgs.isError ? (
          <ErrorState message={errMsg(orgs.error)} onRetry={() => orgs.refetch()} />
        ) : !orgs.data?.length ? (
          <EmptyState title="No organisations yet" />
        ) : (
          <Table>
            <THead>
              <tr>
                <Th>Name</Th>
                <Th>Plan</Th>
                <Th>Status</Th>
                <Th align="right">Users</Th>
                <Th align="right">Assets</Th>
                <Th align="right">Scans</Th>
                <Th>Last scan</Th>
                <Th align="right">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </THead>
            <TBody>
              {orgs.data.map((o) => (
                <Tr key={o.id}>
                  <Td label="Name">
                    <span className="block text-ink">{o.name}</span>
                    <span className="font-mono text-[11px] text-ink-3">{o.sector ?? "no sector"}</span>
                  </Td>
                  <Td label="Plan">
                    <Select
                      aria-label={`Plan for ${o.name}`}
                      value={o.plan}
                      className="h-8 w-40"
                      disabled={update.isPending}
                      onChange={(e) => update.mutate({ id: o.id, data: { plan: e.target.value } })}
                    >
                      {planOptions.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </Select>
                  </Td>
                  <Td label="Status">
                    <StatusChip value={o.status} />
                  </Td>
                  <Td label="Users" align="right" mono>
                    {o.user_count}
                  </Td>
                  <Td label="Assets" align="right" mono>
                    {o.asset_count}
                  </Td>
                  <Td label="Scans" align="right" mono>
                    {o.scan_count}
                  </Td>
                  <Td label="Last scan" className="text-ink-2">
                    <RelTime value={o.last_scan_at} />
                  </Td>
                  <Td align="right">
                    <Button
                      size="sm"
                      variant={o.status === "suspended" ? "secondary" : "danger"}
                      pending={update.isPending && update.variables?.id === o.id && !!update.variables.data.status}
                      pendingLabel="Saving"
                      onClick={async () => {
                        const suspending = o.status !== "suspended";
                        const ok = await confirm({
                          title: suspending ? "Suspend this organisation?" : "Reactivate this organisation?",
                          subject: o.name,
                          body: suspending ? "Its users are signed out and cannot sign in until it is reactivated." : "Its users can sign in again.",
                          confirmLabel: suspending ? "Suspend" : "Reactivate",
                          tone: suspending ? "danger" : "primary",
                        });
                        if (ok) update.mutate({ id: o.id, data: { status: suspending ? "suspended" : "active" } });
                      }}
                    >
                      {o.status === "suspended" ? "Reactivate" : "Suspend"}
                    </Button>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Section>
    </div>
  );
}

export default function AdminPage() {
  return (
    <OperatorGate>
      <Console />
    </OperatorGate>
  );
}
