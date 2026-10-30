"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type DryRun, type PlanRow, type VerifyReport } from "@/lib/api";
import { errMsg, shortId } from "@/lib/utils";
import { downloadBase64 } from "@/lib/domain";
import { PageHeader, Section } from "@/components/ui/page";
import { Readout, ReadoutStrip } from "@/components/ui/numbers";
import { Button } from "@/components/ui/button";
import { Chip, Stamp, StatusChip } from "@/components/ui/marks";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { BlockSkeleton, Notice } from "@/components/ui/feedback";
import { CodeBlock } from "@/components/ui/code";
import { useToast } from "@/components/ui/toast";
import { IconArrowRight, IconDownload, IconPackage, IconPlay, IconPlus, IconVerify } from "@/components/icons";

type Bundle = { bundle_id: string; manifest: unknown; tar_base64: string };

export default function MigrationPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const [dry, setDry] = useState<DryRun | null>(null);
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [bundle, setBundle] = useState<Bundle | null>(null);

  const pipeline = useQuery({ queryKey: ["pipeline"], queryFn: api.migration.pipeline });
  const plans = useQuery({ queryKey: ["migration-plans"], queryFn: api.migration.plans });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["pipeline"] });
    qc.invalidateQueries({ queryKey: ["migration-plans"] });
  };
  const fail = (title: string) => (e: unknown) => toast({ title, description: errMsg(e), tone: "error" });

  const dryRun = useMutation({
    mutationFn: api.migration.dryRun,
    onSuccess: (r) => {
      setDry(r);
      toast({ title: `Dry-run: ${r.change_count} change${r.change_count === 1 ? "" : "s"} planned`, tone: "success" });
    },
    onError: fail("Dry-run failed"),
  });
  const createPlan = useMutation({
    mutationFn: api.migration.createPlan,
    onSuccess: () => { refresh(); toast({ title: "Change plan created", tone: "success" }); },
    onError: fail("Could not create a plan"),
  });
  const verifyPlan = useMutation({
    mutationFn: (id: string) => api.migration.verify(id),
    onSuccess: (r) => {
      setVerify(r);
      refresh();
      toast({ title: r.converged ? "Verified — converged" : "Verified — violations remain", tone: r.converged ? "success" : "error" });
    },
    onError: fail("Verification failed"),
  });
  const buildBundle = useMutation({
    mutationFn: (id: string) => api.migration.bundle(id),
    onSuccess: (b) => { setBundle(b); refresh(); toast({ title: `Bundle ${shortId(b.bundle_id)} ready`, tone: "success" }); },
    onError: fail("Could not build the bundle"),
  });

  const p = pipeline.data;
  const rows: PlanRow[] = plans.data ?? [];

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="Convergence"
        title="Migration"
        description="Converge your cryptography from where it is to where policy requires — preview the change set, build a signed bundle, and verify it closes the violations. Payment services stay up: nothing is applied until it verifies, and every change carries its own rollback."
        actions={
          <Button onClick={() => dryRun.mutate()} pending={dryRun.isPending} pendingLabel="Running dry-run">
            <IconPlay size={16} /> Dry-run
          </Button>
        }
      />

      {/* Pipeline status */}
      {pipeline.isLoading ? (
        <BlockSkeleton className="h-28" />
      ) : p ? (
        <ReadoutStrip>
          <Readout
            label="Converged"
            value={<Stamp tone={p.converged ? "safe" : "urgent"} value={p.converged ? "yes" : "no"}>{p.converged ? "Converged" : "Drift"}</Stamp>}
            foot={p.open_violations + " open violation" + (p.open_violations === 1 ? "" : "s")}
          />
          <Readout label="Open violations" value={p.open_violations} foot="policy breaches to close" />
          <Readout label="Plans" value={p.plans.total} foot={Object.entries(p.plans.by_status).map(([k, v]) => `${v} ${k}`).join(" · ") || "none yet"} />
          <Readout label="Bundles" value={p.bundles} foot="signed change sets" />
          <Readout label="Attestations" value={p.attestations} foot="posture certificates" />
        </ReadoutStrip>
      ) : null}

      {/* 01 · Dry-run — the change set */}
      <Section index="01" title="Planned changes" description="A verification-gated preview: each change shows what moves from classical to post-quantum, how it's validated, and how to roll it back.">
        {!dry ? (
          <Notice title="No dry-run yet">Run a dry-run to compute the change set from your current policy violations.</Notice>
        ) : dry.change_count === 0 ? (
          <Notice title="Nothing to migrate">No changes needed — the current state already satisfies policy.</Notice>
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap gap-2">
              <Chip tone="accent">{dry.change_count} changes</Chip>
              {Object.entries(dry.by_platform).map(([plat, n]) => (
                <Chip key={plat}>{plat}: {n}</Chip>
              ))}
              <Chip>{dry.affected_assets.length} assets</Chip>
            </div>
            <Table>
              <THead>
                <tr>
                  <Th>Asset</Th>
                  <Th>Change</Th>
                  <Th>From → To</Th>
                  <Th>Rollback</Th>
                  <Th align="right">Mode</Th>
                </tr>
              </THead>
              <TBody>
                {dry.changes.map((c, i) => (
                  <Tr key={i}>
                    <Td label="Asset">
                      <div className="font-mono text-xs">{shortId(c.asset_id)}</div>
                      <div className="text-ink-3 text-xs">{c.provider}{c.slot ? ` · ${c.slot}` : ""}</div>
                    </Td>
                    <Td label="Change" className="text-ink-2">{c.action}<div className="text-ink-3 text-xs font-mono">{c.rule_key}</div></Td>
                    <Td label="From → To" className="font-mono text-xs">
                      <span className="text-immediate">{c.from ?? "—"}</span>
                      <IconArrowRight size={12} className="mx-2 inline opacity-60" />
                      <span className="text-safe">{c.to ?? "—"}</span>
                    </Td>
                    <Td label="Rollback" className="max-w-xs text-ink-3 text-xs">{c.rollback[0] ?? "automatic revert on failure"}</Td>
                    <Td label="Mode" align="right">
                      <Chip tone={c.manual ? "urgent" : "safe"}>{c.manual ? "manual" : "automated"}</Chip>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
      </Section>

      {/* 02 · Change plans */}
      <Section
        index="02"
        title="Change plans"
        description="Freeze a dry-run into a plan, build its signed bundle, and verify it closes the violations."
        actions={
          <Button variant="secondary" onClick={() => createPlan.mutate()} pending={createPlan.isPending} pendingLabel="Creating">
            <IconPlus size={16} /> Create plan
          </Button>
        }
      >
        {plans.isLoading ? (
          <BlockSkeleton className="h-24" />
        ) : rows.length === 0 ? (
          <Notice title="No plans yet">Create a plan to turn the current change set into a signed, verifiable bundle.</Notice>
        ) : (
          <Table>
            <THead>
              <tr>
                <Th>Plan</Th>
                <Th>Status</Th>
                <Th align="right">Actions</Th>
              </tr>
            </THead>
            <TBody>
              {rows.map((row) => (
                <Tr key={row.id}>
                  <Td label="Plan" className="font-mono text-xs">{shortId(row.id)}</Td>
                  <Td label="Status"><StatusChip value={row.status} /></Td>
                  <Td label="Actions" align="right">
                    <div className="flex justify-end gap-2">
                      <Button size="sm" variant="ghost" onClick={() => buildBundle.mutate(row.id)} pending={buildBundle.isPending}>
                        <IconPackage size={14} /> Bundle
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => verifyPlan.mutate(row.id)} pending={verifyPlan.isPending}>
                        <IconVerify size={14} /> Verify
                      </Button>
                    </div>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Section>

      {/* Verify result */}
      {verify ? (
        <Section index="03" title="Verification" description="Re-evaluated policy after applying the plan.">
          <div className="flex flex-wrap items-center gap-3">
            <Stamp tone={verify.converged ? "safe" : "urgent"} value={verify.converged ? "converged" : "remaining"}>
              {verify.converged ? "Converged" : `${verify.remaining.length} remaining`}
            </Stamp>
            {verify.cleared.map((c) => <Chip key={c} tone="safe">cleared: {c}</Chip>)}
            {verify.remaining.map((c) => <Chip key={c} tone="urgent">open: {c}</Chip>)}
          </div>
        </Section>
      ) : null}

      {/* Bundle */}
      {bundle ? (
        <Section index="04" title="Signed change bundle" description={`Bundle ${shortId(bundle.bundle_id)} — a self-contained, signed set of changes with a manifest.`}
          actions={
            <Button variant="secondary" onClick={() => downloadBase64(bundle.tar_base64, `seqr-bundle-${shortId(bundle.bundle_id)}.tar.gz`)}>
              <IconDownload size={16} /> Download .tar.gz
            </Button>
          }>
          <CodeBlock code={JSON.stringify(bundle.manifest, null, 2)} filename={`bundle-${shortId(bundle.bundle_id)}-manifest.json`} maxHeight={260} />
        </Section>
      ) : null}
    </div>
  );
}
