"use client";

import Link from "next/link";
import { Fragment, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, isStatus, type DryRun, type VerifyReport } from "@/lib/api";
import { cn, errMsg, humanize, shortId } from "@/lib/utils";
import { DEMO_TEMPLATES, SEV_ORDER, downloadBase64, frameworkLabel, plain, ruleLabel, slotOf } from "@/lib/domain";
import { downloadWithAuth } from "@/lib/download";
import { PageHeader, RelTime, Section } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { BlockSkeleton, EmptyState, ErrorState, Notice, ReadoutSkeleton, Skeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, Stamp, StatusChip, Swatch, toneFor } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { CodeBlock } from "@/components/ui/code";
import { TBody, THead, Table, Td, Th, Tr, nextSort, sortRows } from "@/components/ui/table";
import { Dial } from "@/components/viz/dial";
import { StackStrip } from "@/components/viz/bars";
import {
  IconCertificate,
  IconChevronDown,
  IconChevronRight,
  IconDownload,
  IconPackage,
  IconPlay,
  IconSignature,
  IconVerify,
  IconPlus,
} from "@/components/icons";

const KEYS = [
  "pipeline",
  "compliance",
  "violations-current",
  "component-states",
  "graph-assets",
  "attestations",
  "graph-events",
  "context-risk",
  "migration-plans",
  "org",
  "assets",
  "cbom-summary",
];

function scrollToId(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
}

export default function PosturePage() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const pipeline = useQuery({ queryKey: ["pipeline"], queryFn: api.migration.pipeline });
  const compliance = useQuery({ queryKey: ["compliance"], queryFn: api.risk.compliance });
  const violations = useQuery({ queryKey: ["violations-current"], queryFn: api.graph.currentViolations });
  const states = useQuery({ queryKey: ["component-states"], queryFn: api.graph.componentStates });
  const assets = useQuery({ queryKey: ["graph-assets"], queryFn: api.graph.assets });
  const attestations = useQuery({ queryKey: ["attestations"], queryFn: api.graph.attestations });
  const events = useQuery({ queryKey: ["graph-events"], queryFn: api.graph.events });
  const plans = useQuery({ queryKey: ["migration-plans"], queryFn: api.migration.plans });

  const [dry, setDry] = useState<DryRun | null>(null);
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [bundle, setBundle] = useState<{ bundle_id: string; manifest: unknown; tar_base64: string } | null>(null);
  const [template, setTemplate] = useState<string>("banking");
  const [reseedHidden, setReseedHidden] = useState(false);

  const invalidateAll = () => KEYS.forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
  const fail = (title: string) => (e: unknown) => toast({ title, description: errMsg(e), tone: "error" });

  const dryRun = useMutation({
    mutationFn: api.migration.dryRun,
    onSuccess: (r) => {
      setDry(r);
      toast({ title: `Dry-run found ${r.change_count} change${r.change_count === 1 ? "" : "s"}`, tone: "success" });
    },
    onError: fail("Dry-run failed"),
  });
  const createPlan = useMutation({
    mutationFn: api.migration.createPlan,
    onSuccess: (p) => {
      invalidateAll();
      toast({ title: "Plan created", description: `Plan ${shortId(p.id)} is ${humanize(p.status)}.`, tone: "success" });
    },
    onError: fail("Could not create a plan"),
  });
  const verifyLatest = useMutation({
    mutationFn: async () => {
      const list = await api.migration.plans();
      if (!list.length) throw new Error("There is no plan yet. Create one first.");
      return api.migration.verify(list[0].id);
    },
    onSuccess: (r) => {
      setVerify(r);
      invalidateAll();
      toast({ title: r.converged ? "Plan converged" : "Plan not converged yet", tone: r.converged ? "success" : "neutral" });
    },
    onError: fail("Verification failed"),
  });
  const buildBundle = useMutation({
    mutationFn: async () => {
      const list = await api.migration.plans();
      if (!list.length) throw new Error("There is no plan yet. Create one first.");
      return api.migration.bundle(list[0].id);
    },
    onSuccess: (b) => {
      setBundle(b);
      invalidateAll();
      toast({ title: "Change bundle built", description: `Bundle ${shortId(b.bundle_id)} is ready to download.`, tone: "success" });
    },
    onError: fail("Could not build the bundle"),
  });
  const attest = useMutation({
    mutationFn: api.graph.generateAttestation,
    onSuccess: () => {
      invalidateAll();
      toast({ title: "Attestation signed", tone: "success" });
    },
    onError: fail("Attestation failed"),
  });
  const reseed = useMutation({
    mutationFn: (t: string) => api.migration.reseed(t),
    onSuccess: (r) => {
      setDry(null);
      setVerify(null);
      setBundle(null);
      qc.invalidateQueries();
      toast({ title: `Loaded the ${r.template} dataset`, tone: "success" });
    },
    onError: (e) => {
      if (isStatus(e, 403, 404)) {
        setReseedHidden(true);
        toast({ title: "Demo datasets are turned off on this deployment", tone: "neutral" });
      } else fail("Could not load the dataset")(e);
    },
  });

  const p = pipeline.data;
  const risk = useMemo(() => {
    const c = { immediate: 0, urgent: 0, planned: 0 };
    (violations.data ?? []).forEach((v) => {
      if (v.severity in c) c[v.severity as keyof typeof c]++;
    });
    const score = Math.min(100, c.immediate * 18 + c.urgent * 9 + c.planned * 3);
    const level = c.immediate ? "High" : c.urgent ? "Elevated" : c.planned ? "Moderate" : "Low";
    const tone = c.immediate ? "immediate" : c.urgent ? "urgent" : c.planned ? "planned" : "safe";
    return { ...c, score, level, tone: tone as "immediate" | "urgent" | "planned" | "safe", total: (violations.data ?? []).length };
  }, [violations.data]);

  const comp = useMemo(() => {
    const entries = Object.entries(compliance.data ?? {});
    const by = (s: string) => entries.filter(([, v]) => v.status === s).length;
    return { entries, pass: by("PASS"), fail: by("FAIL"), partial: by("PARTIAL"), monitor: by("MONITOR"), planned: by("PLANNED") };
  }, [compliance.data]);

  const coverage = useMemo(() => {
    const total = states.data?.length ?? 0;
    const violating = new Set((violations.data ?? []).map((v) => `${v.asset_id}:${slotOf(v.rule_key)}`)).size;
    const pct = total ? Math.round(((total - Math.min(violating, total)) / total) * 100) : 0;
    return { total, violating, pct };
  }, [states.data, violations.data]);

  const assetName = useMemo(() => {
    const m = new Map<string, string>();
    (assets.data ?? []).forEach((a) => m.set(a.id, a.name || a.identifier));
    return (id: string) => m.get(id) ?? shortId(id);
  }, [assets.data]);

  if (pipeline.isError && !isStatus(pipeline.error, 404))
    return <ErrorState message={errMsg(pipeline.error)} onRetry={() => pipeline.refetch()} />;

  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="Overview"
        title="Cryptographic posture"
        description="Your organisation's quantum readiness across every asset, from discovery to a verified, signed migration."
        actions={
          !reseedHidden && (
            <div className="flex items-end gap-2">
              <label className="block">
                <span className="eyebrow mb-1.5 block">Demo dataset</span>
                <Select
                  value={template}
                  disabled={reseed.isPending}
                  onChange={async (e) => {
                    const t = e.target.value;
                    const ok = await confirm({
                      title: "Replace the workspace data?",
                      subject: `${t} template`,
                      body: "This reloads the organisation with the demo dataset. Current assets, plans and attestations are replaced.",
                      confirmLabel: "Load dataset",
                      tone: "primary",
                    });
                    if (!ok) return;
                    setTemplate(t);
                    reseed.mutate(t);
                  }}
                  className="w-44 capitalize"
                  aria-label="Demo dataset"
                >
                  {DEMO_TEMPLATES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </label>
              {reseed.isPending && <span className="pb-3 font-mono text-[11px] text-ink-3">Loading</span>}
            </div>
          )
        }
      />

      {/* Executive strip */}
      {violations.isLoading || compliance.isLoading || states.isLoading || pipeline.isLoading ? (
        <ReadoutSkeleton />
      ) : (
        <ReadoutStrip cols={4}>
          <div className="flex items-center gap-4 p-5">
            <Dial value={risk.score} label="Quantum risk" tone={risk.tone} size={120} />
            <div>
              <p className="eyebrow">Quantum risk</p>
              <p
                className={cn(
                  "mt-2 font-display text-[2rem] leading-none",
                  { immediate: "text-immediate", urgent: "text-urgent", planned: "text-planned", safe: "text-safe" }[risk.tone]
                )}
              >
                {risk.level}
              </p>
              <p className="mt-2 text-xs text-ink-3">
                {risk.total} open · {risk.immediate} immediate · {risk.urgent} urgent
              </p>
            </div>
          </div>
          <div className="p-5">
            <p className="eyebrow">Compliance</p>
            <p className="mt-2 font-display text-[2.4rem] leading-none tabular">
              <CountUp value={comp.pass} />
              <span className="ml-1 text-base text-ink-3">/ {comp.entries.length} pass</span>
            </p>
            <div className="mt-3 flex flex-wrap gap-1">
              {comp.entries.map(([k, v]) => (
                <Chip key={k} tone={toneFor(v.status)}>
                  {frameworkLabel(k)}
                </Chip>
              ))}
            </div>
          </div>
          <Readout
            label="Remediation coverage"
            value={<CountUp value={coverage.pct} suffix="%" />}
            tone={coverage.pct === 100 ? "safe" : "urgent"}
            foot={`${coverage.violating} of ${coverage.total} state slots need work`}
          />
          <div className="p-5">
            <p className="eyebrow">Migration status</p>
            <div className="mt-3">
              {p?.converged ? (
                <Stamp tone="safe" value="converged">
                  Converged
                </Stamp>
              ) : (
                <Stamp tone="urgent" value={p?.open_violations}>
                  {p?.open_violations ?? 0} open
                </Stamp>
              )}
            </div>
            <p className="mt-3 text-xs text-ink-3">
              {p?.plans.total ?? 0} plans · {p?.bundles ?? 0} bundles · {p?.attestations ?? 0} attestations
            </p>
          </div>
        </ReadoutStrip>
      )}

      {/* Pipeline ledger */}
      <Section index="01" title="Pipeline" description="Each stage of the spine, from inventory to signed attestation. Select a stage to jump to it.">
        {pipeline.isLoading || !p ? (
          <Skeleton className="h-20 w-full" />
        ) : (
          <ol className="grid grid-cols-2 gap-px border-y border-ink bg-rule sm:grid-cols-4 lg:grid-cols-7 [&>li]:bg-bg">
            {[
              { label: "Assets", value: p.assets.total, target: "sec-assets" },
              { label: "Graph edges", value: p.edges, target: "sec-assets" },
              { label: "State slots", value: p.component_states.total, target: "sec-state" },
              { label: "Violations", value: p.open_violations, target: "sec-violations", tone: p.open_violations ? "text-immediate" : "text-safe" },
              { label: "Plans", value: p.plans.total, target: "sec-actions" },
              { label: "Bundles", value: p.bundles, target: "sec-actions" },
              { label: "Attestations", value: p.attestations, target: "sec-attest" },
            ].map((s, i) => (
              <li key={s.label}>
                <button
                  onClick={() => scrollToId(s.target)}
                  className="group flex w-full flex-col items-start gap-1 px-4 py-4 text-left transition-colors duration-micro hover:bg-surface"
                >
                  <span className="font-mono text-[10px] text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                  <span className={cn("font-display text-3xl leading-none tabular", s.tone ?? "text-ink")}>
                    <CountUp value={s.value} />
                  </span>
                  <span className="text-xs text-ink-2 group-hover:text-ink">{s.label}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </Section>

      {/* Migration lifecycle */}
      <Section
        id="sec-actions"
        index="02"
        title="Migration lifecycle"
        description="Preview the change set, commit a plan, build the signed bundle, verify convergence, then attest."
      >
        <div className="flex flex-wrap gap-2 border-y border-rule py-4">
          <Button variant="secondary" onClick={() => dryRun.mutate()} pending={dryRun.isPending} pendingLabel="Running dry-run">
            <IconPlay size={16} /> Dry-run
          </Button>
          <Button variant="secondary" onClick={() => createPlan.mutate()} pending={createPlan.isPending} pendingLabel="Creating plan">
            <IconPlus size={16} /> Create plan
          </Button>
          <Button
            variant="secondary"
            onClick={() => buildBundle.mutate()}
            pending={buildBundle.isPending}
            pendingLabel="Building bundle"
            disabled={!plans.data?.length}
          >
            <IconPackage size={16} /> Build bundle
          </Button>
          <Button
            variant="secondary"
            onClick={() => verifyLatest.mutate()}
            pending={verifyLatest.isPending}
            pendingLabel="Verifying"
            disabled={!plans.data?.length}
          >
            <IconVerify size={16} /> Verify latest plan
          </Button>
          <Button onClick={() => attest.mutate()} pending={attest.isPending} pendingLabel="Signing">
            <IconSignature size={16} /> Generate attestation
          </Button>
          {!plans.isLoading && !plans.data?.length && (
            <p className="w-full pt-1 text-xs text-ink-3">Bundle and verify need a plan. Create one first.</p>
          )}
        </div>

        {verify && (
          <div className="mt-6 flex flex-wrap items-center gap-4 border-b border-rule pb-6">
            <Stamp tone={verify.converged ? "safe" : "urgent"} value={verify.new_evaluation_id}>
              {verify.converged ? "Converged" : "Not converged"}
            </Stamp>
            <p className="text-sm text-ink-2">
              Plan {shortId(verify.plan_id)} · cleared <span className="font-mono text-ink">{verify.cleared.length}</span> · remaining{" "}
              <span className="font-mono text-ink">{verify.remaining.length}</span>
            </p>
          </div>
        )}

        {bundle && (
          <div className="mt-6 grid gap-4 border-b border-rule pb-6 lg:grid-cols-[1fr_auto] lg:items-start">
            <CodeBlock code={JSON.stringify(bundle.manifest, null, 2)} filename={`bundle ${shortId(bundle.bundle_id)} manifest.json`} maxHeight={260} />
            <Button variant="secondary" onClick={() => downloadBase64(bundle.tar_base64, `seqr-bundle-${shortId(bundle.bundle_id)}.tar.gz`)}>
              <IconDownload size={16} /> Download .tar.gz
            </Button>
          </div>
        )}

        {dry && (
          <div className="mt-6">
            <div className="flex flex-wrap items-baseline gap-3">
              <p className="font-display text-xl text-ink">
                {dry.change_count} change{dry.change_count === 1 ? "" : "s"} proposed
              </p>
              {Object.entries(dry.by_platform).map(([k, v]) => (
                <Chip key={k}>
                  {k} {v}
                </Chip>
              ))}
              <button onClick={() => setDry(null)} className="ml-auto text-sm text-ink-2 link-underline">
                Clear preview
              </button>
            </div>
            <ol className="mt-4 border-t border-ink">
              {dry.changes.map((c, i) => (
                <li key={i} className="grid gap-3 border-b border-rule py-4 lg:grid-cols-[220px_1fr]">
                  <div>
                    <p className="font-mono text-[11px] text-ink-3">{String(i + 1).padStart(2, "0")}</p>
                    <p className="mt-1 font-mono text-sm text-urgent">{c.action}</p>
                    <p className="mt-1 text-xs text-ink-2">
                      {c.provider} · {c.slot ?? "no slot"}
                    </p>
                    <p className="mt-2 font-mono text-xs text-ink">
                      {c.from ?? "?"} <span className="text-ink-3">to</span> {c.to ?? "?"}
                    </p>
                    {c.manual && <Chip tone="urgent" className="mt-2">manual step</Chip>}
                  </div>
                  <div className="min-w-0 space-y-2">
                    {c.snippets.map((sn, j) => (
                      <CodeBlock key={j} code={sn} filename={`${c.provider} snippet ${j + 1}`} maxHeight={220} />
                    ))}
                    {c.validation.length > 0 && (
                      <p className="text-xs text-ink-2">
                        <span className="eyebrow mr-2">Validate</span>
                        {c.validation.join(" · ")}
                      </p>
                    )}
                    {c.rollback.length > 0 && (
                      <p className="text-xs text-ink-2">
                        <span className="eyebrow mr-2">Rollback</span>
                        {c.rollback.join(" · ")}
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}
      </Section>

      <ContextRisk index="03" assetName={assetName} />

      {/* Violations */}
      <Section id="sec-violations" index="04" title="Open violations" description="Policy breaches from the latest evaluation, worst first.">
        <ViolationsTable
          loading={violations.isLoading}
          error={violations.isError ? errMsg(violations.error) : null}
          onRetry={() => violations.refetch()}
          rows={violations.data ?? []}
          assetName={assetName}
        />
      </Section>

      {/* Component state */}
      <Section id="sec-state" index="05" title="Component state" description="The winning observation for every cryptographic slot, by asset.">
        {states.isLoading ? (
          <TableSkeleton cols={6} />
        ) : states.isError ? (
          <ErrorState message={errMsg(states.error)} onRetry={() => states.refetch()} />
        ) : !states.data?.length ? (
          <EmptyState title="No state yet" body="Add an asset and scan it, or connect a discovery agent." action={{ label: "Add an asset", href: "/dashboard/assets?new=1" }} />
        ) : (
          <>
            <StackStrip
              className="mb-6"
              parts={[
                { label: "Vulnerable", value: states.data.filter((s) => s.quantum_status === "vulnerable").length, tone: "immediate" },
                { label: "Hybrid", value: states.data.filter((s) => s.quantum_status === "hybrid").length, tone: "hybrid" },
                { label: "Safe", value: states.data.filter((s) => s.quantum_status === "safe").length, tone: "safe" },
                { label: "Unknown", value: states.data.filter((s) => !["vulnerable", "hybrid", "safe"].includes(s.quantum_status ?? "")).length, tone: "neutral" },
              ]}
            />
            <Table>
              <THead>
                <tr>
                  <Th>Asset</Th>
                  <Th>Slot</Th>
                  <Th>Algorithm</Th>
                  <Th>Family</Th>
                  <Th>Quantum</Th>
                  <Th>Source</Th>
                </tr>
              </THead>
              <TBody>
                {states.data.map((s) => (
                  <Tr key={s.id}>
                    <Td label="Asset">
                      <Link href={`/dashboard/assets/${s.asset_id}`} className="text-ink link-underline">
                        {assetName(s.asset_id)}
                      </Link>
                    </Td>
                    <Td label="Slot" mono>
                      {s.slot_key}
                      {s.conflict && <Chip tone="urgent" className="ml-2">conflict</Chip>}
                    </Td>
                    <Td label="Algorithm" mono>
                      {s.algorithm ?? "n/a"}
                    </Td>
                    <Td label="Family" mono>
                      {s.algorithm_family ?? "n/a"}
                    </Td>
                    <Td label="Quantum">
                      <StatusChip value={s.quantum_status} />
                    </Td>
                    <Td label="Source" mono className="text-ink-2">
                      {humanize(s.source)}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </>
        )}
      </Section>

      {/* Assets */}
      <Section
        id="sec-assets"
        index="06"
        title="Assets in the graph"
        description={p ? `${p.assets.total} assets, ${p.edges} edges. ${Object.entries(p.assets.by_provenance).map(([k, v]) => `${v} ${humanize(k)}`).join(", ")}.` : undefined}
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href="/dashboard/graph">
              Open the graph <IconChevronRight size={14} />
            </Link>
          </Button>
        }
      >
        {assets.isLoading ? (
          <TableSkeleton cols={4} rows={4} />
        ) : assets.isError ? (
          <ErrorState message={errMsg(assets.error)} onRetry={() => assets.refetch()} />
        ) : !assets.data?.length ? (
          <EmptyState title="No assets" action={{ label: "Add an asset", href: "/dashboard/assets?new=1" }} />
        ) : (
          <Table>
            <THead>
              <tr>
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Provenance</Th>
                <Th>Status</Th>
              </tr>
            </THead>
            <TBody>
              {assets.data.map((a) => (
                <Tr key={a.id}>
                  <Td label="Name">
                    <Link href={`/dashboard/assets/${a.id}`} className="text-ink link-underline">
                      {a.name || a.identifier}
                    </Link>
                    {a.name && a.name !== a.identifier && <span className="ml-2 font-mono text-xs text-ink-3">{a.identifier}</span>}
                  </Td>
                  <Td label="Type" mono>
                    {humanize(a.type)}
                  </Td>
                  <Td label="Provenance" mono className="text-ink-2">
                    {humanize(a.provenance)}
                  </Td>
                  <Td label="Status">
                    <StatusChip value={a.status} />
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Section>

      {/* Attestations */}
      <Section id="sec-attest" index="07" title="Attestations" description="Signed posture snapshots. Each binds the policy version, the evaluation result and the graph schema.">
        {attestations.isLoading ? (
          <TableSkeleton cols={4} rows={3} />
        ) : attestations.isError ? (
          <ErrorState message={errMsg(attestations.error)} onRetry={() => attestations.refetch()} />
        ) : !attestations.data?.length ? (
          <EmptyState title="Nothing attested yet" body="Generate an attestation to sign the current posture." action={{ label: "Generate attestation", onClick: () => attest.mutate() }} />
        ) : (
          <ul className="border-t border-ink">
            {attestations.data.map((at) => (
              <li key={at.id} className="grid gap-3 border-b border-rule py-4 md:grid-cols-[1fr_auto] md:items-center">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-3">
                    <span className="font-mono text-sm text-ink">{shortId(at.id, 12)}</span>
                    <Chip>policy {at.policy_version}</Chip>
                    <Chip>schema v{at.graph_schema_version}</Chip>
                    <RelTime value={at.created_at} className="text-xs text-ink-3" />
                  </p>
                  <p className="mt-1 truncate font-mono text-[11px] text-ink-3">
                    key {at.key_id} · result {at.evaluation_result_hash.slice(0, 24)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <DownloadButton url={api.graph.attestationCertUrl(at.id)} filename={`seqr-attestation-${shortId(at.id)}.pdf`} label="Certificate (PDF)" icon />
                  <DownloadButton url={api.graph.attestationDownloadUrl(at.id)} filename={`seqr-attestation-${shortId(at.id)}.json`} label="Raw JSON" />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Events */}
      <Section id="sec-events" index="08" title="Event timeline" description="Everything the spine recorded, newest first.">
        {events.isLoading ? (
          <BlockSkeleton lines={6} />
        ) : events.isError ? (
          <ErrorState message={errMsg(events.error)} onRetry={() => events.refetch()} />
        ) : !events.data?.length ? (
          <EmptyState title="No events yet" />
        ) : (
          <EventTimeline events={events.data} assetName={assetName} />
        )}
      </Section>
    </div>
  );
}

function DownloadButton({ url, filename, label, icon }: { url: string; filename: string; label: string; icon?: boolean }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  return (
    <Button
      variant="secondary"
      size="sm"
      pending={busy}
      pendingLabel="Downloading"
      onClick={async () => {
        setBusy(true);
        try {
          await downloadWithAuth(url, filename);
        } catch (e) {
          toast({ title: "Download failed", description: errMsg(e), tone: "error" });
        } finally {
          setBusy(false);
        }
      }}
    >
      {icon ? <IconCertificate size={14} /> : <IconDownload size={14} />} {label}
    </Button>
  );
}

function ViolationsTable({
  loading,
  error,
  onRetry,
  rows,
  assetName,
}: {
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  rows: { id: string; asset_id: string; rule_key: string; severity: string; actual: string | null; target_state: string | null }[];
  assetName: (id: string) => string;
}) {
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" } | null>({ key: "severity", dir: "asc" });
  if (loading) return <TableSkeleton cols={4} rows={4} />;
  if (error) return <ErrorState message={error} onRetry={onRetry} />;
  if (!rows.length) return <Notice title="No open violations">The latest evaluation found nothing out of policy.</Notice>;
  const sorted = sortRows(rows, sort, (r, k) =>
    k === "severity" ? SEV_ORDER.indexOf(r.severity as (typeof SEV_ORDER)[number]) : k === "asset" ? assetName(r.asset_id) : (r as Record<string, unknown>)[k]
  );
  const counts = SEV_ORDER.map((s) => ({ s, n: rows.filter((r) => r.severity === s).length }));
  return (
    <>
      <div className="mb-4 flex flex-wrap gap-4">
        {counts.map(({ s, n }) => (
          <span key={s} className="inline-flex items-center gap-2 font-mono text-xs text-ink-2">
            <Swatch tone={toneFor(s)} /> {s} <span className="text-ink tabular">{n}</span>
          </span>
        ))}
      </div>
      <Table>
        <THead>
          <tr>
            <Th sort={sort?.key === "severity" ? sort.dir : null} onSort={() => setSort(nextSort(sort, "severity"))}>
              Severity
            </Th>
            <Th sort={sort?.key === "rule_key" ? sort.dir : null} onSort={() => setSort(nextSort(sort, "rule_key"))}>
              Rule
            </Th>
            <Th sort={sort?.key === "asset" ? sort.dir : null} onSort={() => setSort(nextSort(sort, "asset"))}>
              Asset
            </Th>
            <Th>Actual, then target</Th>
          </tr>
        </THead>
        <TBody>
          {sorted.map((v) => (
            <Tr key={v.id}>
              <Td label="Severity">
                <StatusChip value={v.severity} />
              </Td>
              <Td label="Rule">{ruleLabel(v.rule_key)}</Td>
              <Td label="Asset">
                <Link href={`/dashboard/assets/${v.asset_id}`} className="text-ink link-underline">
                  {assetName(v.asset_id)}
                </Link>
              </Td>
              <Td label="Actual" mono className="text-ink-2">
                {v.actual ?? "n/a"} <span className="text-ink-3">to</span> <span className="text-ink">{v.target_state ?? "n/a"}</span>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </>
  );
}

function ContextRisk({ index, assetName }: { index: string; assetName: (id: string) => string }) {
  const risk = useQuery({ queryKey: ["context-risk"], queryFn: api.graph.contextRisk });
  const [open, setOpen] = useState<string | null>(null);
  const d = risk.data;
  return (
    <Section
      id="sec-risk"
      index={index}
      title="Risk-ranked cryptography"
      description="Context-aware scoring: algorithm, role, exposure, data sensitivity and shelf life. Select a row to see why."
    >
      {risk.isLoading ? (
        <TableSkeleton cols={6} />
      ) : risk.isError ? (
        <ErrorState message={errMsg(risk.error)} onRetry={() => risk.refetch()} />
      ) : !d || !d.components.length ? (
        <EmptyState title="No cryptography observed yet" action={{ label: "Add an asset", href: "/dashboard/assets?new=1" }} />
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {Object.entries(d.summary.tiers).map(([t, n]) => (
              <Chip key={t} tone={toneFor(t.toLowerCase())}>
                {t.toLowerCase()} {n}
              </Chip>
            ))}
            {d.summary.hndl > 0 && <Chip tone="immediate">HNDL {d.summary.hndl}</Chip>}
          </div>
          <Table>
            <THead>
              <tr>
                <Th align="right">Score</Th>
                <Th>Tier</Th>
                <Th>Algorithm</Th>
                <Th>Where</Th>
                <Th>Role and exposure</Th>
                <Th>HNDL</Th>
              </tr>
            </THead>
            <TBody>
              {d.components.map((c, i) => {
                const k = `${c.rel_path}:${i}`;
                const isOpen = open === k;
                return (
                  <Fragment key={k}>
                    <Tr onClick={() => setOpen(isOpen ? null : k)} aria-expanded={isOpen}>
                      <Td label="Score" align="right" mono>
                        <span className="inline-flex items-center gap-2">
                          {isOpen ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
                          {c.score.toFixed(0)}
                        </span>
                      </Td>
                      <Td label="Tier">
                        <StatusChip value={c.tier.toLowerCase()} />
                      </Td>
                      <Td label="Algorithm" mono>
                        {c.algorithm}
                      </Td>
                      <Td label="Where" mono className="max-w-[280px]">
                        <span className="block truncate">{c.asset_id ? assetName(c.asset_id) : c.rel_path}</span>
                        {c.slot_key && <span className="text-ink-3">{c.slot_key}</span>}
                      </Td>
                      <Td label="Role" className="text-ink-2">
                        {humanize(c.role)} · {humanize(c.exposure)}
                      </Td>
                      <Td label="HNDL">{c.hndl ? <Chip tone="immediate">yes</Chip> : <span className="font-mono text-xs text-ink-3">no</span>}</Td>
                    </Tr>
                    {isOpen && (
                      <tr className="border-b border-rule bg-surface">
                        <td colSpan={6} className="px-3 py-4">
                          <ul className="grid gap-1.5 text-sm text-ink-2 md:grid-cols-2">
                            {c.reasons.map((r, j) => (
                              <li key={j} className="flex gap-2">
                                <span className="font-mono text-xs text-ink-3">{String(j + 1).padStart(2, "0")}</span>
                                {plain(r)}
                              </li>
                            ))}
                          </ul>
                          <p className="mt-3 font-mono text-[11px] text-ink-3">
                            data {humanize(c.data_sensitivity)} · shelf life {humanize(c.shelf_life)} · {c.dependents} dependents
                          </p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </TBody>
          </Table>
          <p className="mt-4 max-w-3xl text-xs text-ink-3">{plain(d.summary.hndl_disclaimer)}</p>
        </>
      )}
    </Section>
  );
}

function EventTimeline({
  events,
  assetName,
}: {
  events: { id: string; type: string; actor: string | null; asset_id: string | null; payload: Record<string, unknown> | null; at: string }[];
  assetName: (id: string) => string;
}) {
  const [limit, setLimit] = useState(12);
  const list = [...events].sort((a, b) => b.at.localeCompare(a.at));
  return (
    <div>
      <ol className="relative border-l border-ink pl-6">
        {list.slice(0, limit).map((e) => (
          <li key={e.id} className="relative pb-5 last:pb-0">
            <span aria-hidden className="absolute -left-[29px] top-1.5 h-2 w-2 bg-ink" />
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="text-sm font-medium capitalize text-ink">{humanize(e.type)}</span>
              <RelTime value={e.at} className="font-mono text-[11px] text-ink-3" />
              {e.asset_id && (
                <Link href={`/dashboard/assets/${e.asset_id}`} className="text-xs text-ink-2 link-underline">
                  {assetName(e.asset_id)}
                </Link>
              )}
            </div>
            {e.payload && Object.keys(e.payload).length > 0 && (
              <p className="mt-1 truncate font-mono text-[11px] text-ink-3">
                {Object.entries(e.payload)
                  .slice(0, 4)
                  .map(([k, v]) => `${k} ${typeof v === "string" && v.length > 14 ? v.slice(0, 8) : JSON.stringify(v)}`)
                  .join(" · ")}
              </p>
            )}
          </li>
        ))}
      </ol>
      {list.length > limit && (
        <Button variant="ghost" size="sm" className="mt-4" onClick={() => setLimit((l) => l + 20)}>
          Show {Math.min(20, list.length - limit)} more
        </Button>
      )}
    </div>
  );
}
