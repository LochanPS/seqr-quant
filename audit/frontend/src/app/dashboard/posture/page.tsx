"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Radar, Network, ShieldCheck, ShieldAlert, ListChecks, Package,
  FileSignature, CheckCircle2, XCircle, PlayCircle, ScrollText, Boxes, GaugeCircle,
  Download, FileText, Terminal,
} from "lucide-react";
import { api, type DryRun, type VerifyReport } from "@/lib/api";
import { downloadWithAuth } from "@/lib/download";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/shared/States";

const TEMPLATES = ["banking", "healthcare", "telecom", "government", "saas"] as const;
const SEV_ORDER = ["immediate", "urgent", "planned"];
const SEV: Record<string, string> = { immediate: "text-vulnerable", urgent: "text-urgent", planned: "text-planned" };
function sevColor(s: string) { return SEV[s] ?? "text-muted-foreground"; }
function statusColor(s: string | null) {
  if (s === "hybrid" || s === "safe") return "text-safe";
  if (s === "vulnerable") return "text-vulnerable";
  return "text-muted-foreground";
}
function riskColor(label: string) {
  const l = label.toLowerCase();
  if (l === "low") return "text-safe";
  if (l === "high" || l === "critical") return "text-vulnerable";
  return "text-urgent";
}
function complianceColor(s: string) {
  if (s === "PASS") return "bg-safe/15 text-safe";
  if (s === "FAIL") return "bg-vulnerable/15 text-vulnerable";
  if (s === "MONITOR") return "bg-muted text-muted-foreground";
  return "bg-urgent/15 text-urgent";
}

// Plain-language names for policy rules — a CISO shouldn't have to read engine slugs.
const RULE_LABEL: Record<string, string> = {
  kex_must_be_hybrid: "Key exchange is not post-quantum hybrid",
  no_static_rsa_kex: "Static RSA key exchange — no forward secrecy",
  cert_min_rsa: "Certificate key below policy minimum",
  no_exposed_classical_origin: "Classical origin exposed behind the CDN edge",
};
function ruleLabel(k: string) { return RULE_LABEL[k] ?? k; }
function slotOf(rule: string) {
  if (rule.includes("kex")) return "tls:kex";
  if (rule.includes("cert")) return "tls:cert";
  return "origin";
}

function ExecCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</CardTitle></CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}
function Stage({ icon: Icon, label, value, tone, target }: { icon: React.ElementType; label: string; value: React.ReactNode; tone?: string; target: string }) {
  return (
    <button onClick={() => scrollTo(target)} className="flex min-w-[110px] flex-1 flex-col items-center gap-1 rounded-lg border bg-card/40 px-3 py-3 transition-colors hover:bg-accent">
      <Icon className={`h-5 w-5 ${tone ?? "text-quantum"}`} />
      <span className="text-lg font-semibold tabular-nums">{value}</span>
      <span className="text-center text-[0.68rem] uppercase tracking-wide text-muted-foreground">{label}</span>
    </button>
  );
}

export default function PosturePage() {
  const qc = useQueryClient();
  const pipeline = useQuery({ queryKey: ["pipeline"], queryFn: api.migration.pipeline });
  const compliance = useQuery({ queryKey: ["compliance"], queryFn: api.risk.compliance });
  const violations = useQuery({ queryKey: ["violations-current"], queryFn: api.graph.currentViolations });
  const states = useQuery({ queryKey: ["component-states"], queryFn: api.graph.componentStates });
  const assets = useQuery({ queryKey: ["graph-assets"], queryFn: api.graph.assets });
  const attestations = useQuery({ queryKey: ["attestations"], queryFn: api.graph.attestations });
  const events = useQuery({ queryKey: ["graph-events"], queryFn: api.graph.events });

  const [dry, setDry] = useState<DryRun | null>(null);
  const [verifyReport, setVerifyReport] = useState<VerifyReport | null>(null);
  const [template, setTemplate] = useState<string>("banking");
  // Demo template switching (reseed) is hidden — it would overwrite the org's real
  // discovered/scanned data with a seeded template. Kept in code, not exposed in UI.
  const [switcherUnavailable, setSwitcherUnavailable] = useState(true);

  const invalidateAll = () =>
    ["pipeline", "risk-score", "compliance", "violations-current", "component-states", "graph-assets", "attestations", "graph-events"]
      .forEach((k) => qc.invalidateQueries({ queryKey: [k] }));

  const dryRun = useMutation({ mutationFn: api.migration.dryRun, onSuccess: setDry });
  const createPlan = useMutation({ mutationFn: api.migration.createPlan, onSuccess: invalidateAll });
  const genAttestation = useMutation({ mutationFn: api.graph.generateAttestation, onSuccess: invalidateAll });
  const reseed = useMutation({
    mutationFn: (t: string) => api.migration.reseed(t),
    onSuccess: () => { setDry(null); setVerifyReport(null); invalidateAll(); },
    onError: () => setSwitcherUnavailable(true),
  });
  const verifyLatest = useMutation({
    mutationFn: async () => {
      const plans = await api.migration.plans();
      if (!plans.length) throw new Error("No plan yet — create one first.");
      return api.migration.verify(plans[0].id);
    },
    onSuccess: (r) => { setVerifyReport(r); invalidateAll(); },
  });

  const p = pipeline.data;
  const findings = useMemo(() => {
    const v = violations.data ?? [];
    const c = { immediate: 0, urgent: 0, planned: 0 };
    v.forEach((x) => { const k = x.severity as keyof typeof c; if (c[k] !== undefined) c[k]++; });
    const level = c.immediate ? "High" : c.urgent ? "Elevated" : c.planned ? "Moderate" : "Low";
    const tone = c.immediate ? "text-vulnerable" : c.urgent ? "text-urgent" : c.planned ? "text-planned" : "text-safe";
    return { ...c, level, tone, total: v.length };
  }, [violations.data]);
  const complianceStats = useMemo(() => {
    const m = compliance.data ?? {};
    const entries = Object.entries(m);
    const pass = entries.filter(([, v]) => v.status === "PASS").length;
    return { pass, total: entries.length, entries };
  }, [compliance.data]);

  const remediation = useMemo(() => {
    const totalSlots = states.data?.length ?? 0;
    const violating = new Set((violations.data ?? []).map((v) => `${v.asset_id}:${slotOf(v.rule_key)}`)).size;
    const pct = totalSlots ? Math.round(((totalSlots - Math.min(violating, totalSlots)) / totalSlots) * 100) : 0;
    return { totalSlots, violating, pct };
  }, [states.data, violations.data]);

  const sortedViolations = useMemo(
    () => [...(violations.data ?? [])].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    [violations.data]
  );

  if (pipeline.isError) return <ErrorState message={(pipeline.error as Error)?.message} onRetry={() => pipeline.refetch()} />;

  return (
    <div className="space-y-6">
      {/* Header + template switcher */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cryptographic Posture</h1>
          <p className="mt-1 text-sm text-muted-foreground">Your organisation&apos;s quantum-readiness across every asset — from discovery to verified migration.</p>
        </div>
        {!switcherUnavailable && (
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Demo dataset</label>
            <select
              value={template}
              disabled={reseed.isPending}
              onChange={(e) => { setTemplate(e.target.value); reseed.mutate(e.target.value); }}
              className="rounded-lg border bg-card px-3 py-1.5 text-sm capitalize"
            >
              {TEMPLATES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            {reseed.isPending && <span className="text-xs text-muted-foreground">loading…</span>}
          </div>
        )}
      </div>

      {/* Executive summary */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <ExecCard title="Quantum Risk">
          {violations.isLoading ? <Skeleton className="h-14 w-full" /> : (
            <div className="flex items-end gap-2">
              <span className={`text-4xl font-bold ${findings.tone}`}>{findings.level}</span>
            </div>
          )}
          <p className="mt-1 text-xs text-muted-foreground">{findings.total} open findings · {findings.immediate} immediate · {findings.urgent} urgent</p>
        </ExecCard>

        <ExecCard title="Compliance">
          {compliance.isLoading ? <Skeleton className="h-14 w-full" /> : (
            <>
              <div className="flex items-end gap-1">
                <span className="text-4xl font-bold tabular-nums">{complianceStats.pass}</span>
                <span className="mb-1 text-sm text-muted-foreground">/ {complianceStats.total} frameworks pass</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {complianceStats.entries.slice(0, 5).map(([k, v]) => (
                  <span key={k} className={`rounded px-1.5 py-0.5 text-[0.6rem] font-medium ${complianceColor(v.status)}`}>{k.split("_")[0]}</span>
                ))}
              </div>
            </>
          )}
        </ExecCard>

        <ExecCard title="Remediation coverage">
          {states.isLoading ? <Skeleton className="h-14 w-full" /> : (
            <>
              <div className="flex items-end gap-2">
                <span className={`text-4xl font-bold tabular-nums ${remediation.pct === 100 ? "text-safe" : "text-urgent"}`}>{remediation.pct}%</span>
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-accent">
                <div className={`h-full rounded-full ${remediation.pct === 100 ? "bg-safe" : "bg-urgent"}`} style={{ width: `${remediation.pct}%` }} />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{remediation.violating} of {remediation.totalSlots} slots need work</p>
            </>
          )}
        </ExecCard>

        <ExecCard title="Migration status">
          {pipeline.isLoading || !p ? <Skeleton className="h-14 w-full" /> : (
            <>
              <div className={`flex items-center gap-2 text-lg font-semibold ${p.converged ? "text-safe" : "text-urgent"}`}>
                {p.converged ? <CheckCircle2 className="h-5 w-5" /> : <XCircle className="h-5 w-5" />}
                {p.converged ? "Converged" : `${p.open_violations} open`}
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                plans {p.plans.total} · bundles {p.bundles} · attestations {p.attestations}
              </p>
            </>
          )}
        </ExecCard>
      </div>

      {/* Lifecycle stage strip (clickable) */}
      {pipeline.isLoading || !p ? <Skeleton className="h-24 w-full" /> : (
        <div className="flex flex-wrap gap-2">
          <Stage icon={Boxes} label="Assets" value={p.assets.total} target="sec-assets" />
          <Stage icon={Network} label="Graph edges" value={p.edges} target="sec-assets" />
          <Stage icon={ListChecks} label="State slots" value={p.component_states.total} target="sec-state" />
          <Stage icon={ShieldAlert} label="Violations" value={p.open_violations} tone={p.open_violations ? "text-vulnerable" : "text-safe"} target="sec-violations" />
          <Stage icon={GaugeCircle} label="Plans" value={p.plans.total} target="sec-actions" />
          <Stage icon={Package} label="Bundles" value={p.bundles} target="sec-actions" />
          <Stage icon={FileSignature} label="Attestations" value={p.attestations} target="sec-attest" />
        </div>
      )}

      {/* Migration actions */}
      <Card id="sec-actions">
        <CardHeader><CardTitle className="text-base">Migration lifecycle</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <button onClick={() => dryRun.mutate()} disabled={dryRun.isPending} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"><PlayCircle className="h-4 w-4" /> Dry-run</button>
            <button onClick={() => createPlan.mutate()} disabled={createPlan.isPending} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"><ListChecks className="h-4 w-4" /> Create plan</button>
            <button onClick={() => verifyLatest.mutate()} disabled={verifyLatest.isPending} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"><CheckCircle2 className="h-4 w-4" /> Verify latest plan</button>
            <button onClick={() => genAttestation.mutate()} disabled={genAttestation.isPending} className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium hover:bg-accent disabled:opacity-50"><FileSignature className="h-4 w-4" /> Generate attestation</button>
          </div>
          {(createPlan.isError || verifyLatest.isError || dryRun.isError) && (
            <p className="text-sm text-vulnerable">{((createPlan.error || verifyLatest.error || dryRun.error) as Error)?.message}</p>
          )}
          {verifyReport && (
            <p className={`text-sm ${verifyReport.converged ? "text-safe" : "text-urgent"}`}>Verify: converged={String(verifyReport.converged)} · cleared {verifyReport.cleared.length} · remaining {verifyReport.remaining.length}</p>
          )}
          {dry && (
            <div className="rounded-lg border bg-card/40 p-3">
              <p className="text-sm font-medium">Dry-run — {dry.change_count} changes ({Object.entries(dry.by_platform).map(([k, v]) => `${k}:${v}`).join(", ")})</p>
              <div className="mt-2 max-h-64 space-y-2 overflow-auto">
                {dry.changes.map((c, i) => (
                  <div key={i} className="rounded border p-2 text-xs">
                    <span className="font-mono text-urgent">{c.action}</span> · {c.provider} · {c.slot ?? "-"} · {c.from ?? "?"} → {c.to ?? "?"}
                    {c.snippets.map((sn, j) => <pre key={j} className="mt-1 overflow-auto rounded bg-background p-2 text-[0.7rem] leading-relaxed">{sn}</pre>)}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Violations + state */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card id="sec-violations">
          <CardHeader><CardTitle className="text-base">Open violations (by severity)</CardTitle></CardHeader>
          <CardContent>
            {violations.isLoading ? <Skeleton className="h-32 w-full" /> :
              violations.isError ? <p className="text-sm text-vulnerable">Failed to load.</p> :
              sortedViolations.length === 0 ? <p className="text-sm text-safe">Policy satisfied — no open violations.</p> : (
              <div className="space-y-2 text-sm">
                {sortedViolations.map((v) => (
                  <div key={v.id} className="border-b pb-2">
                    <span className={`font-mono text-xs font-semibold uppercase ${sevColor(v.severity)}`}>{v.severity}</span>
                    <p className="font-medium">{ruleLabel(v.rule_key)}</p>
                    <p className="text-xs text-muted-foreground">{v.actual} → {v.target_state}</p>
                    <p className="mt-0.5 font-mono text-[0.6rem] text-muted-foreground/70">{v.rule_key}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card id="sec-state">
          <CardHeader><CardTitle className="text-base">Component state (current)</CardTitle></CardHeader>
          <CardContent>
            {states.isLoading ? <Skeleton className="h-32 w-full" /> :
              (states.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">No state yet.</p> : (
              <div className="max-h-72 space-y-1 overflow-auto text-sm">
                {(states.data ?? []).map((st) => (
                  <div key={st.id} className="flex items-center justify-between gap-2 border-b py-1">
                    <span className="font-mono text-xs">{st.slot_key}</span>
                    <span className={`font-mono text-xs ${statusColor(st.quantum_status)}`}>{st.algorithm ?? "?"}</span>
                    <span className="text-[0.7rem] text-muted-foreground">{st.source}{st.conflict ? " ⚠ conflict" : ""}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Assets + attestations */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card id="sec-assets">
          <CardHeader><CardTitle className="text-base">Assets ({assets.data?.length ?? 0})</CardTitle></CardHeader>
          <CardContent>
            {assets.isLoading ? <Skeleton className="h-32 w-full" /> :
              (assets.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">No assets.</p> : (
              <div className="max-h-72 space-y-1 overflow-auto text-sm">
                {(assets.data ?? []).map((a) => (
                  <div key={a.id} className="flex items-center justify-between gap-2 border-b py-1">
                    <span className="truncate font-medium">{a.identifier}</span>
                    <span className="rounded bg-accent px-1.5 py-0.5 text-[0.6rem] uppercase text-muted-foreground">{a.type}</span>
                    <span className="text-[0.6rem] text-muted-foreground">{a.provenance}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card id="sec-attest">
          <CardHeader><CardTitle className="text-base">Attestations</CardTitle></CardHeader>
          <CardContent>
            {attestations.isLoading ? <Skeleton className="h-32 w-full" /> :
              (attestations.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">None yet — generate one above.</p> : (
              <div className="max-h-72 space-y-2 overflow-auto text-sm">
                {(attestations.data ?? []).map((at) => (
                  <div key={at.id} className="border-b pb-2">
                    <p className="font-mono text-xs">{at.key_id}</p>
                    <p className="text-[0.7rem] text-muted-foreground">policy v{at.policy_version} · schema v{at.graph_schema_version} · {new Date(at.created_at).toLocaleString()}</p>
                    <p className="truncate font-mono text-[0.6rem] text-muted-foreground">sig {at.signature.slice(0, 40)}…</p>
                    <div className="mt-1.5 flex gap-2">
                      <button
                        onClick={() => downloadWithAuth(api.graph.attestationCertUrl(at.id), `seqr-attestation-${at.id}.pdf`)}
                        className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[0.7rem] font-medium hover:bg-accent"
                      >
                        <FileText className="h-3 w-3" /> Certificate (PDF)
                      </button>
                      <button
                        onClick={() => downloadWithAuth(api.graph.attestationDownloadUrl(at.id), `seqr-attestation-${at.id}.json`)}
                        className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[0.7rem] font-medium hover:bg-accent"
                      >
                        <Download className="h-3 w-3" /> Signed JSON
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {(attestations.data ?? []).length > 0 && (
              <div className="mt-3 rounded-lg border bg-muted/40 p-3">
                <p className="flex items-center gap-1.5 text-xs font-medium"><Terminal className="h-3.5 w-3.5" /> Verify offline (air-gapped)</p>
                <p className="mt-1 text-[0.7rem] text-muted-foreground">
                  Anyone can confirm a certificate is authentic and untampered with no callback to SeQr:
                </p>
                <pre className="mt-1.5 overflow-x-auto rounded bg-background px-2 py-1.5 font-mono text-[0.7rem]">seqr verify-attestation seqr-attestation-&lt;id&gt;.json</pre>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Audit trail */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2 text-base"><ScrollText className="h-4 w-4" /> Audit trail</CardTitle></CardHeader>
        <CardContent>
          {events.isLoading ? <Skeleton className="h-24 w-full" /> :
            (events.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">No events.</p> : (
            <div className="max-h-64 space-y-1 overflow-auto font-mono text-xs">
              {(events.data ?? []).map((e) => (
                <div key={e.id} className="flex items-center gap-3 border-b py-1">
                  <span className="text-muted-foreground">{e.at ? new Date(e.at).toLocaleTimeString() : ""}</span>
                  <span className="font-semibold text-quantum">{e.type}</span>
                  <span className="truncate text-muted-foreground">{e.actor?.slice(0, 8)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
