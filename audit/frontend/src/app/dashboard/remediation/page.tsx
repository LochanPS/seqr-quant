"use client";

import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, type RemediationPlan, type RemediationResult } from "@/lib/api";
import { cn, errMsg, humanize } from "@/lib/utils";
import { plain } from "@/lib/domain";
import { PageHeader, Section, Segmented } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Switch } from "@/components/ui/field";
import { Notice, ReadoutSkeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, Stamp, StatusChip } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { CommandLine } from "@/components/ui/code";
import { useToast } from "@/components/ui/toast";
import { Curve } from "@/components/viz/curve";
import { IconMinus, IconPlay, IconPlus, IconUpload } from "@/components/icons";

type Mode = "infra" | "sample" | "upload";

function best(r: RemediationResult): RemediationPlan | undefined {
  return r.plans.opt ?? r.plans.exhaustive ?? r.plans.greedy ?? undefined;
}

export default function RemediationPage() {
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<Mode>("infra");
  const [budget, setBudget] = useState(24);
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const [reportName, setReportName] = useState<string | null>(null);
  const [useOpt, setUseOpt] = useState(true);
  const [useQaoa, setUseQaoa] = useState(false);

  const run = useMutation({
    mutationFn: () => {
      const b = Math.max(1, budget || 1);
      if (mode === "infra") return api.remediation.planInfra({ budget: b, use_opt: useOpt, use_qaoa: useQaoa, curve: curveFor(b) });
      return api.remediation.plan({ report: mode === "upload" ? report : null, budget: b, use_opt: useOpt, use_qaoa: useQaoa, curve: curveFor(b) });
    },
    onSuccess: (r) => {
      const p = best(r);
      toast({ title: "Plan ready", description: p ? `${p.removed_pct.toFixed(1)}% of risk removed for ${p.effort} engineer-hours.` : undefined, tone: "success" });
    },
    onError: (e) => toast({ title: "Planning failed", description: errMsg(e), tone: "error" }),
  });

  async function onFile(f: File | undefined) {
    if (!f) return;
    try {
      const parsed = JSON.parse(await f.text());
      if (!Array.isArray(parsed?.findings)) throw new Error("The file has no findings array.");
      setReport(parsed);
      setReportName(f.name);
      setMode("upload");
      run.reset();
    } catch (e) {
      toast({ title: "Not a risk-v2 report", description: errMsg(e), tone: "error" });
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  const r = run.data;
  const canRun = mode !== "upload" || !!report;

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="Planning"
        title="Remediation planner"
        description="Given an engineer-hour budget, choose the fixes that remove the most quantum risk. Findings are ranked by context-aware risk; the selection is solved with QpiAI Opt and checked against a greedy heuristic and a certified optimum."
      />

      <section className="grid grid-cols-1 gap-10 border-y border-ink py-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
        <div className="min-w-0 space-y-4">
          <p className="eyebrow">01 · Findings</p>
          <Segmented
            label="Findings source"
            value={mode}
            onChange={(m) => {
              if (m === "upload" && !report) {
                fileRef.current?.click();
                return;
              }
              setMode(m);
              setBudget(m === "infra" ? 24 : 40);
              run.reset();
            }}
            options={[
              { value: "infra", label: "Your infrastructure" },
              { value: "sample", label: "ACME Bank sample" },
              { value: "upload", label: reportName ? "Uploaded file" : "Upload" },
            ]}
          />
          <p className="max-w-md text-sm text-ink-2">
            {mode === "infra" &&
              "Every vulnerable slot in your asset graph, ranked as on the Overview. Actions include hybrid key exchange, SSH PQ KEX, certificate reissue, origin lock-down and segmentation."}
            {mode === "sample" && "A sample codebase report from a fictional bank, useful for seeing the solver on a larger instance."}
            {mode === "upload" && (reportName ? <span className="font-mono">{reportName}</span> : "Choose a risk-v2 JSON report.")}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => fileRef.current?.click()}>
              <IconUpload size={14} /> {report ? "Replace file" : "Upload risk-v2 JSON"}
            </Button>
            {report && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setReport(null);
                  setReportName(null);
                  setMode("sample");
                  run.reset();
                }}
              >
                Remove file
              </Button>
            )}
            <input ref={fileRef} type="file" accept="application/json,.json" className="sr-only" tabIndex={-1} onChange={(e) => onFile(e.target.files?.[0])} />
          </div>
          <div>
            <p className="mb-1.5 text-xs text-ink-3">Produce your own report with the CLI:</p>
            <CommandLine command="seqr scan code PATH --context ctx.json --output json" />
          </div>
        </div>

        <div className="min-w-0 space-y-4">
          <p className="eyebrow">02 · Budget and solvers</p>
          <Field label="Budget in engineer-hours">
            {({ id }) => (
              <div className="flex w-56">
                <Button variant="secondary" size="icon" aria-label="Decrease budget" onClick={() => setBudget((b) => Math.max(1, b - 4))}>
                  <IconMinus size={16} />
                </Button>
                <Input
                  id={id}
                  type="number"
                  min={1}
                  value={budget}
                  onChange={(e) => setBudget(Number(e.target.value))}
                  className="-mx-px text-center font-mono text-base tabular"
                />
                <Button variant="secondary" size="icon" aria-label="Increase budget" onClick={() => setBudget((b) => b + 4)}>
                  <IconPlus size={16} />
                </Button>
              </div>
            )}
          </Field>
          <div className="max-w-md space-y-3 border-t border-rule pt-4">
            <Switch checked={useOpt} onChange={setUseOpt} label="Use QpiAI Opt" description="Solve the selection on QpiAI's optimiser, then compare against greedy and exhaustive search." />
            <Switch checked={useQaoa} onChange={setUseQaoa} label="Run QAOA alternatives" description="Sample near-optimal alternatives on QpiAI QCloud. Slower, about 10 to 20 seconds." />
          </div>
        </div>

        <div className="flex items-end">
          <Button size="lg" onClick={() => run.mutate()} pending={run.isPending} pendingLabel={useQaoa ? "Solving, QAOA running" : "Solving"} disabled={!canRun}>
            <IconPlay size={16} /> Plan remediation
          </Button>
        </div>
      </section>

      {run.isPending && (
        <div className="space-y-10">
          <ReadoutSkeleton />
          <TableSkeleton cols={3} rows={5} />
        </div>
      )}
      {!r && !run.isPending && (
        <Notice title="No plan yet">Pick a findings source and budget, then run the planner. Results appear here.</Notice>
      )}
      {r && !run.isPending && <Results r={r} />}
    </div>
  );
}

function curveFor(b: number) {
  const pts = [0.25, 0.5, 1, 1.5, 2, 3].map((f) => Math.max(1, Math.round(b * f)));
  return Array.from(new Set(pts)).sort((x, y) => x - y);
}

function Results({ r }: { r: RemediationResult }) {
  const p = best(r);
  const byId = Object.fromEntries(r.actions.map((a) => [a.id, a]));
  const plans = (["greedy", "exhaustive", "opt"] as const).map((k) => [k, r.plans[k]] as const).filter(([, v]) => !!v);

  return (
    <div className="space-y-14">
      <ReadoutStrip cols={4}>
        <Readout label="Total risk" value={<CountUp value={r.baseline_risk} />} foot={`${r.findings.length} findings · source ${humanize(r.source)}`} />
        <Readout
          label="Risk removed"
          value={p ? <CountUp value={p.removed_pct} decimals={1} suffix="%" /> : "n/a"}
          tone={p && p.removed_pct > 50 ? "safe" : "urgent"}
          foot={p ? p.method.split(":")[0] : undefined}
        />
        <Readout label="Effort used" value={p ? <CountUp value={p.effort} suffix=" h" /> : "n/a"} foot={`of ${r.budget} h budget`} />
        <div className="p-5">
          <p className="eyebrow">QpiAI Opt against optimum</p>
          <div className="mt-3">
            {r.opt_gap_to_optimum === undefined ? (
              <span className="font-display text-3xl text-ink-3">n/a</span>
            ) : r.opt_gap_to_optimum === 0 ? (
              <Stamp tone="safe" value="optimal">
                Optimal
              </Stamp>
            ) : (
              <Stamp tone="urgent" value={r.opt_gap_to_optimum}>
                +{r.opt_gap_to_optimum}
              </Stamp>
            )}
          </div>
          <p className="mt-3 text-xs text-ink-3">{r.plans.exhaustive ? "Certified by exhaustive search" : "No certificate, instance too large"}</p>
        </div>
      </ReadoutStrip>

      {Object.keys(r.errors).length > 0 && (
        <div className="border border-urgent/60 p-5">
          <p className="eyebrow text-urgent">Solver notes</p>
          <ul className="mt-2 space-y-1 text-sm text-ink-2">
            {Object.entries(r.errors).map(([k, v]) => (
              <li key={k}>
                <span className="font-mono text-ink">{k}</span> {plain(v)}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid gap-12 xl:grid-cols-[1fr_1.2fr]">
        <Section index="01" title="Chosen actions" description={p ? `${p.chosen.length} actions selected by ${p.method.split(":")[0]}.` : undefined}>
          {!p || !p.chosen.length ? (
            <Notice title="Nothing fits this budget">Raise the budget to cover at least one action.</Notice>
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>Action</Th>
                  <Th align="right">Effort</Th>
                  <Th align="right">Covers</Th>
                </tr>
              </THead>
              <TBody>
                {p.chosen.map((id, i) => (
                  <Tr key={id}>
                    <Td label="Action">
                      <span className="mr-3 font-mono text-[11px] text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                      {byId[id]?.label ?? id}
                    </Td>
                    <Td label="Effort" align="right" mono>
                      {byId[id]?.effort ?? "?"} h
                    </Td>
                    <Td label="Covers" align="right" mono>
                      {byId[id]?.covers ?? "?"}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </Section>

        <Section index="02" title="Risk removed against budget" description="Each point is a full solve at that budget. The accent line marks yours.">
          <Curve points={r.curve.map((c) => ({ x: c.budget, y: c.removed_pct }))} markX={r.budget} xLabel="Hours" yLabel="Removed" />
        </Section>
      </div>

      <Section index="03" title="Solver comparison">
        <Table>
          <THead>
            <tr>
              <Th>Method</Th>
              <Th align="right">Residual</Th>
              <Th align="right">Removed</Th>
              <Th align="right">Effort</Th>
              <Th>Feasible</Th>
              <Th align="right">Time</Th>
            </tr>
          </THead>
          <TBody>
            {plans.map(([k, v]) => (
              <Tr key={k} className={cn(v === p && "bg-surface")}>
                <Td label="Method">
                  <span className="font-medium text-ink">{k}</span>
                  <span className="ml-2 font-mono text-[11px] text-ink-3">{v!.method}</span>
                </Td>
                <Td label="Residual" align="right" mono>
                  {v!.residual.toFixed(1)}
                </Td>
                <Td label="Removed" align="right" mono>
                  {v!.removed_pct.toFixed(1)}%
                </Td>
                <Td label="Effort" align="right" mono>
                  {v!.effort} h
                </Td>
                <Td label="Feasible">
                  <StatusChip value={v!.feasible ? "pass" : "fail"} />
                </Td>
                <Td label="Time" align="right" mono>
                  {v!.solver_time_s != null ? `${v!.solver_time_s.toFixed(2)} s` : "n/a"}
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </Section>

      {r.qaoa && (
        <Section index="04" title="QAOA alternatives" description={`${r.qaoa.qubits} qubits · ${r.qaoa.reps} reps · CVaR alpha ${r.qaoa.cvar_alpha} · ${r.qaoa.seconds.toFixed(1)} s`}>
          <div className="mb-5 flex flex-wrap gap-2">
            <Chip tone={r.qaoa.contains_best_known ? "safe" : "urgent"}>{r.qaoa.contains_best_known ? "contains best known" : "best known not sampled"}</Chip>
            {r.qaoa.amplification != null && <Chip>amplification {r.qaoa.amplification.toFixed(1)}x</Chip>}
            <Chip>p optimal {(r.qaoa.p_optimal * 100).toFixed(1)}%</Chip>
            <Chip>p uniform {(r.qaoa.p_uniform * 100).toFixed(1)}%</Chip>
          </div>
          <Table>
            <THead>
              <tr>
                <Th>Actions</Th>
                <Th align="right">Residual</Th>
                <Th align="right">Effort</Th>
                <Th align="right">Sample P</Th>
              </tr>
            </THead>
            <TBody>
              {r.qaoa.alternatives.map((a, i) => (
                <Tr key={i}>
                  <Td label="Actions" className="text-ink-2">
                    {a.chosen.map((id) => byId[id]?.label ?? id).join(", ") || "none"}
                    {!a.feasible && <Chip tone="immediate" className="ml-2">over budget</Chip>}
                  </Td>
                  <Td label="Residual" align="right" mono>
                    {a.residual.toFixed(1)}
                  </Td>
                  <Td label="Effort" align="right" mono>
                    {a.effort} h
                  </Td>
                  <Td label="Sample P" align="right" mono>
                    {(a.probability * 100).toFixed(1)}%
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </Section>
      )}

      <Section index={r.qaoa ? "05" : "04"} title="Findings" description="The ranked input to the planner.">
        <Table>
          <THead>
            <tr>
              <Th align="right">Score</Th>
              <Th>Tier</Th>
              <Th>Where</Th>
              <Th>Role and exposure</Th>
              <Th>HNDL</Th>
              <Th>Top reason</Th>
            </tr>
          </THead>
          <TBody>
            {r.findings.slice(0, 60).map((f, i) => (
              <Tr key={i}>
                <Td label="Score" align="right" mono>
                  {f.score.toFixed(0)}
                </Td>
                <Td label="Tier">
                  <StatusChip value={f.tier.toLowerCase()} />
                </Td>
                <Td label="Where" mono className="max-w-[280px]">
                  <span className="block truncate">{f.rel_path}</span>
                  <span className="text-ink-3">
                    {f.algorithm}
                    {f.line_number ? ` · line ${f.line_number}` : ""}
                  </span>
                </Td>
                <Td label="Role" className="text-ink-2">
                  {humanize(f.role)} · {humanize(f.exposure)}
                </Td>
                <Td label="HNDL">{f.hndl ? <Chip tone="immediate">yes</Chip> : <span className="font-mono text-xs text-ink-3">no</span>}</Td>
                <Td label="Reason" className="max-w-[340px] text-ink-2">
                  {plain(f.top_reason)}
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
        {r.findings.length > 60 && <p className="mt-3 font-mono text-xs text-ink-3">Showing the top 60 of {r.findings.length}.</p>}
      </Section>

      {r.notes.length > 0 && (
        <Section title="Notes">
          <ul className="max-w-3xl space-y-2 text-sm text-ink-2">
            {r.notes.map((n, i) => (
              <li key={i} className="flex gap-3">
                <span className="font-mono text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</span>
                {plain(n)}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
