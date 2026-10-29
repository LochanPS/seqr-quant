"use client";

import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Atom, Loader2, Play, Target, Upload } from "lucide-react";
import {
  api,
  type RemediationPlan,
  type RemediationResult,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";

type BadgeVariant = "vulnerable" | "urgent" | "planned" | "muted";
const TIER_VARIANT: Record<string, BadgeVariant> = {
  IMMEDIATE: "vulnerable",
  URGENT: "urgent",
  PLANNED: "planned",
  MONITOR: "muted",
};

export default function RemediationPage() {
  const { toast } = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [budget, setBudget] = useState("40");
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const [reportName, setReportName] = useState<string | null>(null);
  const [useOpt, setUseOpt] = useState(true);
  const [useQaoa, setUseQaoa] = useState(false);

  const run = useMutation({
    mutationFn: () =>
      api.remediation.plan({
        report,
        budget: Number(budget) || 40,
        use_opt: useOpt,
        use_qaoa: useQaoa,
        curve: [20, 40, 80],
      }),
    onError: (e: Error) =>
      toast({ title: "Planning failed", description: e.message, variant: "error" }),
  });

  async function onFile(f: File | undefined) {
    if (!f) return;
    try {
      const parsed = JSON.parse(await f.text());
      if (!Array.isArray(parsed?.findings)) throw new Error("no findings[] in this file");
      setReport(parsed);
      setReportName(f.name);
    } catch (e) {
      toast({
        title: "Not a risk-v2 report",
        description: e instanceof Error ? e.message : String(e),
        variant: "error",
      });
    }
  }

  const r = run.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Remediation planner</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Given an engineer-hour budget, choose the fixes that remove the most quantum risk.
          Findings are ranked by context-aware risk; the selection is solved with QpiAI Opt and
          checked against a greedy heuristic and a certified optimum.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Inputs</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-[1fr_1fr_auto] md:items-end">
          <div className="space-y-2">
            <Label htmlFor="budget">Budget (engineer-hours)</Label>
            <Input
              id="budget"
              type="number"
              min={1}
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Findings</Label>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                <Upload className="mr-2 h-4 w-4" /> Upload risk-v2 JSON
              </Button>
              {report ? (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setReport(null);
                    setReportName(null);
                  }}
                >
                  Use sample
                </Button>
              ) : null}
              <input
                ref={fileRef}
                type="file"
                accept="application/json,.json"
                className="hidden"
                onChange={(e) => onFile(e.target.files?.[0])}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              {reportName ?? "ACME Bank sample"} — produce your own with{" "}
              <code className="font-mono">seqr scan code PATH --context ctx.json --output json</code>
            </p>
          </div>
          <Button onClick={() => run.mutate()} disabled={run.isPending}>
            {run.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-2 h-4 w-4" />
            )}
            Plan
          </Button>
          <div className="flex flex-wrap gap-6 text-sm md:col-span-3">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={useOpt} onChange={(e) => setUseOpt(e.target.checked)} />
              QpiAI Opt (HUBO)
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={useQaoa}
                onChange={(e) => setUseQaoa(e.target.checked)}
              />
              QpiAI QCloud QAOA alternatives (slower, ~10–20 s)
            </label>
          </div>
        </CardContent>
      </Card>

      {r ? <Results r={r} /> : null}
    </div>
  );
}

function bestPlan(r: RemediationResult): RemediationPlan | undefined {
  return r.plans.opt ?? r.plans.exhaustive ?? r.plans.greedy ?? undefined;
}

function Results({ r }: { r: RemediationResult }) {
  const best = bestPlan(r);
  const effortOf = Object.fromEntries(r.actions.map((a) => [a.id, a]));
  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <Stat label="Total risk" value={r.baseline_risk.toFixed(0)} sub={`${r.findings.length} findings`} />
        <Stat
          label="Risk removed"
          value={best ? `${best.removed_pct.toFixed(1)}%` : "—"}
          sub={best?.method.split(":")[0] ?? ""}
        />
        <Stat
          label="Effort used"
          value={best ? `${best.effort}h` : "—"}
          sub={`of ${r.budget}h budget`}
        />
        <Stat
          label="QpiAI Opt vs optimum"
          value={
            r.opt_gap_to_optimum === undefined
              ? "—"
              : r.opt_gap_to_optimum === 0
                ? "optimal"
                : `+${r.opt_gap_to_optimum}`
          }
          sub={r.plans.exhaustive ? "certified by exhaustive search" : "no certificate (large instance)"}
        />
      </div>

      {Object.keys(r.errors).length ? (
        <Card className="border-urgent/40">
          <CardContent className="pt-6 text-sm">
            {Object.entries(r.errors).map(([k, v]) => (
              <p key={k}>
                <span className="font-medium">{k}:</span> {v}
              </p>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Target className="h-4 w-4" /> Chosen plan
            </CardTitle>
          </CardHeader>
          <CardContent>
            {best && best.chosen.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Action</TableHead>
                    <TableHead className="text-right">Effort</TableHead>
                    <TableHead className="text-right">Covers</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {best.chosen.map((id) => (
                    <TableRow key={id}>
                      <TableCell>
                        <div className="font-mono text-xs">{id}</div>
                        <div className="text-xs text-muted-foreground">{effortOf[id]?.label}</div>
                      </TableCell>
                      <TableCell className="text-right">{effortOf[id]?.effort}h</TableCell>
                      <TableCell className="text-right">{effortOf[id]?.covers}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No action fits this budget.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Solver comparison</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Method</TableHead>
                  <TableHead className="text-right">Residual</TableHead>
                  <TableHead className="text-right">Removed</TableHead>
                  <TableHead className="text-right">Effort</TableHead>
                  <TableHead className="text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(["greedy", "opt", "exhaustive"] as const).map((k) => {
                  const p = r.plans[k];
                  if (!p) return null;
                  return (
                    <TableRow key={k}>
                      <TableCell className="font-mono text-xs">{p.method}</TableCell>
                      <TableCell className="text-right">{p.residual.toFixed(1)}</TableCell>
                      <TableCell className="text-right">{p.removed_pct.toFixed(1)}%</TableCell>
                      <TableCell className="text-right">{p.effort}h</TableCell>
                      <TableCell className="text-right">
                        {p.solver_time_s ? `${p.solver_time_s.toFixed(2)}s` : "—"}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {r.curve.length ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk removed vs budget</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {r.curve.map((c) => (
              <div key={c.budget} className="grid grid-cols-[4rem_1fr_4rem] items-center gap-3 text-sm">
                <span className="text-muted-foreground">{c.budget}h</span>
                <div className="h-3 rounded bg-muted">
                  <div
                    className="h-3 rounded bg-primary"
                    style={{ width: `${Math.min(100, c.removed_pct)}%` }}
                  />
                </div>
                <span className="text-right tabular-nums">{c.removed_pct.toFixed(1)}%</span>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {r.qaoa ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Atom className="h-4 w-4" /> QpiAI QCloud — alternative plans (CVaR-QAOA)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              {r.qaoa.qubits} qubits · {r.qaoa.reduced_actions.length} contested actions · reps{" "}
              {r.qaoa.reps} · {r.qaoa.seconds}s · P(best) {r.qaoa.p_optimal.toFixed(3)} vs uniform{" "}
              {r.qaoa.p_uniform.toFixed(3)} (×{r.qaoa.amplification})
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>#</TableHead>
                  <TableHead>Plan</TableHead>
                  <TableHead className="text-right">Residual</TableHead>
                  <TableHead className="text-right">Effort</TableHead>
                  <TableHead className="text-right">Sample P</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {r.qaoa.alternatives.map((a, i) => (
                  <TableRow key={a.chosen.join("|") || "none"}>
                    <TableCell>{i + 1}</TableCell>
                    <TableCell className="font-mono text-xs">{a.chosen.join(", ") || "(nothing)"}</TableCell>
                    <TableCell className="text-right">{a.residual.toFixed(1)}</TableCell>
                    <TableCell className="text-right">{a.effort}h</TableCell>
                    <TableCell className="text-right">{a.probability.toFixed(3)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings, ranked by context-aware risk</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-right">Score</TableHead>
                <TableHead>Tier</TableHead>
                <TableHead>Where</TableHead>
                <TableHead>Role / exposure</TableHead>
                <TableHead>Why</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.findings.map((f) => (
                <TableRow key={`${f.rel_path}:${f.line_number}:${f.algorithm}`}>
                  <TableCell className="text-right tabular-nums">{Number(f.score).toFixed(0)}</TableCell>
                  <TableCell>
                    <Badge variant={TIER_VARIANT[f.tier] ?? "muted"}>{f.tier}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="font-mono text-xs">
                      {f.rel_path}:{f.line_number}
                    </div>
                    <div className="text-xs text-muted-foreground">{f.algorithm}</div>
                  </TableCell>
                  <TableCell className="text-xs">
                    {f.role.replace("_", " ")} · {f.exposure}
                    {f.hndl ? <span className="ml-1 text-vulnerable">HNDL</span> : null}
                  </TableCell>
                  <TableCell className="max-w-md text-xs text-muted-foreground">{f.top_reason}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="space-y-1 text-xs text-muted-foreground">
        {r.notes.map((n) => (
          <p key={n}>{n}</p>
        ))}
      </div>
    </>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
        <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
      </CardContent>
    </Card>
  );
}
