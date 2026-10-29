"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { CBOMResponse, Component } from "@/lib/types";
import { errMsg } from "@/lib/utils";
import { downloadWithAuth } from "@/lib/download";
import { useDebounced } from "@/lib/hooks";
import { PageHeader, RelTime, Section, Segmented } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { EmptyState, ErrorState, ReadoutSkeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip, toneFor } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { Tip } from "@/components/ui/overlay";
import { useToast } from "@/components/ui/toast";
import { DistributionBars } from "@/components/viz/bars";
import { IconCheck, IconChevronLeft, IconChevronRight, IconClose, IconDownload, IconSearch } from "@/components/icons";

const PAGE_SIZE = 25;
const STATUS = ["", "vulnerable", "hybrid", "safe"] as const;
const MIGRATION = ["open", "in_progress", "done", "false_positive"];
const EXPORTS = [
  { format: "json", label: "JSON", ext: "json" },
  { format: "csv", label: "CSV", ext: "csv" },
  { format: "cyclonedx", label: "CycloneDX", ext: "cdx.json" },
];

function CbomInner() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const qc = useQueryClient();
  const toast = useToast();

  const status = params.get("status") ?? "";
  const family = params.get("family") ?? "";
  const timeline = params.get("timeline") ?? "";
  const migration = params.get("migration") ?? "";
  const page = Math.max(1, Number(params.get("page") ?? 1));
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q, 250);

  const setParam = (patch: Record<string, string | number | null>) => {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "" || v === undefined) next.delete(k);
      else next.set(k, String(v));
    }
    if (!("page" in patch)) next.delete("page");
    router.replace(`${pathname}${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  useEffect(() => {
    if ((params.get("q") ?? "") !== dq) setParam({ q: dq || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);

  const summary = useQuery({ queryKey: ["cbom-summary"], queryFn: api.cbom.summary });
  const listKey = ["cbom", { status, family, timeline, migration, page }];
  const list = useQuery({
    queryKey: listKey,
    queryFn: () =>
      api.cbom.list({
        quantum_status: status,
        algorithm_family: family,
        threat_timeline: timeline,
        migration_status: migration,
        page: String(page),
        page_size: String(PAGE_SIZE),
      }),
    placeholderData: keepPreviousData,
  });

  // Optimistic status change with rollback if the server refuses.
  const patch = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) => api.cbom.patch(id, value),
    onMutate: async ({ id, value }) => {
      await qc.cancelQueries({ queryKey: listKey });
      const prev = qc.getQueryData<CBOMResponse>(listKey);
      qc.setQueryData<CBOMResponse>(listKey, (old) =>
        old ? { ...old, items: old.items.map((c) => (c.id === id ? { ...c, migration_status: value } : c)) } : old
      );
      return { prev };
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(listKey, ctx.prev);
      toast({ title: "Could not update the component", description: errMsg(e), tone: "error" });
    },
    onSuccess: (_d, v) => toast({ title: `Marked ${v.value.replace(/_/g, " ")}`, tone: "success", duration: 2500 }),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["cbom"] });
      qc.invalidateQueries({ queryKey: ["cbom-summary"] });
    },
  });

  const [exporting, setExporting] = useState<string | null>(null);
  const doExport = async (format: string, ext: string) => {
    setExporting(format);
    try {
      await downloadWithAuth(api.cbom.exportUrl(format), `seqr-cbom.${ext}`);
    } catch (e) {
      toast({ title: "Export failed", description: errMsg(e), tone: "error" });
    } finally {
      setExporting(null);
    }
  };

  const rows = useMemo(() => {
    const needle = dq.trim().toLowerCase();
    const items = list.data?.items ?? [];
    return needle ? items.filter((c) => `${c.location_detail} ${c.algorithm}`.toLowerCase().includes(needle)) : items;
  }, [list.data, dq]);
  const totalPages = Math.max(1, Math.ceil((list.data?.total ?? 0) / PAGE_SIZE));
  const s = summary.data;
  const anyFilter = status || family || timeline || migration || q;

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="Inventory · Preview"
        title="Cryptographic bill of materials"
        description="Every algorithm SeQr has recorded across your scans, in a form auditors accept. Export as CycloneDX 1.6, JSON or CSV."
        actions={EXPORTS.map((e) => (
          <Button key={e.format} variant="secondary" onClick={() => doExport(e.format, e.ext)} pending={exporting === e.format} pendingLabel="Exporting">
            <IconDownload size={16} /> {e.label}
          </Button>
        ))}
      />

      {summary.isLoading ? (
        <ReadoutSkeleton count={6} />
      ) : summary.isError ? (
        <ErrorState message={errMsg(summary.error)} onRetry={() => summary.refetch()} />
      ) : s ? (
        <>
          <ReadoutStrip cols={6}>
            <Readout label="Components" value={<CountUp value={s.total_components} />} />
            <Readout label="Vulnerable" value={<CountUp value={s.vulnerable} />} tone={s.vulnerable ? "immediate" : undefined} />
            <Readout label="Hybrid" value={<CountUp value={s.hybrid} />} tone={s.hybrid ? "hybrid" : undefined} />
            <Readout label="Safe" value={<CountUp value={s.safe} />} tone={s.safe ? "safe" : undefined} />
            <Readout label="HNDL high" value={<CountUp value={s.hndl_high} />} tone={s.hndl_high ? "immediate" : undefined} />
            <Readout label="Avg agility" value={<CountUp value={s.avg_crypto_agility_score} decimals={1} />} foot="out of 10" />
          </ReadoutStrip>
          <div className="grid gap-10 lg:grid-cols-2">
            <Section title="By algorithm family">
              <DistributionBars
                data={Object.entries(s.by_algorithm_family).map(([label, value]) => ({ label, value }))}
                toneOf={(l) => (l.startsWith("ML-") || l.includes("SLH") ? "hybrid" : "neutral")}
              />
            </Section>
            <Section title="By threat timeline">
              <DistributionBars
                data={Object.entries(s.by_threat_timeline).map(([label, value]) => ({ label: label.toLowerCase(), value }))}
                toneOf={(l) => toneFor(l)}
                empty="No timeline assigned yet. Live scans assign one to each finding."
              />
            </Section>
          </div>
        </>
      ) : null}

      <Section title="Components" description={list.data ? `${list.data.total} matching on the server.` : undefined}>
        <div className="mb-5 flex flex-wrap items-end gap-3 border-y border-rule py-3">
          <Segmented
            label="Quantum status"
            value={status as (typeof STATUS)[number]}
            onChange={(v) => setParam({ status: v })}
            options={STATUS.map((v) => ({ value: v, label: v || "All" }))}
          />
          <Select value={family} onChange={(e) => setParam({ family: e.target.value })} aria-label="Algorithm family" className="h-8 w-40">
            <option value="">All families</option>
            {Object.keys(s?.by_algorithm_family ?? {}).map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </Select>
          <Select value={timeline} onChange={(e) => setParam({ timeline: e.target.value })} aria-label="Threat timeline" className="h-8 w-40">
            <option value="">All timelines</option>
            {Object.keys(s?.by_threat_timeline ?? {}).map((t) => (
              <option key={t} value={t}>
                {t.toLowerCase()}
              </option>
            ))}
          </Select>
          <Select value={migration} onChange={(e) => setParam({ migration: e.target.value })} aria-label="Migration status" className="h-8 w-40">
            <option value="">Any migration</option>
            {MIGRATION.map((m) => (
              <option key={m} value={m}>
                {m.replace(/_/g, " ")}
              </option>
            ))}
          </Select>
          <div className="relative w-full max-w-[260px]">
            <IconSearch size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by location" aria-label="Filter by location" className="h-8 pl-8" />
          </div>
          {anyFilter && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setQ("");
                router.replace(pathname, { scroll: false });
              }}
            >
              Reset
            </Button>
          )}
        </div>

        {list.isLoading ? (
          <TableSkeleton cols={8} />
        ) : list.isError ? (
          <ErrorState message={errMsg(list.error)} onRetry={() => list.refetch()} />
        ) : !rows.length ? (
          anyFilter ? (
            <EmptyState title="Nothing matches these filters" action={{ label: "Reset filters", onClick: () => { setQ(""); router.replace(pathname); } }} />
          ) : (
            <EmptyState title="The inventory is empty" body="Scan an asset to record its cryptography." action={{ label: "Go to assets", href: "/dashboard/assets" }} />
          )
        ) : (
          <div className={list.isFetching && list.isPlaceholderData ? "opacity-60 transition-opacity" : "transition-opacity"}>
            <Table>
              <THead>
                <tr>
                  <Th>Location</Th>
                  <Th>Algorithm</Th>
                  <Th>Status</Th>
                  <Th>HNDL</Th>
                  <Th>Timeline</Th>
                  <Th align="right">Priority</Th>
                  <Th>Migration</Th>
                  <Th align="right">
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </THead>
              <TBody>
                {rows.map((c) => (
                  <ComponentRow key={c.id} c={c} onPatch={(value) => patch.mutate({ id: c.id, value })} />
                ))}
              </TBody>
            </Table>
          </div>
        )}

        <div className="mt-5 flex items-center justify-between gap-4">
          <span className="font-mono text-xs text-ink-3 tabular">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setParam({ page: page - 1 })}>
              <IconChevronLeft size={14} /> Previous
            </Button>
            <Button variant="secondary" size="sm" disabled={page >= totalPages} onClick={() => setParam({ page: page + 1 })}>
              Next <IconChevronRight size={14} />
            </Button>
          </div>
        </div>
      </Section>
    </div>
  );
}

function ComponentRow({ c, onPatch }: { c: Component; onPatch: (v: string) => void }) {
  return (
    <Tr>
      <Td label="Location" mono className="max-w-[320px]">
        <span className="block truncate text-ink">{c.location_detail}</span>
        <span className="text-[11px] text-ink-3">
          {c.location_type} · seen <RelTime value={c.last_seen_at} />
        </span>
      </Td>
      <Td label="Algorithm" mono>
        {c.algorithm}
        {c.key_size ? <span className="text-ink-3"> {c.key_size}</span> : null}
      </Td>
      <Td label="Status">
        <StatusChip value={c.quantum_status} />
      </Td>
      <Td label="HNDL">{c.estimated_hndl_exposure ? <Chip tone={toneFor(c.estimated_hndl_exposure)}>{c.estimated_hndl_exposure}</Chip> : <span className="font-mono text-xs text-ink-3">n/a</span>}</Td>
      <Td label="Timeline">
        <StatusChip value={c.threat_timeline?.toLowerCase()} />
      </Td>
      <Td label="Priority" align="right" mono>
        {c.pqc_migration_priority ?? "n/a"}
      </Td>
      <Td label="Migration">
        <StatusChip value={c.migration_status} />
      </Td>
      <Td align="right">
        <span className="inline-flex gap-1">
          <Tip label="Mark done">
            <Button variant="ghost" size="icon-sm" aria-label="Mark done" disabled={c.migration_status === "done"} onClick={() => onPatch("done")}>
              <IconCheck size={16} />
            </Button>
          </Tip>
          <Tip label="Mark false positive">
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Mark false positive"
              disabled={c.migration_status === "false_positive"}
              onClick={() => onPatch("false_positive")}
            >
              <IconClose size={16} />
            </Button>
          </Tip>
          {(c.migration_status === "done" || c.migration_status === "false_positive") && (
            <Button variant="ghost" size="sm" onClick={() => onPatch("open")}>
              Reopen
            </Button>
          )}
        </span>
      </Td>
    </Tr>
  );
}

export default function CbomPage() {
  return (
    <Suspense fallback={<TableSkeleton cols={8} />}>
      <CbomInner />
    </Suspense>
  );
}
