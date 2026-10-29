"use client";

import Link from "next/link";
import { useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api, isStatus } from "@/lib/api";
import { errMsg, humanize, shortId } from "@/lib/utils";
import { assetTypeLabel } from "@/lib/domain";
import { PageHeader, RelTime, Section } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { BlockSkeleton, EmptyState, ErrorState, Notice, ReadoutSkeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { Readout, ReadoutStrip } from "@/components/ui/numbers";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useAssetActions } from "@/components/assets/use-asset-actions";
import { IconArrowLeft, IconScan, IconTrash, IconGraph } from "@/components/icons";

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => api.assets.get(id), retry: false });
  // Graph-only assets (discovered by the agent) have no row in /assets; fall back to the graph node.
  const graphNode = useQuery({
    queryKey: ["graph-asset", id],
    queryFn: () => api.graph.asset(id),
    enabled: asset.isError,
    retry: false,
  });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans.list });
  const state = useQuery({ queryKey: ["asset-state", id], queryFn: () => api.graph.assetState(id), retry: false });
  const edges = useQuery({ queryKey: ["asset-edges", id], queryFn: () => api.graph.assetEdges(id), retry: false });
  const graphAssets = useQuery({ queryKey: ["graph-assets"], queryFn: api.graph.assets });
  const { scan, confirmDelete } = useAssetActions();

  const history = useMemo(
    () => (scans.data ?? []).filter((s) => s.asset_id === id).sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? "")),
    [scans.data, id]
  );
  const nameOf = useMemo(() => {
    const m = new Map((graphAssets.data ?? []).map((g) => [g.id, g.name || g.identifier]));
    return (x: string) => m.get(x) ?? shortId(x);
  }, [graphAssets.data]);

  const a = asset.data;
  const g = graphNode.data;
  const title = a?.name || a?.identifier || g?.name || g?.identifier;
  const isGraphOnly = !a && !!g;

  if (asset.isLoading || (asset.isError && graphNode.isLoading)) {
    return (
      <div className="space-y-10">
        <BlockSkeleton lines={3} className="max-w-xl" />
        <ReadoutSkeleton />
        <TableSkeleton />
      </div>
    );
  }
  if (!a && !g) {
    if (isStatus(asset.error, 404) || isStatus(graphNode.error, 404))
      return (
        <EmptyState
          title="Asset not found"
          body="It may have been deleted, or it belongs to another workspace."
          action={{ label: "Back to assets", href: "/dashboard/assets" }}
        />
      );
    return <ErrorState message={errMsg(asset.error)} onRetry={() => asset.refetch()} />;
  }

  return (
    <div className="space-y-12">
      <Link href="/dashboard/assets" className="inline-flex items-center gap-2 text-sm text-ink-2 transition-colors duration-micro hover:text-ink">
        <IconArrowLeft size={14} /> Assets
      </Link>
      <PageHeader
        eyebrow={assetTypeLabel(a?.type ?? g?.type ?? "")}
        title={title ?? "Asset"}
        description={<span className="font-mono text-sm">{a?.identifier ?? g?.identifier}</span>}
        actions={
          a ? (
            <>
              <Button variant="danger" onClick={() => confirmDelete(a, () => router.push("/dashboard/assets"))}>
                <IconTrash size={16} /> Delete
              </Button>
              <Button onClick={() => scan.mutate(a.id)} pending={scan.isPending} pendingLabel="Starting scan">
                <IconScan size={16} /> Scan now
              </Button>
            </>
          ) : (
            <Button asChild variant="secondary">
              <Link href={`/dashboard/graph?node=${id}`}>
                <IconGraph size={16} /> Show in graph
              </Link>
            </Button>
          )
        }
      />

      {isGraphOnly && (
        <Notice title="Discovered asset">
          This asset was found by discovery, not added by hand, so it has no scan history. Its cryptography comes from graph observations.
        </Notice>
      )}

      <ReadoutStrip cols={4}>
        <Readout label="Sensitivity" value={<span className="text-2xl capitalize">{a?.data_sensitivity ?? "n/a"}</span>} />
        <div className="p-5">
          <p className="eyebrow">Status</p>
          <div className="mt-3">
            <StatusChip value={a?.last_scan_status ?? a?.status ?? g?.status} />
          </div>
          <p className="mt-3 text-xs text-ink-3">{g ? `provenance ${humanize(g.provenance)}` : `schedule ${a?.scan_schedule ?? "manual"}`}</p>
        </div>
        <Readout label="Scans" value={history.length} foot={a?.last_scanned_at ? <>last <RelTime value={a.last_scanned_at} /></> : "never scanned"} />
        <Readout
          label="Crypto slots"
          value={state.data?.length ?? 0}
          foot={`${(state.data ?? []).filter((s) => s.quantum_status === "vulnerable").length} vulnerable`}
          tone={(state.data ?? []).some((s) => s.quantum_status === "vulnerable") ? "immediate" : undefined}
        />
      </ReadoutStrip>

      <Section index="01" title="Component state" description="What the graph currently believes about each cryptographic slot on this asset.">
        {state.isLoading ? (
          <TableSkeleton cols={5} rows={3} />
        ) : state.isError ? (
          isStatus(state.error, 404) ? (
            <Notice title="Not in the graph yet">Scan this asset to place it in the crypto-asset graph.</Notice>
          ) : (
            <ErrorState message={errMsg(state.error)} onRetry={() => state.refetch()} />
          )
        ) : !state.data?.length ? (
          <Notice title="No observations yet">Run a scan to record this asset&apos;s key exchange and certificate.</Notice>
        ) : (
          <Table>
            <THead>
              <tr>
                <Th>Slot</Th>
                <Th>Algorithm</Th>
                <Th>Family</Th>
                <Th>Quantum</Th>
                <Th>Source</Th>
              </tr>
            </THead>
            <TBody>
              {state.data.map((s) => (
                <Tr key={s.id}>
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
        )}
      </Section>

      <Section index="02" title="Linked assets" description="Edges in the graph that touch this asset.">
        {edges.isLoading ? (
          <TableSkeleton cols={4} rows={2} />
        ) : edges.isError ? (
          isStatus(edges.error, 404) ? (
            <Notice title="No graph edges">This asset is not connected to anything yet.</Notice>
          ) : (
            <ErrorState message={errMsg(edges.error)} onRetry={() => edges.refetch()} />
          )
        ) : !edges.data?.length ? (
          <Notice title="No graph edges">This asset is not connected to anything yet.</Notice>
        ) : (
          <ul className="border-t border-ink">
            {edges.data.map((e) => {
              const other = e.src_asset_id === id ? e.dst_asset_id : e.src_asset_id;
              const outgoing = e.src_asset_id === id;
              return (
                <li key={e.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-rule py-3">
                  <span className="w-20 font-mono text-[11px] uppercase text-ink-3">{outgoing ? "out" : "in"}</span>
                  <span className="font-mono text-sm text-ink-2">{humanize(e.relation)}</span>
                  <Link href={`/dashboard/assets/${other}`} className="text-sm text-ink link-underline">
                    {nameOf(other)}
                  </Link>
                  <span className="ml-auto font-mono text-[11px] text-ink-3">
                    {humanize(e.discovered_by)} · confidence {(e.confidence * 100).toFixed(0)}%
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      {a && (
        <Section index="03" title="Scan history" description="Select a scan to see its findings.">
          {scans.isLoading ? (
            <TableSkeleton cols={5} rows={3} />
          ) : scans.isError ? (
            <ErrorState message={errMsg(scans.error)} onRetry={() => scans.refetch()} />
          ) : !history.length ? (
            <EmptyState title="Never scanned" body="Run the first scan to inventory this asset." action={{ label: "Scan now", onClick: () => scan.mutate(a.id) }} />
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>Status</Th>
                  <Th>Scan</Th>
                  <Th align="right">Components</Th>
                  <Th align="right">Vulnerable</Th>
                  <Th align="right">Started</Th>
                </tr>
              </THead>
              <TBody>
                {history.map((s) => (
                  <Tr key={s.id} onClick={() => router.push(`/dashboard/scans/${s.id}`)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && router.push(`/dashboard/scans/${s.id}`)}>
                    <Td label="Status">
                      <StatusChip value={s.status} />
                    </Td>
                    <Td label="Scan" mono>
                      <Link href={`/dashboard/scans/${s.id}`} className="link-underline" onClick={(e) => e.stopPropagation()}>
                        {shortId(s.id)}
                      </Link>{" "}
                      <span className="text-ink-3">{s.type}</span>
                    </Td>
                    <Td label="Components" align="right" mono>
                      {s.components_found}
                    </Td>
                    <Td label="Vulnerable" align="right" mono className={s.vulnerable_found ? "text-immediate" : undefined}>
                      {s.vulnerable_found}
                    </Td>
                    <Td label="Started" align="right" className="text-ink-2">
                      <RelTime value={s.started_at ?? s.created_at} />
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </Section>
      )}
    </div>
  );
}
