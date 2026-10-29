"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { errMsg } from "@/lib/utils";
import { assetTypeLabel } from "@/lib/domain";
import { useStoredState } from "@/lib/hooks";
import { Flip } from "@/lib/gsap";
import { PageHeader, RelTime, Segmented } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { TBody, THead, Table, Td, Th, Tr, nextSort, sortRows } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { AddAssetDialog } from "@/components/assets/add-asset-dialog";
import { useAssetActions } from "@/components/assets/use-asset-actions";
import { IconDatabase, IconGlobe, IconMail, IconPlus, IconScan, IconSearch, IconServer, IconLock } from "@/components/icons";

type SortKey = "name" | "type" | "sensitivity" | "status" | "scanned";

function TypeGlyph({ type }: { type: string }) {
  const p = { size: 16, className: "text-ink-3" };
  if (type === "ssh") return <IconLock {...p} />;
  if (type === "smtp") return <IconMail {...p} />;
  if (["postgres", "mysql", "mongodb"].includes(type)) return <IconDatabase {...p} />;
  if (["amqp", "grpc", "host", "load_balancer", "hsm"].includes(type)) return <IconServer {...p} />;
  return <IconGlobe {...p} />;
}

function AssetsInner() {
  const router = useRouter();
  const params = useSearchParams();
  const qc = useQueryClient();
  const toast = useToast();
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets.list });
  const { scan, confirmDelete } = useAssetActions();
  const [addOpen, setAddOpen] = useState(false);
  const [view, setView] = useStoredState<"table" | "list">("seqr_assets_view", "table");
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" } | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const flipState = useRef<Flip.FlipState | null>(null);

  useEffect(() => {
    if (params.get("new") === "1") {
      setAddOpen(true);
      router.replace("/dashboard/assets");
    }
  }, [params, router]);

  const scanAll = useMutation({
    mutationFn: api.assets.scanAll,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["scans"] });
      toast({
        title: r.queued ? `Queued ${r.queued} scan${r.queued === 1 ? "" : "s"}` : "Nothing to scan",
        description: r.queued ? "Results appear on each asset as scans complete." : "Add an asset first.",
        tone: r.queued ? "success" : "neutral",
      });
    },
    onError: (e) => toast({ title: "Could not start scans", description: errMsg(e), tone: "error" }),
  });

  const types = useMemo(() => Array.from(new Set((assets.data ?? []).map((a) => a.type))).sort(), [assets.data]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const filtered = (assets.data ?? []).filter(
      (a) =>
        (type === "all" || a.type === type) &&
        (!needle || `${a.name ?? ""} ${a.identifier} ${a.type}`.toLowerCase().includes(needle))
    );
    return sortRows(filtered, sort, (a: Asset, k) =>
      k === "name" ? a.name || a.identifier : k === "sensitivity" ? a.data_sensitivity : k === "status" ? a.last_scan_status ?? a.status : k === "scanned" ? a.last_scanned_at ?? "" : a.type
    );
  }, [assets.data, q, type, sort]);

  // Capture positions before a reorder or view change, then animate from them with Flip.
  const capture = () => {
    if (listRef.current) flipState.current = Flip.getState(listRef.current.querySelectorAll("[data-flip-id]"));
  };
  useEffect(() => {
    if (!flipState.current) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      flipState.current = null;
      return;
    }
    Flip.from(flipState.current, { duration: 0.45, ease: "instrument", absolute: false, nested: true, prune: true });
    flipState.current = null;
  }, [rows, view]);

  const sortBy = (k: SortKey) => {
    capture();
    setSort(nextSort(sort, k));
  };

  const RowMenu = ({ a }: { a: Asset }) => (
    <Menu>
      <MenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={`Actions for ${a.name || a.identifier}`}>
          Actions
        </Button>
      </MenuTrigger>
      <MenuContent>
        <MenuItem onSelect={() => scan.mutate(a.id)}>Scan now</MenuItem>
        <MenuItem asChild>
          <Link href={`/dashboard/assets/${a.id}`}>View details</Link>
        </MenuItem>
        {a.last_scan_id && (
          <MenuItem asChild>
            <Link href={`/dashboard/scans/${a.last_scan_id}`}>Open last scan</Link>
          </MenuItem>
        )}
        <MenuSeparator />
        <MenuItem danger onSelect={() => confirmDelete(a)}>
          Delete
        </MenuItem>
      </MenuContent>
    </Menu>
  );

  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="Inventory"
        title="Assets"
        description="Every endpoint SeQr knows about. Scan one to inventory its cryptography and feed the graph."
        actions={
          <>
            <Button variant="secondary" onClick={() => scanAll.mutate()} pending={scanAll.isPending} pendingLabel="Queuing scans" disabled={!assets.data?.length}>
              <IconScan size={16} /> Scan all
            </Button>
            <Button onClick={() => setAddOpen(true)}>
              <IconPlus size={16} /> Add asset
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-full max-w-xs">
          <IconSearch size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name or host" aria-label="Filter assets" className="pl-9" />
        </div>
        <Select value={type} onChange={(e) => setType(e.target.value)} aria-label="Filter by type" className="w-44">
          <option value="all">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {assetTypeLabel(t)}
            </option>
          ))}
        </Select>
        <span className="font-mono text-xs text-ink-3 tabular">
          {rows.length} of {assets.data?.length ?? 0}
        </span>
        <Segmented
          className="ml-auto"
          label="View"
          value={view}
          onChange={(v) => {
            capture();
            setView(v);
          }}
          options={[
            { value: "table", label: "Table" },
            { value: "list", label: "List" },
          ]}
        />
      </div>

      {assets.isLoading ? (
        <TableSkeleton cols={6} />
      ) : assets.isError ? (
        <ErrorState message={errMsg(assets.error)} onRetry={() => assets.refetch()} />
      ) : !assets.data?.length ? (
        <EmptyState
          title="No assets yet"
          body="Add a domain, SSH host, mail server or database. SeQr scans it from the outside."
          action={{ label: "Add your first asset", onClick: () => setAddOpen(true) }}
        />
      ) : !rows.length ? (
        <EmptyState
          title="No assets match"
          body="Clear the filter to see everything."
          action={{
            label: "Clear filters",
            onClick: () => {
              setQ("");
              setType("all");
            },
          }}
        />
      ) : view === "table" ? (
        <div ref={listRef}>
          <Table>
            <THead>
              <tr>
                {(
                  [
                    ["name", "Asset"],
                    ["type", "Type"],
                    ["sensitivity", "Sensitivity"],
                    ["status", "Last scan"],
                    ["scanned", "Scanned"],
                  ] as [SortKey, string][]
                ).map(([k, l]) => (
                  <Th key={k} sort={sort?.key === k ? sort.dir : null} onSort={() => sortBy(k)}>
                    {l}
                  </Th>
                ))}
                <Th align="right">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </THead>
            <TBody>
              {rows.map((a) => (
                <Tr key={a.id} data-flip-id={a.id}>
                  <Td label="Asset">
                    <Link href={`/dashboard/assets/${a.id}`} className="group inline-flex min-w-0 items-center gap-2.5">
                      <TypeGlyph type={a.type} />
                      <span className="min-w-0">
                        <span className="block truncate text-ink group-hover:underline">{a.name || a.identifier}</span>
                        {a.name && <span className="block truncate font-mono text-[11px] text-ink-3">{a.identifier}</span>}
                      </span>
                    </Link>
                  </Td>
                  <Td label="Type" mono className="text-ink-2">
                    {assetTypeLabel(a.type)}
                  </Td>
                  <Td label="Sensitivity">
                    <Chip>{a.data_sensitivity}</Chip>
                  </Td>
                  <Td label="Last scan">
                    <StatusChip value={a.last_scan_status ?? "never"} />
                  </Td>
                  <Td label="Scanned" className="text-ink-2">
                    <RelTime value={a.last_scanned_at} />
                  </Td>
                  <Td align="right">
                    <span className="inline-flex items-center gap-1">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => scan.mutate(a.id)}
                        pending={scan.isPending && scan.variables === a.id}
                        pendingLabel="Starting"
                      >
                        Scan now
                      </Button>
                      <RowMenu a={a} />
                    </span>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </div>
      ) : (
        <div ref={listRef} className="grid gap-px border-y border-rule bg-rule md:grid-cols-2">
          {rows.map((a) => (
            <article key={a.id} data-flip-id={a.id} className="flex flex-col gap-5 bg-bg p-6">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="eyebrow flex items-center gap-2">
                    <TypeGlyph type={a.type} /> {assetTypeLabel(a.type)}
                  </p>
                  <Link href={`/dashboard/assets/${a.id}`} className="mt-2 block truncate font-display text-2xl text-ink link-underline">
                    {a.name || a.identifier}
                  </Link>
                  <p className="mt-1 truncate font-mono text-xs text-ink-3">{a.identifier}</p>
                </div>
                <StatusChip value={a.last_scan_status ?? "never"} />
              </div>
              <dl className="grid grid-cols-2 gap-4 border-t border-rule pt-4 text-sm">
                <div>
                  <dt className="eyebrow">Sensitivity</dt>
                  <dd className="mt-1 capitalize text-ink">{a.data_sensitivity}</dd>
                </div>
                <div>
                  <dt className="eyebrow">Scanned</dt>
                  <dd className="mt-1 text-ink">
                    <RelTime value={a.last_scanned_at} />
                  </dd>
                </div>
              </dl>
              <div className="mt-auto flex items-center gap-2">
                <Button size="sm" onClick={() => scan.mutate(a.id)} pending={scan.isPending && scan.variables === a.id} pendingLabel="Starting">
                  Scan now
                </Button>
                <Button asChild variant="ghost" size="sm">
                  <Link href={`/dashboard/assets/${a.id}`}>View details</Link>
                </Button>
                <span className="ml-auto">
                  <RowMenu a={a} />
                </span>
              </div>
            </article>
          ))}
        </div>
      )}

      <AddAssetDialog open={addOpen} onOpenChange={setAddOpen} />
    </div>
  );
}

export default function AssetsPage() {
  return (
    <Suspense fallback={<TableSkeleton cols={6} />}>
      <AssetsInner />
    </Suspense>
  );
}

