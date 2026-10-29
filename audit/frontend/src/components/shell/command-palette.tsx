"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import * as D from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { cn, errMsg } from "@/lib/utils";
import { logout, useStoredState, useThemeSwitch } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { IconArrowRight, IconSearch, type IconProps } from "@/components/icons";
import {
  IconAgent,
  IconAssets,
  IconCbom,
  IconGraph,
  IconKey,
  IconLogout,
  IconPlus,
  IconScan,
  IconSignature,
  IconTheme,
} from "@/components/icons";
import { NAV } from "./nav";

type Item = {
  id: string;
  group: "Recent" | "Pages" | "Actions" | "Assets" | "Graph" | "Components";
  label: string;
  hint?: string;
  keywords?: string;
  icon: (p: IconProps) => JSX.Element;
  run: () => void | Promise<void>;
};

/** Subsequence match with a bonus for word starts and contiguous runs. 0 means no match. */
function score(query: string, text: string): number {
  if (!query) return 1;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return 100 - t.indexOf(q);
  let qi = 0;
  let s = 0;
  let run = 0;
  for (let i = 0; i < t.length && qi < q.length; i++) {
    if (t[i] === q[qi]) {
      qi++;
      run++;
      s += run * 2 + (i === 0 || /[\s\-_./:]/.test(t[i - 1]) ? 5 : 0);
    } else run = 0;
  }
  return qi === q.length ? s : 0;
}

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const toast = useToast();
  const qc = useQueryClient();
  const { toggle } = useThemeSwitch();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [recent, setRecent] = useStoredState<string[]>("seqr_palette_recent", []);
  const listRef = useRef<HTMLDivElement>(null);

  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets.list, enabled: open });
  const graph = useQuery({ queryKey: ["graph-assets"], queryFn: api.graph.assets, enabled: open });
  const comps = useQuery({
    queryKey: ["cbom-palette"],
    queryFn: () => api.cbom.list({ page_size: "200" }),
    enabled: open,
  });

  useEffect(() => {
    if (open) {
      setQ("");
      setActive(0);
    }
  }, [open]);

  const go = (href: string) => () => router.push(href);

  const all = useMemo<Item[]>(() => {
    const items: Item[] = [];
    for (const n of NAV)
      items.push({ id: `page:${n.href}`, group: "Pages", label: n.label, hint: n.href, keywords: n.keywords, icon: n.icon, run: go(n.href) });
    items.push(
      { id: "act:add-asset", group: "Actions", label: "Add asset", icon: IconPlus, run: go("/dashboard/assets?new=1") },
      {
        id: "act:scan-all",
        group: "Actions",
        label: "Run all scans",
        icon: IconScan,
        run: async () => {
          try {
            const r = await api.assets.scanAll();
            qc.invalidateQueries({ queryKey: ["assets"] });
            qc.invalidateQueries({ queryKey: ["scans"] });
            toast({ title: r.queued ? `Queued ${r.queued} scan${r.queued === 1 ? "" : "s"}` : "No assets to scan", tone: "success" });
          } catch (e) {
            toast({ title: "Could not start scans", description: errMsg(e), tone: "error" });
          }
        },
      },
      {
        id: "act:attest",
        group: "Actions",
        label: "Generate attestation",
        icon: IconSignature,
        run: async () => {
          try {
            await api.graph.generateAttestation();
            qc.invalidateQueries({ queryKey: ["attestations"] });
            qc.invalidateQueries({ queryKey: ["pipeline"] });
            toast({ title: "Attestation signed", tone: "success" });
          } catch (e) {
            toast({ title: "Attestation failed", description: errMsg(e), tone: "error" });
          }
        },
      },
      { id: "act:key", group: "Actions", label: "Create API key", icon: IconKey, run: go("/dashboard/settings?tab=keys&new=1") },
      { id: "act:agent", group: "Actions", label: "Connect agent", icon: IconAgent, run: go("/dashboard/connections?new=1") },
      { id: "act:theme", group: "Actions", label: "Toggle theme", icon: IconTheme, run: () => toggle() },
      { id: "act:logout", group: "Actions", label: "Log out", icon: IconLogout, run: () => logout() }
    );
    for (const a of assets.data ?? [])
      items.push({
        id: `asset:${a.id}`,
        group: "Assets",
        label: a.name || a.identifier,
        hint: `${a.type} · ${a.identifier}`,
        icon: IconAssets,
        run: go(`/dashboard/assets/${a.id}`),
      });
    for (const g of graph.data ?? [])
      items.push({
        id: `graph:${g.id}`,
        group: "Graph",
        label: g.name || g.identifier,
        hint: `${g.type} · ${g.provenance}`,
        icon: IconGraph,
        run: go(`/dashboard/graph?node=${g.id}`),
      });
    for (const c of comps.data?.items ?? [])
      items.push({
        id: `comp:${c.id}`,
        group: "Components",
        label: `${c.algorithm} · ${c.location_detail}`,
        hint: c.quantum_status,
        icon: IconCbom,
        run: go(`/dashboard/cbom?status=${c.quantum_status}`),
      });
    return items;
    // `go` closes over router only
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assets.data, graph.data, comps.data, router, toast, qc, toggle]);

  const results = useMemo(() => {
    if (!q.trim()) {
      const byId = new Map(all.map((i) => [i.id, i]));
      const rec = recent.map((id) => byId.get(id)).filter(Boolean).map((i) => ({ ...(i as Item), group: "Recent" as const }));
      return [...rec, ...all.filter((i) => i.group === "Pages" || i.group === "Actions")];
    }
    return all
      .map((i) => ({ i, s: Math.max(score(q, i.label) * 2, score(q, `${i.hint ?? ""} ${i.keywords ?? ""}`)) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 40)
      .map((x) => x.i);
  }, [q, all, recent]);

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const select = (item: Item) => {
    setRecent([item.id, ...recent.filter((r) => r !== item.id)].slice(0, 5));
    onOpenChange(false);
    void item.run();
  };

  const groups: { name: string; items: { item: Item; index: number }[] }[] = [];
  results.forEach((item, index) => {
    let g = groups.find((x) => x.name === item.group);
    if (!g) groups.push((g = { name: item.group, items: [] }));
    g.items.push({ item, index });
  });
  const loading = open && (assets.isLoading || graph.isLoading || comps.isLoading);

  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="overlay fixed inset-0 z-50 bg-bg/60" />
        <D.Content
          className="dialog-panel fixed left-1/2 top-[38%] z-50 w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 max-w-2xl border border-ink bg-bg"
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => Math.min(a + 1, results.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => Math.max(a - 1, 0));
            } else if (e.key === "Enter" && results[active]) {
              e.preventDefault();
              select(results[active]);
            }
          }}
        >
          <D.Title className="sr-only">Search and commands</D.Title>
          <D.Description className="sr-only">Type to search pages, actions, assets and components.</D.Description>
          <div className="flex items-center gap-3 border-b border-ink px-4">
            <IconSearch size={18} className="text-ink-3" />
            <input
              autoFocus
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search pages, actions, assets, components"
              aria-label="Search"
              role="combobox"
              aria-expanded
              aria-controls="palette-list"
              aria-activedescendant={results[active] ? `pal-${active}` : undefined}
              className="h-14 min-w-0 flex-1 bg-transparent text-[15px] text-ink placeholder:text-ink-3 focus:outline-none"
            />
            <kbd className="font-mono text-[10px] text-ink-3">ESC</kbd>
          </div>
          <div ref={listRef} id="palette-list" role="listbox" className="max-h-[min(420px,55dvh)] overflow-y-auto py-2">
            {results.length === 0 && (
              <p className="px-4 py-8 text-sm text-ink-3">{loading ? "Loading live data" : `Nothing matches "${q}".`}</p>
            )}
            {groups.map((g) => (
              <div key={g.name} className="py-1">
                <p className="eyebrow px-4 py-1.5">{g.name}</p>
                {g.items.map(({ item, index }) => {
                  const Icon = item.icon;
                  const on = index === active;
                  return (
                    <div
                      key={`${g.name}:${item.id}`}
                      id={`pal-${index}`}
                      data-index={index}
                      role="option"
                      aria-selected={on}
                      onMouseMove={() => setActive(index)}
                      onClick={() => select(item)}
                      className={cn("flex cursor-pointer items-center gap-3 px-4 py-2.5", on ? "bg-ink text-bg" : "text-ink")}
                    >
                      <Icon size={16} className={on ? "text-bg" : "text-ink-3"} />
                      <span className="min-w-0 flex-1 truncate text-sm">{item.label}</span>
                      {item.hint && (
                        <span className={cn("max-w-[40%] truncate font-mono text-[11px]", on ? "text-bg/70" : "text-ink-3")}>{item.hint}</span>
                      )}
                      {on && <IconArrowRight size={14} />}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 border-t border-rule px-4 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-ink-3">
            <span>Up and down to move</span>
            <span>Enter to open</span>
            {loading && <span className="ml-auto">Fetching live data</span>}
          </div>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
