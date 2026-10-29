"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "motion/react";
import { api, getToken, isStatus } from "@/lib/api";
import type { TransportSummary } from "@/lib/types";
import { agilityTier, cn, errMsg, humanize, shortId } from "@/lib/utils";
import { PageHeader, RelTime, Section } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, Notice, ReadoutSkeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, Stamp, StatusChip, toneFor } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { StackStrip } from "@/components/viz/bars";
import { Dial } from "@/components/viz/dial";
import { useAssetActions } from "@/components/assets/use-asset-actions";
import { IconArrowLeft, IconCbom, IconScan } from "@/components/icons";

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
const RUNNING = ["pending", "queued", "running", "in_progress"];
const DEFAULT_STEPS = ["Queued", "Resolving host", "Handshake and certificate", "Classifying algorithms", "Writing inventory"];

type Live = { algorithm: string; algorithm_family?: string; location_detail?: string; quantum_status?: string };

export default function ScanPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.scans.get(id),
    retry: false,
    refetchInterval: (q) => (q.state.data && RUNNING.includes(q.state.data.status) ? 2500 : false),
  });
  const s = scan.data;
  const running = !!s && RUNNING.includes(s.status);
  const done = s?.status === "complete" || s?.status === "completed";

  const [steps, setSteps] = useState<string[]>([]);
  const [live, setLive] = useState<Live[]>([]);
  const [wsState, setWsState] = useState<"idle" | "live" | "fallback">("idle");
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!running) return;
    const token = getToken();
    if (!token) return;
    let closedByUs = false;
    try {
      const sock = new WebSocket(`${WS_BASE}/ws/scans/${id}?token=${encodeURIComponent(token)}`);
      ws.current = sock;
      sock.onopen = () => setWsState("live");
      sock.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (m.type === "step" && m.step) setSteps((x) => (x.includes(m.step) ? x : [...x, m.step]));
          if (m.type === "finding") setLive((x) => [...x, m]);
          if (m.type === "complete" || m.type === "failed") {
            qc.invalidateQueries({ queryKey: ["scan", id] });
            qc.invalidateQueries({ queryKey: ["scan-components", id] });
            qc.invalidateQueries({ queryKey: ["assets"] });
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      sock.onerror = () => setWsState("fallback");
      sock.onclose = () => {
        if (!closedByUs) setWsState((w) => (w === "live" ? w : "fallback"));
      };
    } catch {
      setWsState("fallback");
    }
    return () => {
      closedByUs = true;
      ws.current?.close();
    };
  }, [running, id, qc]);

  const components = useQuery({
    queryKey: ["scan-components", id],
    queryFn: () => api.cbom.list({ page_size: "200" }),
    enabled: done,
    select: (r) => r.items.filter((c) => c.scan_id === id),
  });
  const riskScore = useQuery({ queryKey: ["risk-score"], queryFn: api.risk.score, enabled: done });
  const asset = useQuery({
    queryKey: ["asset", s?.asset_id],
    queryFn: () => api.assets.get(s!.asset_id!),
    enabled: !!s?.asset_id,
    retry: false,
  });
  const { scan: rescan } = useAssetActions();

  const counts = useMemo(() => {
    const list = components.data ?? [];
    const by = (q: string) => list.filter((c) => c.quantum_status === q).length;
    return { total: list.length, vulnerable: by("vulnerable"), hybrid: by("hybrid"), safe: by("safe") };
  }, [components.data]);

  if (scan.isLoading)
    return (
      <div className="space-y-10">
        <ReadoutSkeleton />
        <TableSkeleton />
      </div>
    );
  if (scan.isError || !s)
    return isStatus(scan.error, 404) ? (
      <EmptyState title="Scan not found" body="It may belong to another workspace." action={{ label: "Back to assets", href: "/dashboard/assets" }} />
    ) : (
      <ErrorState message={errMsg(scan.error)} onRetry={() => scan.refetch()} />
    );

  const stepList = steps.length ? steps : DEFAULT_STEPS;
  const activeStep = steps.length ? steps.length - 1 : running ? 1 : stepList.length - 1;
  const assetLabel = asset.data?.name || asset.data?.identifier;
  const t = s.transport_summary;

  return (
    <div className="space-y-12">
      <Link
        href={s.asset_id ? `/dashboard/assets/${s.asset_id}` : "/dashboard/assets"}
        className="inline-flex items-center gap-2 text-sm text-ink-2 transition-colors duration-micro hover:text-ink"
      >
        <IconArrowLeft size={14} /> {assetLabel ?? "Assets"}
      </Link>
      <PageHeader
        eyebrow={`Scan ${shortId(s.id)} · ${s.type} · ${s.trigger}`}
        title={assetLabel ? `Scan of ${assetLabel}` : "Scan"}
        description={
          <span className="inline-flex flex-wrap items-center gap-3">
            <Stamp tone={toneFor(s.status)} value={s.status}>
              {humanize(s.status)}
            </Stamp>
            <span className="text-sm text-ink-3">
              started <RelTime value={s.started_at ?? s.created_at} />
              {s.completed_at && (
                <>
                  {" "}
                  · finished <RelTime value={s.completed_at} />
                </>
              )}
            </span>
          </span>
        }
        actions={
          <>
            {done && (
              <Button asChild variant="secondary">
                <Link href="/dashboard/cbom">
                  <IconCbom size={16} /> Open in CBOM
                </Link>
              </Button>
            )}
            {s.asset_id && (
              <Button onClick={() => rescan.mutate(s.asset_id!)} pending={rescan.isPending} pendingLabel="Starting" disabled={running}>
                <IconScan size={16} /> Scan again
              </Button>
            )}
          </>
        }
      />

      {running && (
        <Section index="01" title="In progress" description={wsState === "live" ? "Streaming live from the scanner." : "Checking every few seconds."}>
          <div className="grid gap-10 lg:grid-cols-[320px_1fr]">
            <ol className="border-l border-ink">
              {stepList.map((st, i) => {
                const state = i < activeStep ? "done" : i === activeStep ? "active" : "todo";
                return (
                  <li key={st} className="relative py-2.5 pl-6">
                    <span
                      aria-hidden
                      className={cn(
                        "absolute -left-[5px] top-[15px] h-2 w-2",
                        state === "done" ? "bg-ink" : state === "active" ? "animate-skeleton bg-accent" : "border border-rule bg-bg"
                      )}
                    />
                    <span className={cn("text-sm", state === "todo" ? "text-ink-3" : "text-ink")}>{st}</span>
                  </li>
                );
              })}
            </ol>
            <div>
              <p className="eyebrow mb-3">Live findings</p>
              {live.length === 0 ? (
                <p className="text-sm text-ink-3">Findings appear here as the scanner classifies them.</p>
              ) : (
                <ul className="border-t border-rule">
                  <AnimatePresence initial={false}>
                    {live.map((f, i) => (
                      <motion.li
                        key={i}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="flex items-center gap-4 border-b border-rule py-2.5 font-mono text-[13px]"
                      >
                        <span className="w-28 text-ink">{f.algorithm}</span>
                        <span className="min-w-0 flex-1 truncate text-ink-2">{f.location_detail}</span>
                        <StatusChip value={f.quantum_status} />
                      </motion.li>
                    ))}
                  </AnimatePresence>
                </ul>
              )}
            </div>
          </div>
        </Section>
      )}

      {s.status === "failed" && (
        <div role="alert" className="border border-immediate/60 p-6">
          <p className="font-display text-xl text-immediate">Scan failed</p>
          <p className="mt-2 break-words font-mono text-sm text-ink-2">{s.error_message ?? "The scanner did not return a reason."}</p>
          {s.asset_id && (
            <Button className="mt-4" variant="danger" onClick={() => rescan.mutate(s.asset_id!)} pending={rescan.isPending} pendingLabel="Retrying">
              Retry scan
            </Button>
          )}
        </div>
      )}

      {done && (
        <>
          {riskScore.isLoading || components.isLoading ? (
            <ReadoutSkeleton />
          ) : (
            <ReadoutStrip cols={4}>
              <div className="flex items-center gap-4 p-5">
                <Dial value={riskScore.data?.score ?? 0} label="Quantum risk" size={110} tone={toneFor(riskScore.data?.label) === "neutral" ? "ink" : (toneFor(riskScore.data?.label) as "immediate")} />
                <div>
                  <p className="eyebrow">Org risk</p>
                  <p className="mt-2 font-display text-2xl capitalize">{riskScore.data?.label ?? "n/a"}</p>
                </div>
              </div>
              <Readout label="Components" value={<CountUp value={s.components_found || counts.total} />} />
              <Readout label="Vulnerable" value={<CountUp value={s.vulnerable_found || counts.vulnerable} />} tone={s.vulnerable_found || counts.vulnerable ? "immediate" : "safe"} />
              <div className="p-5">
                <p className="eyebrow">Cryptographic status</p>
                <StackStrip
                  className="mt-4"
                  parts={[
                    { label: "Vulnerable", value: counts.vulnerable, tone: "immediate" },
                    { label: "Hybrid", value: counts.hybrid, tone: "hybrid" },
                    { label: "Safe", value: counts.safe, tone: "safe" },
                  ]}
                />
              </div>
            </ReadoutStrip>
          )}

          {t && <TransportPosture t={t} />}

          <Section index="02" title="Components" description="Every algorithm this scan recorded.">
            {components.isLoading ? (
              <TableSkeleton cols={5} />
            ) : components.isError ? (
              <ErrorState message={errMsg(components.error)} onRetry={() => components.refetch()} />
            ) : !components.data?.length ? (
              <Notice title="No components on record">
                This scan finished without recording components. Seeded demo scans carry no findings; run a new scan to collect them.
              </Notice>
            ) : (
              <Table>
                <THead>
                  <tr>
                    <Th>Algorithm</Th>
                    <Th>Location</Th>
                    <Th>Status</Th>
                    <Th>Timeline</Th>
                    <Th align="right">Priority</Th>
                  </tr>
                </THead>
                <TBody>
                  {components.data.map((c) => (
                    <Tr key={c.id}>
                      <Td label="Algorithm" mono>
                        {c.algorithm}
                        {c.key_size ? <span className="text-ink-3"> · {c.key_size}</span> : null}
                      </Td>
                      <Td label="Location" mono className="max-w-[360px] text-ink-2">
                        <span className="block truncate">{c.location_detail}</span>
                      </Td>
                      <Td label="Status">
                        <StatusChip value={c.quantum_status} />
                      </Td>
                      <Td label="Timeline">
                        <StatusChip value={c.threat_timeline?.toLowerCase()} />
                      </Td>
                      <Td label="Priority" align="right" mono>
                        {c.pqc_migration_priority ?? "n/a"}
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </Section>

          <Section index="03" title="Edge and origin" description="Why a quantum-safe CDN edge is not the whole answer.">
            <div className="grid gap-8 border-t border-ink pt-6 md:grid-cols-2">
              <p className="text-sm leading-relaxed text-ink-2">
                When a domain sits behind a CDN, the scanner talks to the <span className="text-ink">edge</span>. The edge may already offer hybrid
                post-quantum key exchange, but traffic between the edge and your <span className="text-ink">origin</span> can still be classical, and
                an origin that answers directly on the internet bypasses the edge entirely.
              </p>
              <dl className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <dt className="eyebrow">Scanned</dt>
                  <dd className="mt-1 text-ink">{t?.scan_target === "edge" ? "CDN edge" : "Direct to host"}</dd>
                </div>
                <div>
                  <dt className="eyebrow">CDN</dt>
                  <dd className="mt-1 text-ink">{t?.cdn_detected ? t.cdn_provider ?? "detected" : "none detected"}</dd>
                </div>
                <div>
                  <dt className="eyebrow">Origin assessed</dt>
                  <dd className="mt-1 text-ink">{t?.origin_assessed ? "yes" : "no"}</dd>
                </div>
                <div>
                  <dt className="eyebrow">Origin candidates</dt>
                  <dd className="mt-1 font-mono text-xs text-ink">
                    {t?.origin_candidates?.length ? t.origin_candidates.map((o) => `${o.hostname} ${o.ip}`).join(", ") : "none found"}
                  </dd>
                </div>
              </dl>
              {t?.origin_note && <p className="text-sm text-ink-2 md:col-span-2">{t.origin_note}</p>}
            </div>
          </Section>
        </>
      )}
    </div>
  );
}

function TransportPosture({ t }: { t: TransportSummary }) {
  const tier = agilityTier(t.crypto_agility_score);
  const rows: [string, React.ReactNode][] = [
    ["Protocol", t.protocol ?? "tls"],
    ["TLS version", t.tls_version?.replace(/_/g, ".") ?? "n/a"],
    ["Certificate", t.cert_algorithm ?? "n/a"],
    ["Key exchange", t.key_exchange ?? "n/a"],
    ["Hybrid status", t.hybrid_status ?? "n/a"],
    ["PQC (active probe)", t.pqc_active_supported ? t.pqc_active_group ?? "supported" : "not offered"],
    ["Deployment level", t.deployment_level_name ?? (t.deployment_level != null ? `level ${t.deployment_level}` : "n/a")],
  ];
  if (t.host_key) rows.push(["SSH host key", t.host_key]);
  return (
    <Section index="01" title="Transport posture" description="What the handshake told us.">
      <div className="grid gap-8 border-t border-ink pt-2 lg:grid-cols-[1fr_280px]">
        <dl>
          {rows.map(([k, v]) => (
            <div key={k} className="grid grid-cols-[180px_1fr] border-b border-rule py-2.5">
              <dt className="eyebrow self-center">{k}</dt>
              <dd className="font-mono text-sm text-ink">{v}</dd>
            </div>
          ))}
        </dl>
        <div className="pt-4">
          <p className="eyebrow">Crypto agility</p>
          <p className="mt-2 font-display text-5xl leading-none tabular">
            <CountUp value={t.crypto_agility_score ?? 0} decimals={1} />
            <span className="text-lg text-ink-3"> / 10</span>
          </p>
          <Chip tone={tier.variant === "vulnerable" ? "immediate" : tier.variant === "safe" ? "safe" : "planned"} className="mt-3">
            {tier.label}
          </Chip>
          <p className="mt-3 text-xs leading-relaxed text-ink-3">
            A well-configured classical stack tops out near 6.5 today. Higher scores need hybrid post-quantum key exchange.
          </p>
        </div>
      </div>
    </Section>
  );
}
