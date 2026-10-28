"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowLeft, CheckCircle2, ShieldQuestion } from "lucide-react";
import { api, getToken } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScanStatusBadge, QuantumStatusBadge, TimelineBadge } from "@/components/shared/StatusBadges";
import {
  FindingsPanel,
  IndeterminateBar,
  StepText,
  type LiveFinding,
} from "@/components/scans/ScanProgress";
import { QuantumRiskGauge } from "@/components/dashboard/QuantumRiskGauge";
import { ErrorState } from "@/components/shared/States";
import { agilityTier, formatDate } from "@/lib/utils";
import type { Component, TransportSummary } from "@/lib/types";

const WS_BASE =
  process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

const STEPS = [
  "Resolving DNS and TLS endpoints…",
  "Probing TLS configuration…",
  "Enumerating cipher suites and key exchange…",
  "Inspecting certificate chain…",
  "Classifying quantum exposure…",
];

export default function ScanPage({
  params,
}: {
  params: { id: string };
}) {
  const { id } = params;
  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const [step, setStep] = useState(STEPS[0]);
  const wsRef = useRef<WebSocket | null>(null);

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.scans.get(id),
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "complete" || s === "failed" ? false : 2000;
    },
  });

  const status = scan.data?.status;
  const running = status === "queued" || status === "running";
  const complete = status === "complete";

  // cycle step text while running
  useEffect(() => {
    if (!running) return;
    let i = 0;
    const t = setInterval(() => {
      i = (i + 1) % STEPS.length;
      setStep(STEPS[i]);
    }, 1800);
    return () => clearInterval(t);
  }, [running]);

  // websocket for live findings
  useEffect(() => {
    if (!running) return;
    const token = getToken();
    if (!token) return;
    let closed = false;
    try {
      const ws = new WebSocket(`${WS_BASE}/ws/scans/${id}?token=${token}`);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.type === "complete" || data.type === "failed") {
            scan.refetch();
            return;
          }
          const algo = data.algorithm || data.algo;
          if (algo || data.location || data.location_detail) {
            setFindings((prev) => [
              {
                id: data.id || `${Date.now()}-${prev.length}`,
                algorithm: algo,
                location: data.location || data.location_detail,
                risk: data.risk || data.quantum_status,
                message: data.message,
              },
              ...prev,
            ]);
          }
          if (data.step || data.message) setStep(data.step || data.message);
        } catch {
          /* ignore non-JSON frames */
        }
      };
      ws.onerror = () => {
        if (!closed) ws.close();
      };
      return () => {
        closed = true;
        ws.close();
      };
    } catch {
      /* WS unavailable — polling fallback handles status */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, id]);

  // load components for this scan once complete
  const cbom = useQuery({
    queryKey: ["cbom-all"],
    queryFn: () => api.cbom.list({ page_size: "200" }),
    enabled: complete,
  });
  const risk = useQuery({
    queryKey: ["risk-score"],
    queryFn: api.risk.score,
    enabled: complete,
  });

  const scanComponents: Component[] =
    cbom.data?.items.filter((c) => c.scan_id === id) ?? [];

  if (scan.isError) {
    return <ErrorState message={(scan.error as Error)?.message} onRetry={scan.refetch} />;
  }

  return (
    <div className="space-y-6">
      <Link
        href="/dashboard/assets"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back
      </Link>

      {/* header */}
      <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Network scan
          </h1>
          {scan.isLoading ? (
            <Skeleton className="mt-2 h-4 w-40" />
          ) : (
            <p className="mt-1 text-sm text-muted-foreground">
              Started {formatDate(scan.data?.created_at)}
            </p>
          )}
        </div>
        {scan.data && <ScanStatusBadge status={scan.data.status} />}
      </div>

      {/* progress */}
      {running && (
        <Card>
          <CardContent className="space-y-4 pt-6">
            <IndeterminateBar active />
            <StepText text={step} active />
          </CardContent>
        </Card>
      )}

      {status === "failed" && (
        <Card className="border-vulnerable/30">
          <CardContent className="pt-6">
            <p className="font-medium text-vulnerable">Scan failed</p>
            <p className="mt-1 font-mono text-xs text-muted-foreground">
              {scan.data?.error_message || "Unknown error"}
            </p>
          </CardContent>
        </Card>
      )}

      {/* live findings while running */}
      {running && (
        <Card>
          <CardHeader>
            <CardTitle>Live findings</CardTitle>
          </CardHeader>
          <CardContent>
            <FindingsPanel findings={findings} />
          </CardContent>
        </Card>
      )}

      {/* results when complete */}
      {complete && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 gap-4 lg:grid-cols-3"
        >
          {scan.data?.transport_summary?.tls_version && (
            <TransportPostureCard t={scan.data.transport_summary} />
          )}
          {scan.data?.transport_summary?.scan_target === "edge" && (
            <OriginCard t={scan.data.transport_summary} />
          )}

          {/* secure summary */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-safe" /> What is secure
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <Row
                label="Safe components"
                value={scanComponents.filter((c) => c.quantum_status === "safe").length}
              />
              <Row
                label="Hybrid components"
                value={scanComponents.filter((c) => c.quantum_status === "hybrid").length}
              />
              <Row label="Total discovered" value={scan.data?.components_found ?? 0} />
            </CardContent>
          </Card>

          {/* risk gauge */}
          <Card>
            <CardHeader>
              <CardTitle>Quantum risk</CardTitle>
            </CardHeader>
            <CardContent>
              {risk.isLoading ? (
                <Skeleton className="h-[150px] w-full" />
              ) : (
                <QuantumRiskGauge
                  score={risk.data?.score ?? 0}
                  label={risk.data?.label ?? "low"}
                />
              )}
            </CardContent>
          </Card>

          {/* vulnerable count */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldQuestion className="h-4 w-4 text-vulnerable" /> Exposed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-4xl font-semibold text-vulnerable tabular-nums">
                {scan.data?.vulnerable_found ?? 0}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                quantum-vulnerable components found
              </p>
            </CardContent>
          </Card>

          {/* cryptographic status table */}
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle>Cryptographic status</CardTitle>
            </CardHeader>
            <CardContent>
              {cbom.isLoading ? (
                <Skeleton className="h-40 w-full" />
              ) : scanComponents.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No components recorded for this scan.
                </p>
              ) : (
                <div className="space-y-2">
                  {scanComponents.map((c) => (
                    <div
                      key={c.id}
                      className="flex items-center justify-between rounded-lg border px-4 py-2.5"
                    >
                      <div className="min-w-0">
                        <p className="truncate font-mono text-sm">
                          {c.algorithm}
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          {c.location_detail}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <TimelineBadge timeline={c.threat_timeline} />
                        <QuantumStatusBadge status={c.quantum_status} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium tabular-nums">{value}</span>
    </div>
  );
}

function PostureRow({
  label,
  value,
  badge,
}: {
  label: string;
  value: React.ReactNode;
  badge?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/50 py-2 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2 font-mono text-sm">
        {value}
        {badge}
      </span>
    </div>
  );
}

function TransportPostureCard({ t }: { t: TransportSummary }) {
  const hybrid = t.pqc_active_supported || t.hybrid_status === "hybrid";
  return (
    <Card className="lg:col-span-3">
      <CardHeader>
        <CardTitle>Transport posture</CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        {t.tls_version && (
          <PostureRow
            label="TLS version"
            value={t.tls_version}
            badge={t.tls_version === "TLS_1_3" ? <Badge variant="safe">modern</Badge> : null}
          />
        )}
        {t.cert_algorithm && (
          <PostureRow
            label="Certificate"
            value={t.cert_algorithm}
            badge={<Badge variant="vulnerable">quantum-vulnerable</Badge>}
          />
        )}
        {t.key_exchange && (
          <PostureRow
            label="Key exchange"
            value={t.key_exchange}
            badge={
              hybrid ? (
                <Badge variant="safe">hybrid PQC</Badge>
              ) : (
                <Badge variant="vulnerable">quantum-vulnerable</Badge>
              )
            }
          />
        )}
        {t.deployment_level_name && (
          <PostureRow
            label="Deployment"
            value={`Level ${t.deployment_level ?? "?"} / 4 — ${t.deployment_level_name}`}
          />
        )}
        {t.cdn_detected && t.cdn_provider && (
          <PostureRow label="CDN" value={t.cdn_provider} />
        )}
        {typeof t.crypto_agility_score === "number" && (
          <PostureRow
            label="Crypto agility"
            value={`${t.crypto_agility_score} / 10`}
            badge={
              <Badge variant={agilityTier(t.crypto_agility_score).variant}>
                {agilityTier(t.crypto_agility_score).label}
              </Badge>
            }
          />
        )}
      </CardContent>
    </Card>
  );
}

function OriginCard({ t }: { t: TransportSummary }) {
  const candidates = t.origin_candidates ?? [];
  return (
    <Card className="border-accent/30 lg:col-span-3">
      <CardHeader>
        <CardTitle className="text-base">Edge vs origin</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          This scan measured the{" "}
          <span className="font-medium text-foreground">CDN edge</span>. Edge hybrid PQC
          protects only the client-to-edge hop — it is not end-to-end quantum-safe, and the
          origin server was not directly assessed.
        </p>
        {candidates.length > 0 ? (
          <div>
            <p className="mb-1 font-medium text-foreground">
              Origin endpoints discovered (passive DNS — not scanned):
            </p>
            <ul className="space-y-1 font-mono text-xs text-muted-foreground">
              {candidates.map((c, i) => (
                <li key={i}>
                  {c.hostname} → {c.ip}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-muted-foreground">
            No exposed origin endpoints were discovered outside the CDN.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
