"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { marketing } from "@/lib/marketing-tokens";
import { agilityTier } from "@/lib/utils";
import { GlowButton } from "./GlowButton";

// Single brand amber — the "in name only" hue (paper.accent). Unified across the site so
// there are three colors only: amber (brand), emerald (safe), rose (vulnerable).
const AMBER = "#A65A16";
const AMBER_TINT = "rgba(166, 90, 22, 0.10)";

// Sample scan output. Captured via the seqr-scanner active ML-KEM probe against live
// domains on 2026-06-28, then frozen here. Real measured values — do not fabricate;
// refresh by re-running the scanner (active_pqc=True) against these domains.
const EXAMPLES: { label: string; domain: string; result: ScanResult }[] = [
  {
    label: "Razorpay",
    domain: "razorpay.com",
    result: {
      domain: "razorpay.com",
      reachable: true,
      tls_version: "TLS_1_3",
      cert_algorithm: "RSA-2048",
      cert_expiry_date: "2026-11-04",
      key_exchange: "X25519",
      hybrid_status: "hybrid",
      pqc_offered: true,
      pqc_active_supported: true,
      pqc_active_group: "X25519MLKEM768",
      scan_target: "edge",
      origin_assessed: false,
      deployment_level: 3,
      deployment_level_name: "Hybrid Deployed",
      crypto_agility_score: 6.5,
      cdn_detected: true,
      cdn_provider: "Amazon CloudFront",
      scan_duration_ms: 31282,
      cbom: {
        components: [
          { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "razorpay.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing) / ML-KEM-768 (key exchange)", hndl_risk: false },
          { algorithm: "X25519", algorithm_family: "ECC", location_detail: "razorpay.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "planned", recommended_algorithm: "ML-KEM-768", hndl_risk: false },
        ],
        summary: { total_components: 2, vulnerable_count: 2, safe_count: 0, by_threat_timeline: { urgent: 1, planned: 1 }, by_algorithm_family: { RSA: 1, ECC: 1 } },
      },
    },
  },
  {
    label: "BillDesk",
    domain: "billdesk.com",
    result: {
      domain: "billdesk.com",
      reachable: true,
      tls_version: "TLS_1_2",
      cert_algorithm: "RSA-2048",
      cert_expiry_date: "2026-10-21",
      key_exchange: "ECDHE",
      hybrid_status: "none",
      pqc_offered: false,
      pqc_active_supported: false,
      pqc_active_group: null,
      scan_target: "direct",
      origin_assessed: true,
      deployment_level: 1,
      deployment_level_name: "Modern Classical",
      crypto_agility_score: 3.5,
      cdn_detected: false,
      cdn_provider: null,
      scan_duration_ms: 6796,
      cbom: {
        components: [
          { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "billdesk.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing) / ML-KEM-768 (key exchange)", hndl_risk: false },
          { algorithm: "ECDHE", algorithm_family: "ECC", location_detail: "billdesk.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "Consult NIST PQC standards", hndl_risk: false },
        ],
        summary: { total_components: 2, vulnerable_count: 2, safe_count: 0, by_threat_timeline: { urgent: 2 }, by_algorithm_family: { RSA: 1, ECC: 1 } },
      },
    },
  },
  {
    label: "Instamojo",
    domain: "instamojo.com",
    result: {
      domain: "instamojo.com",
      reachable: true,
      tls_version: "TLS_1_2",
      cert_algorithm: "RSA-2048",
      cert_expiry_date: "2026-08-27",
      key_exchange: "RSA",
      hybrid_status: "none",
      pqc_offered: false,
      pqc_active_supported: false,
      pqc_active_group: null,
      scan_target: "edge",
      origin_assessed: false,
      deployment_level: 1,
      deployment_level_name: "Modern Classical",
      crypto_agility_score: 0.5,
      cdn_detected: true,
      cdn_provider: "Cloudflare",
      scan_duration_ms: 5796,
      cbom: {
        components: [
          { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "instamojo.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing) / ML-KEM-768 (key exchange)", hndl_risk: false },
          { algorithm: "RSA", algorithm_family: "RSA", location_detail: "instamojo.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing) / ML-KEM-768 (key exchange)", hndl_risk: false },
        ],
        summary: { total_components: 2, vulnerable_count: 2, safe_count: 0, by_threat_timeline: { urgent: 2 }, by_algorithm_family: { RSA: 2 } },
      },
    },
  },
];

type CbomComponent = {
  algorithm: string;
  algorithm_family: string;
  location_detail: string;
  quantum_status: string;
  migration_priority?: string;
  threat_timeline: string;
  recommended_algorithm: string;
  hndl_risk?: boolean;
};

type CbomBlock = {
  components: CbomComponent[];
  summary: {
    total_components: number;
    vulnerable_count: number;
    safe_count: number;
    by_threat_timeline: Record<string, number>;
    by_algorithm_family: Record<string, number>;
  };
  // Full CycloneDX 1.6 document — present on live scans, enables client-side download.
  cyclonedx?: unknown;
  disclaimer?: string;
};

type ScanResult = {
  domain: string;
  reachable: boolean;
  tls_version?: string | null;
  cert_algorithm?: string | null;
  cert_expiry_date?: string | null;
  key_exchange?: string | null;
  hybrid_status?: string | null;
  pqc_offered?: boolean;
  pqc_active_supported?: boolean;
  pqc_active_group?: string | null;
  scan_target?: string;
  origin_assessed?: boolean;
  deployment_level?: number;
  deployment_level_name?: string;
  crypto_agility_score?: number;
  cdn_detected?: boolean;
  cdn_provider?: string | null;
  scan_duration_ms?: number;
  error_category?: string;
  message?: string;
  cbom?: CbomBlock | null;
};

const LOADING_STEPS = [
  "Resolving DNS...",
  "Establishing TLS handshake...",
  "Inspecting certificate chain...",
  "Analysing crypto algorithms...",
];

function ResultPanel({ result }: { result: ScanResult }) {
  if (!result.reachable) {
    return (
      <div
        className="rounded-xl p-6 text-sm"
        style={{ background: "#0a0a0a", border: `1px solid ${marketing.border}` }}
      >
        <p style={{ color: marketing.vulnerable }}>
          Could not reach {result.domain} on port 443.
        </p>
        <p className="mt-2" style={{ color: marketing.textMuted }}>
          The domain may not be using HTTPS, or it&apos;s blocking automated scans. Try one of the
          examples above instead.
        </p>
      </div>
    );
  }

  const isStrong =
    (result.deployment_level ?? 0) >= 3 || (result.crypto_agility_score ?? 0) >= 7;

  return (
    <div
      className="overflow-hidden rounded-xl font-mono text-sm"
      style={{
        background: "#0a0a0a",
        border: `1px solid ${marketing.borderStrong}`,
        // left border flags a finding (amber). Modern setups get no strip — no green sideline.
        borderLeft: isStrong ? `1px solid ${marketing.borderStrong}` : `4px solid ${AMBER}`,
      }}
    >
      <div className="px-4 py-2" style={{ background: AMBER }}>
        <span className="font-mono text-xs font-semibold" style={{ color: "#000" }}>seqr — scan result</span>
      </div>
      <div className="p-5 leading-7">
        <p style={{ color: marketing.safe }}>$ seqr scan domain {result.domain}</p>
        <p className="mt-2" style={{ color: marketing.textFaint }}>
          ──────────────────────────────────────
        </p>
        {result.tls_version && (
          <p>
            <span style={{ color: marketing.textMuted }}>TLS Version:    </span>
            {/* item 13: modern transport reads emerald (protected), legacy stays neutral */}
            <span style={{ color: result.tls_version === "TLS_1_3" ? marketing.safe : marketing.textPrimary }}>
              {result.tls_version}
            </span>
            {result.tls_version === "TLS_1_3" && (
              <span style={{ color: marketing.safe, fontWeight: 700 }}>    [MODERN]</span>
            )}
          </p>
        )}
        {result.cert_algorithm && (
          <p>
            <span style={{ color: marketing.textMuted }}>Certificate:    </span>
            <span style={{ color: marketing.vulnerable }}>{result.cert_algorithm}</span>
            <span style={{ color: marketing.vulnerable, fontWeight: 700 }}>    [QUANTUM-VULNERABLE]</span>
          </p>
        )}
        {result.key_exchange && (
          <p>
            <span style={{ color: marketing.textMuted }}>Key Exchange:   </span>
            {/* item 13: ephemeral key exchange = forward secrecy present → emerald; RSA = none → rose */}
            <span style={{ color: result.key_exchange === "RSA" ? marketing.textPrimary : marketing.safe }}>
              {result.key_exchange}
            </span>
            {result.key_exchange === "RSA" ? (
              <span style={{ color: marketing.vulnerable, fontWeight: 700 }}>    [NO FORWARD SECRECY]</span>
            ) : (
              <span style={{ color: marketing.safe, fontWeight: 700 }}>    [FORWARD SECRECY]</span>
            )}
          </p>
        )}
        {result.pqc_active_supported && result.pqc_active_group && (
          <p>
            <span style={{ color: marketing.textMuted }}>PQC (active):   </span>
            <span style={{ color: marketing.safe }}>{result.pqc_active_group}</span>
            <span style={{ color: marketing.safe, fontWeight: 700 }}>    [HYBRID PQC]</span>
          </p>
        )}
        {result.deployment_level !== undefined && (
          <p>
            <span style={{ color: marketing.textMuted }}>Deployment:     </span>
            <span style={{ color: marketing.textPrimary }}>
              Level {result.deployment_level} / 4 — {result.deployment_level_name}
            </span>
          </p>
        )}
        {result.cdn_detected && result.cdn_provider && (
          <p>
            <span style={{ color: marketing.textMuted }}>CDN:            </span>
            <span style={{ color: marketing.safe }}>
              {result.cdn_provider} (low migration effort)
            </span>
          </p>
        )}
        {result.scan_target === "edge" && (
          <p>
            <span style={{ color: marketing.textMuted }}>Scanned:        </span>
            <span style={{ color: marketing.textFaint }}>CDN edge — origin not directly assessed</span>
          </p>
        )}
        {result.crypto_agility_score !== undefined && (
          <p>
            <span style={{ color: marketing.textMuted }}>Agility Score:  </span>
            <span style={{ color: marketing.textPrimary }}>{result.crypto_agility_score} / 10</span>
            <span style={{ color: marketing.textFaint }}> — {agilityTier(result.crypto_agility_score).label}</span>
          </p>
        )}
        <p className="mt-2" style={{ color: marketing.textFaint }}>
          ──────────────────────────────────────
        </p>
        {result.scan_target === "edge" && (result.deployment_level ?? 0) >= 3 ? (
          <p style={{ color: AMBER }}>
            Hybrid PQC detected at the CDN edge — but the certificate is classical and the origin
            server isn&apos;t directly assessed. Edge PQC is not end-to-end quantum-safe.
          </p>
        ) : isStrong ? (
          <p style={{ color: marketing.safe }}>
            ✓ Nice setup — this domain is already running modern TLS. Want to see deeper findings?
            Try scanning a company&apos;s payment or auth API instead.
          </p>
        ) : (
          <p style={{ color: AMBER }}>
            PQC Status: MIGRATION REQUIRED (not a current threat)
          </p>
        )}
        <p className="mt-2" style={{ color: marketing.textFaint }}>
          ✓ Scan complete in {((result.scan_duration_ms ?? 0) / 1000).toFixed(1)}s
        </p>
      </div>
    </div>
  );
}

function downloadCbom(cbom: CbomBlock, domain: string) {
  const doc = cbom.cyclonedx ?? cbom;
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `seqr-cbom-${domain.replace(/[^a-z0-9.-]/gi, "_")}.cdx.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function statusColor(status: string): string {
  if (status === "vulnerable" || status === "deprecated") return marketing.vulnerable;
  if (status === "safe") return marketing.safe;
  return marketing.textPrimary;
}

function timelineColor(timeline: string): string {
  if (timeline === "immediate" || timeline === "urgent") return AMBER;
  if (timeline === "planned") return marketing.textPrimary;
  return marketing.textFaint;
}

function CbomPanel({ cbom, domain }: { cbom: CbomBlock; domain: string }) {
  const s = cbom.summary;
  const canDownload = !!cbom.cyclonedx;

  return (
    <div
      className="mt-4 overflow-hidden rounded-xl"
      style={{ background: "#0a0a0a", border: `1px solid ${marketing.borderStrong}` }}
    >
      <div className="flex items-center justify-between px-4 py-2" style={{ borderBottom: `1px solid ${marketing.border}` }}>
        <span className="font-mono text-xs font-semibold" style={{ color: AMBER }}>
          Cryptographic Bill of Materials (CBOM) · CycloneDX 1.6
        </span>
        {canDownload ? (
          <button
            onClick={() => downloadCbom(cbom, domain)}
            className="rounded-md px-3 py-1 text-xs font-semibold transition-all"
            style={{ background: AMBER, color: "#000" }}
          >
            ↓ Download CBOM (.cdx.json)
          </button>
        ) : (
          <span className="text-xs" style={{ color: marketing.textFaint }}>
            Run a live scan to download
          </span>
        )}
      </div>

      {/* summary chips */}
      <div className="flex flex-wrap gap-2 px-4 pt-4 text-xs">
        <span className="rounded-md px-2 py-1" style={{ background: marketing.surface, color: marketing.textPrimary }}>
          {s.total_components} component{s.total_components === 1 ? "" : "s"}
        </span>
        {s.vulnerable_count > 0 && (
          <span className="rounded-md px-2 py-1" style={{ background: "rgba(190,60,60,0.12)", color: marketing.vulnerable }}>
            {s.vulnerable_count} quantum-vulnerable
          </span>
        )}
        {s.safe_count > 0 && (
          <span className="rounded-md px-2 py-1" style={{ background: "rgba(60,160,90,0.12)", color: marketing.safe }}>
            {s.safe_count} quantum-safe
          </span>
        )}
      </div>

      {/* component table */}
      <div className="overflow-x-auto px-4 py-3">
        <table className="w-full min-w-[520px] border-collapse font-mono text-xs">
          <thead>
            <tr style={{ color: marketing.textMuted }}>
              <th className="py-1 pr-4 text-left font-medium">Algorithm</th>
              <th className="py-1 pr-4 text-left font-medium">Location</th>
              <th className="py-1 pr-4 text-left font-medium">Status</th>
              <th className="py-1 pr-4 text-left font-medium">Timeline</th>
              <th className="py-1 text-left font-medium">Recommended</th>
            </tr>
          </thead>
          <tbody>
            {cbom.components.map((c, i) => (
              <tr key={i} style={{ borderTop: `1px solid ${marketing.border}` }}>
                <td className="py-2 pr-4" style={{ color: marketing.textPrimary }}>
                  {c.algorithm}
                  <span style={{ color: marketing.textFaint }}> · {c.algorithm_family}</span>
                </td>
                <td className="py-2 pr-4" style={{ color: marketing.textFaint }}>
                  {c.location_detail.replace(`${domain}:443 `, "").replace(/[()]/g, "") || "endpoint"}
                </td>
                <td className="py-2 pr-4 font-semibold" style={{ color: statusColor(c.quantum_status) }}>
                  {c.quantum_status}
                </td>
                <td className="py-2 pr-4 uppercase" style={{ color: timelineColor(c.threat_timeline) }}>
                  {c.threat_timeline}
                </td>
                <td className="py-2" style={{ color: marketing.safe }}>
                  {c.recommended_algorithm}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {cbom.disclaimer && (
        <p className="px-4 pb-4 text-[11px] leading-4" style={{ color: marketing.textFaint }}>
          {cbom.disclaimer}
        </p>
      )}
    </div>
  );
}

export function TryItLive() {
  const [selected, setSelected] = useState<number | null>(0);
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [customResult, setCustomResult] = useState<ScanResult | null>(null);
  const [error429, setError429] = useState(false);
  const [showCapture, setShowCapture] = useState(false);

  const displayResult = customResult ?? (selected !== null ? EXAMPLES[selected].result : null);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setCustomResult(null);
    setError429(false);
    setShowCapture(false);
    setLoading(true);
    setLoadingStep(0);

    const stepInterval = setInterval(() => {
      setLoadingStep((s) => Math.min(s + 1, LOADING_STEPS.length - 1));
    }, 900);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      if (res.status === 429) {
        setError429(true);
        return;
      }

      const data = await res.json();
      setCustomResult(data);
      setSelected(null);
      setTimeout(() => setShowCapture(true), 800);
    } catch {
      setCustomResult({
        domain: domain.trim(),
        reachable: false,
        message: "Network error. Check your connection.",
      });
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
    }
  }

  return (
    <section
      id="try-it-live"
      className="py-28"
      style={{ background: "#171512", borderTop: `1px solid ${marketing.border}`, borderBottom: `1px solid ${marketing.border}` }}
    >
      <div className="mx-auto max-w-4xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="mb-12 text-center"
        >
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em]" style={{ color: AMBER }}>
            Live demo
          </p>
          <h2 className="font-display text-3xl font-semibold tracking-tight sm:text-4xl" style={{ color: marketing.textPrimary }}>
            See what&apos;s actually running
          </h2>
          <p className="mt-4 text-base" style={{ color: marketing.textMuted }}>
            Real scan results from real domains. No sign-up required.
          </p>
        </motion.div>

        {/* example tabs */}
        <div className="mb-6 flex gap-2">
          {EXAMPLES.map((ex, i) => (
            <button
              key={ex.label}
              onClick={() => { setSelected(i); setCustomResult(null); setShowCapture(false); setError429(false); }}
              className="rounded-lg px-4 py-2 text-sm font-medium transition-all"
              style={{
                background: selected === i ? AMBER : marketing.surface,
                color: selected === i ? "#000" : marketing.textMuted,
                border: `1px solid ${selected === i ? AMBER : marketing.border}`,
              }}
            >
              {ex.label}
            </button>
          ))}
          <span className="ml-auto flex items-center text-xs" style={{ color: marketing.textFaint }}>
            Sample output
          </span>
        </div>

        {/* result panel */}
        <AnimatePresence mode="wait">
          {displayResult && (
            <motion.div
              key={selected !== null ? `ex-${selected}` : "custom"}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
            >
              <ResultPanel result={displayResult} />
              {displayResult.reachable && displayResult.cbom && displayResult.cbom.components.length > 0 && (
                <CbomPanel cbom={displayResult.cbom} domain={displayResult.domain} />
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* post-result lead capture */}
        <AnimatePresence>
          {showCapture && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4, delay: 0 }}
              className="mt-4 flex items-center justify-between rounded-xl px-5 py-4"
              style={{
                // item 12: invitation box — no left border, warm surface, inviting tone
                border: `1px solid ${marketing.borderStrong}`,
                background: AMBER_TINT,
              }}
            >
              <p className="text-sm" style={{ color: marketing.textPrimary }}>
                Want this as a PDF, or continuous monitoring of this domain? Request early access.
              </p>
              <GlowButton href="/register" className="ml-4 shrink-0 px-4 py-2">
                Create free account →
              </GlowButton>
            </motion.div>
          )}
        </AnimatePresence>

        {/* divider */}
        <div className="relative my-10 flex items-center gap-4">
          <div className="flex-1" style={{ height: 1, background: marketing.border }} />
          <span className="text-xs" style={{ color: marketing.textFaint }}>or try your own</span>
          <div className="flex-1" style={{ height: 1, background: marketing.border }} />
        </div>

        {/* custom domain input */}
        <form onSubmit={handleScan} className="flex gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="yourcompany.com"
            className="flex-1 rounded-lg px-4 py-3 text-sm outline-none"
            style={{
              background: marketing.surface,
              border: `1px solid ${marketing.borderStrong}`,
              color: marketing.textPrimary,
            }}
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-lg px-6 py-3 text-sm font-semibold transition-all disabled:opacity-60"
            style={{ background: AMBER, color: "#000" }}
          >
            {loading ? "Scanning…" : "Scan"}
          </button>
        </form>

        {/* loading steps */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mt-4 space-y-1 font-mono text-sm"
            >
              {LOADING_STEPS.slice(0, loadingStep + 1).map((step, i) => (
                <motion.p
                  key={i}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  style={{ color: i === loadingStep ? AMBER : marketing.textFaint }}
                >
                  {i === loadingStep ? "▶ " : "✓ "}{step}
                </motion.p>
              ))}
            </motion.div>
          )}
        </AnimatePresence>

        {/* 429 error — item 12: friction box, 4px accent left border, warm tint */}
        {error429 && (
          <div className="mt-4 flex items-center justify-between rounded-xl px-5 py-4"
            style={{
              border: `1px solid ${marketing.borderStrong}`,
              borderLeft: `4px solid ${AMBER}`,
              background: AMBER_TINT,
            }}>
            <p className="text-sm" style={{ color: marketing.textPrimary }}>
              You&apos;ve reached the free scan limit.
            </p>
            <GlowButton href="/register" className="ml-4 shrink-0 px-4 py-2">
              Sign up for unlimited scanning
            </GlowButton>
          </div>
        )}
      </div>
    </section>
  );
}
