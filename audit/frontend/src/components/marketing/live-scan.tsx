"use client";

import Link from "next/link";
import { useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { agilityTier, cn } from "@/lib/utils";
import { downloadJson } from "@/lib/domain";
import { gsap, useGSAP, MOTION_QUERIES } from "@/lib/gsap";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/field";
import { StatusChip } from "@/components/ui/marks";
import { IconDownload, IconScan } from "@/components/icons";

type CbomComponent = {
  algorithm: string;
  algorithm_family: string;
  location_detail: string;
  quantum_status: string;
  threat_timeline: string;
  recommended_algorithm: string;
  hndl_risk?: boolean;
};
type ScanResult = {
  domain: string;
  reachable: boolean;
  tls_version?: string | null;
  cert_algorithm?: string | null;
  cert_expiry_date?: string | null;
  key_exchange?: string | null;
  hybrid_status?: string | null;
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
  scanned_at?: string;
  error?: string;
  error_category?: string;
  message?: string;
  cbom?: { components: CbomComponent[]; cyclonedx?: unknown } | null;
};

// Captured with the seqr-scanner active ML-KEM probe on 2026-06-28 and frozen here.
// Real measured values; refresh by re-running the scanner against these domains.
const EXAMPLES: ScanResult[] = [
  {
    domain: "razorpay.com",
    reachable: true,
    tls_version: "TLS_1_3",
    cert_algorithm: "RSA-2048",
    key_exchange: "X25519",
    hybrid_status: "hybrid",
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
    scanned_at: "2026-06-28T00:00:00Z",
    cbom: {
      components: [
        { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "razorpay.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing), ML-KEM-768 (key exchange)" },
        { algorithm: "X25519", algorithm_family: "ECC", location_detail: "razorpay.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "planned", recommended_algorithm: "ML-KEM-768" },
      ],
    },
  },
  {
    domain: "billdesk.com",
    reachable: true,
    tls_version: "TLS_1_2",
    cert_algorithm: "RSA-2048",
    key_exchange: "ECDHE",
    hybrid_status: "none",
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
    scanned_at: "2026-06-28T00:00:00Z",
    cbom: {
      components: [
        { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "billdesk.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing), ML-KEM-768 (key exchange)" },
        { algorithm: "ECDHE", algorithm_family: "ECC", location_detail: "billdesk.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-KEM-768" },
      ],
    },
  },
  {
    domain: "instamojo.com",
    reachable: true,
    tls_version: "TLS_1_2",
    cert_algorithm: "RSA-2048",
    key_exchange: "RSA",
    hybrid_status: "none",
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
    scanned_at: "2026-06-28T00:00:00Z",
    cbom: {
      components: [
        { algorithm: "RSA-2048", algorithm_family: "RSA", location_detail: "instamojo.com:443 (cert)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-DSA-65 (signing), ML-KEM-768 (key exchange)" },
        { algorithm: "RSA", algorithm_family: "RSA", location_detail: "instamojo.com:443 (key exchange)", quantum_status: "vulnerable", threat_timeline: "urgent", recommended_algorithm: "ML-KEM-768 with forward secrecy" },
      ],
    },
  },
];

const STEPS = ["Resolving DNS", "Establishing TLS handshake", "Inspecting certificate chain", "Running active ML-KEM probe", "Analysing algorithms"];
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function verdict(r: ScanResult): { label: string; tone: "immediate" | "urgent" | "hybrid" | "safe"; line: string } {
  if (r.scan_target === "edge" && (r.deployment_level ?? 0) >= 3)
    return { label: "Edge only", tone: "hybrid", line: "Hybrid post-quantum at the CDN edge. The certificate is classical and the origin is not assessed, so this is not end-to-end." };
  if (r.pqc_active_supported) return { label: "Hybrid", tone: "hybrid", line: "Hybrid post-quantum key exchange negotiated. The certificate still needs a post-quantum plan." };
  if ((r.crypto_agility_score ?? 0) < 3) return { label: "Migration required", tone: "immediate", line: "Legacy key exchange without forward secrecy. Recorded traffic is exposed to harvest now, decrypt later." };
  return { label: "Migration required", tone: "urgent", line: "Modern classical TLS. Not a current threat, but every algorithm here has a post-quantum replacement to plan for." };
}

export function LiveScan() {
  const root = useRef<HTMLElement>(null);
  const [selected, setSelected] = useState<number | null>(0);
  const [domain, setDomain] = useState("");
  const [custom, setCustom] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const result = custom ?? (selected != null ? EXAMPLES[selected] : null);
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const valid = DOMAIN_RE.test(clean);

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap.from(".ls-head > *", { opacity: 0, y: 14, stagger: 0.1, duration: 0.7, scrollTrigger: { trigger: root.current, start: "top 70%" } });
      });
      return () => mm.revert();
    },
    { scope: root }
  );

  async function scan(e?: React.FormEvent) {
    e?.preventDefault();
    setTouched(true);
    if (!valid || loading) return;
    setError(null);
    setCustom(null);
    setSelected(null);
    setLoading(true);
    setStep(0);
    const tick = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 1400);
    try {
      const res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: clean }) });
      const data = (await res.json().catch(() => ({}))) as ScanResult;
      if (res.status === 429) {
        const after = res.headers.get("retry-after");
        setError(`Too many scans from your network. ${after ? `Try again in ${after} seconds.` : "Wait a minute and try again."}`);
      } else if (!res.ok || data.error || data.reachable === false) {
        setError(data.message || "The scan did not complete. The host may be blocking probes or is unreachable.");
      } else {
        setCustom({ ...data, domain: data.domain || clean, scanned_at: new Date().toISOString() });
      }
    } catch {
      setError("Network error. Check your connection and try again.");
    } finally {
      clearInterval(tick);
      setLoading(false);
    }
  }

  return (
    <section id="try-it-live" ref={root} className="border-b border-ink">
      <div className="mx-auto max-w-page px-5 py-24 sm:px-8 lg:py-32">
        <div className="ls-head grid gap-6 lg:grid-cols-[1fr_1fr] lg:items-end">
          <div>
            <p className="eyebrow">Live scan · 04</p>
            <h2 className="mt-5 font-display text-[clamp(2.4rem,5vw,4.25rem)] leading-[0.98] text-ink">Inspect any domain.</h2>
          </div>
          <p className="max-w-lg text-[17px] leading-relaxed text-ink-2 lg:justify-self-end">
            The same scanner the platform uses, run against the public internet. Pick a recorded example or type a domain. Results take five to
            forty seconds.
          </p>
        </div>

        <div className="mt-12 grid gap-10 lg:grid-cols-[360px_1fr]">
          <div className="space-y-8">
            <form onSubmit={scan} noValidate>
              <label htmlFor="scan-domain" className="eyebrow mb-2 block">
                Domain
              </label>
              <div className="flex">
                <Input
                  id="scan-domain"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  onBlur={() => setTouched(true)}
                  placeholder="yourbank.in"
                  spellCheck={false}
                  autoCapitalize="off"
                  aria-invalid={touched && !!domain && !valid}
                  className="h-12 border-ink font-mono text-base"
                />
                <Button type="submit" size="lg" className="-ml-px shrink-0" pending={loading} pendingLabel="Scanning" disabled={!domain.trim()}>
                  <IconScan size={16} /> Scan
                </Button>
              </div>
              {touched && domain && !valid && <p className="mt-2 text-xs text-immediate">Enter a bare domain such as example.com.</p>}
            </form>

            <div>
              <p className="eyebrow mb-2">Recorded examples</p>
              <div className="flex flex-col border-t border-ink">
                {EXAMPLES.map((ex, i) => {
                  const on = selected === i && !custom && !loading;
                  return (
                    <button
                      key={ex.domain}
                      onClick={() => {
                        setSelected(i);
                        setCustom(null);
                        setError(null);
                      }}
                      aria-pressed={on}
                      className={cn(
                        "flex items-center justify-between border-b border-rule px-3 py-3 text-left transition-colors duration-micro",
                        on ? "bg-ink text-bg" : "text-ink hover:bg-surface"
                      )}
                    >
                      <span className="font-mono text-sm">{ex.domain}</span>
                      <span className={cn("font-mono text-[11px]", on ? "text-bg/70" : "text-ink-3")}>{ex.deployment_level_name}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {loading && (
              <ol className="border-l border-ink" aria-live="polite">
                {STEPS.map((s, i) => (
                  <li key={s} className="relative py-2 pl-5 text-sm">
                    <span className={cn("absolute -left-[5px] top-[13px] h-2 w-2", i < step ? "bg-ink" : i === step ? "animate-skeleton bg-accent" : "border border-rule bg-bg")} />
                    <span className={i > step ? "text-ink-3" : "text-ink"}>{s}</span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          <div className="min-w-0">
            <AnimatePresence mode="wait">
              {error ? (
                <motion.div key="err" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} role="alert" className="border border-immediate p-8">
                  <p className="eyebrow text-immediate">Scan did not complete</p>
                  <p className="mt-3 font-display text-2xl text-ink">{clean || "This domain"}</p>
                  <p className="mt-2 max-w-lg text-sm text-ink-2">{error}</p>
                  <Button variant="secondary" className="mt-6" onClick={() => scan()}>
                    Try again
                  </Button>
                </motion.div>
              ) : loading ? (
                <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="border border-ink p-8" role="status" aria-label="Scanning">
                  <span className="block h-3 w-40 animate-skeleton bg-surface-2" />
                  <span className="mt-5 block h-10 w-72 animate-skeleton bg-surface-2" />
                  <div className="mt-8 grid grid-cols-2 gap-4">
                    {Array.from({ length: 8 }).map((_, i) => (
                      <span key={i} className="block h-4 animate-skeleton bg-surface-2" style={{ width: `${55 + ((i * 17) % 40)}%` }} />
                    ))}
                  </div>
                </motion.div>
              ) : result ? (
                <motion.div key={result.domain + (custom ? "live" : "rec")} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.35, ease: [0.2, 0, 0, 1] }}>
                  <Certificate r={result} live={!!custom} onAnother={() => {
                    setCustom(null);
                    setSelected(null);
                    setDomain("");
                    document.getElementById("scan-domain")?.focus();
                  }} />
                </motion.div>
              ) : (
                <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex h-full min-h-[320px] items-center justify-center border border-dashed border-rule p-8 text-center text-sm text-ink-3">
                  Enter a domain or pick an example to see its inspection certificate.
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}

function Certificate({ r, live, onAnother }: { r: ScanResult; live: boolean; onAnother: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const v = verdict(r);
  const tier = agilityTier(r.crypto_agility_score);
  const comps = r.cbom?.components ?? [];

  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_QUERIES.full, () => {
        gsap
          .timeline()
          .from(".cert-row", { opacity: 0, x: -10, stagger: 0.05, duration: 0.35, ease: "instrument" })
          .from(".cert-stamp", { scale: 1.35, rotate: -8, opacity: 0, duration: 0.5, ease: "press" }, 0.35)
          .from(".cert-finding", { opacity: 0, y: 6, stagger: 0.08, duration: 0.35 }, 0.5);
      });
      return () => mm.revert();
    },
    { scope: ref, dependencies: [r], revertOnUpdate: true }
  );

  const toneCls = { immediate: "border-immediate text-immediate", urgent: "border-urgent text-urgent", hybrid: "border-hybrid text-hybrid", safe: "border-safe text-safe" }[v.tone];

  const rows: [string, string][] = [
    ["TLS version", r.tls_version?.replace(/_/g, ".").replace("TLS.", "TLS ") ?? "n/a"],
    ["Certificate", r.cert_algorithm ?? "n/a"],
    ["Key exchange", r.key_exchange ?? "n/a"],
    ["PQC, active probe", r.pqc_active_supported ? r.pqc_active_group ?? "supported" : "not offered"],
    ["Deployment", r.deployment_level_name ?? "n/a"],
    ["CDN", r.cdn_detected ? r.cdn_provider ?? "detected" : "none"],
    ["Scanned", `${r.scan_target === "edge" ? "CDN edge" : "direct to host"}${r.scan_duration_ms ? ` in ${(r.scan_duration_ms / 1000).toFixed(1)} s` : ""}`],
  ];

  return (
    <div ref={ref} className="relative border-2 border-ink bg-bg">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink px-6 py-3">
        <span className="eyebrow text-ink">Inspection certificate</span>
        <span className="font-mono text-[11px] text-ink-3">
          {live ? "Live scan" : "Recorded 28 June 2026"} · SeQr scanner
        </span>
      </div>
      <div className="grid gap-8 p-6 md:grid-cols-[1fr_200px]">
        <div className="min-w-0">
          <p className="font-display text-[clamp(2rem,4vw,3rem)] leading-none text-ink">{r.domain}</p>
          <dl className="mt-6 border-t border-rule">
            {rows.map(([k, val]) => (
              <div key={k} className="cert-row grid grid-cols-[150px_1fr] border-b border-rule py-2">
                <dt className="eyebrow self-center">{k}</dt>
                <dd className="font-mono text-sm text-ink">{val}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="flex flex-col items-start gap-5 md:items-end md:text-right">
          <div className={cn("cert-stamp border-[3px] px-3 py-2 font-mono text-sm font-medium uppercase tracking-[0.12em]", toneCls)} style={{ transform: "rotate(-3deg)" }}>
            {v.label}
          </div>
          <div>
            <p className="eyebrow">Crypto agility</p>
            <p className="mt-1 font-display text-5xl leading-none text-ink tabular">
              {(r.crypto_agility_score ?? 0).toFixed(1)}
              <span className="text-base text-ink-3"> / 10</span>
            </p>
            <p className="mt-1 font-mono text-[11px] text-ink-3">{tier.label}</p>
          </div>
        </div>
      </div>
      <p className="border-t border-rule px-6 py-4 text-sm text-ink-2">{v.line}</p>

      {comps.length > 0 && (
        <div className="border-t border-ink">
          <p className="eyebrow px-6 pt-4">Findings · {comps.length}</p>
          <div className="overflow-x-auto px-6 pb-2">
            <table className="w-full min-w-[620px] text-[13px]">
              <thead>
                <tr className="border-b border-rule">
                  {["Algorithm", "Location", "Status", "Timeline", "Replace with"].map((h) => (
                    <th key={h} className="eyebrow py-2 pr-4 text-left font-normal">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {comps.map((c, i) => (
                  <tr key={i} className="cert-finding border-b border-rule last:border-0">
                    <td className="py-2.5 pr-4 font-mono text-ink">{c.algorithm}</td>
                    <td className="py-2.5 pr-4 font-mono text-ink-2">{c.location_detail}</td>
                    <td className="py-2.5 pr-4">
                      <StatusChip value={c.quantum_status} />
                    </td>
                    <td className="py-2.5 pr-4">
                      <StatusChip value={c.threat_timeline} />
                    </td>
                    <td className="py-2.5 font-mono text-ink">{c.recommended_algorithm.replace(/\s*\/\s*/g, ", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-ink px-6 py-4">
        <Button
          variant="secondary"
          size="sm"
          disabled={!r.cbom}
          onClick={() => r.cbom && downloadJson(r.cbom.cyclonedx ?? r.cbom, `seqr-cbom-${r.domain.replace(/[^a-z0-9.-]/gi, "_")}.cdx.json`)}
        >
          <IconDownload size={14} /> Download CBOM (JSON)
        </Button>
        <Button variant="ghost" size="sm" onClick={onAnother}>
          Scan another
        </Button>
        <Button asChild size="sm" className="ml-auto">
          <Link href="/register">Get the full audit</Link>
        </Button>
      </div>
    </div>
  );
}
