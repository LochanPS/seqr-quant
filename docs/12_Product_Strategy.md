# SeQr — Product Strategy & Honest Assessment (2026-07)

Working strategy doc. Captures the reality check + direction agreed in the 2026-07 review.
Not marketing copy — internal truth.

---

## 1. Where we actually are

**What we built:** a *diagnosis* tool. Scan a domain/SSH/mail/DB endpoint → measure its TLS
crypto posture → classify quantum exposure → produce a CBOM + compliance mapping + PDF.
Plus a genuinely novel research insight (passive scanning misses PQC; the PQC that exists is
a CDN-edge mirage) and a credibility asset (the measurement paper).

**What we have NOT built:** the cure. We stop at "here's what's vulnerable and the
recommended replacement." We don't help them *migrate*, and we don't *verify* the fix.

## 2. Is it a real product? What's it worth?

The problem is real and regulator-forced (PCI DSS 12.3.3 + SEBI CSCRF are live mandates for a
cryptographic inventory). The accuracy insight is real. **But diagnosis-only has a
willingness-to-pay ceiling** — a CISO reads the report and asks "now what?"

As-is, honest value: a compliance-checkbox + monitoring tool, ~₹1–4L/yr to a mid fintech.
Not the premium tiers (₹8–15L). Three things move it up:

- **Auditor-grade evidence** (mapped, timestamped, defensible — not just a PDF).
- **Continuous monitoring** (crypto drifts; a one-time scan is a consulting deliverable, not
  SaaS — recurring value requires recurring measurement + diffing + alerts).
- **The remediation bridge** (§3).

## 3. The value ladder + the remediation bridge (the missing half)

**Discover → Inventory → Prioritize → Migrate → Verify → Monitor.**
We stop at *Prioritize*. Retention, expansion revenue, and the moat live in *Migrate + Verify*:

- Per-finding **migration playbooks** — CDN toggle steps, nginx/TLS config generators with
  hybrid groups (X25519MLKEM768), certificate-issuance guidance, origin-hardening steps.
- **Verify-by-rescan** — re-measure and prove the fix worked. This is what makes it sticky.
- **SeQr Gateway** (deferred NGINX PQC terminator) — the actual "make it quantum-safe" box.
  A product, not a report.

Building the bridge is the difference between a scanner and a platform. It is priority #1.

## 4. Architecture problems (ranked)

1. **Data-residency contradiction (biggest).** We sell Indian sovereignty (DPDP, AWS Mumbai
   ap-south-1) but the live SaaS is on **Render Singapore**. A sharp CISO will catch it.
   Fix: AWS Mumbai for the real SaaS, or lead with on-prem. This is positioning *and*
   compliance risk.
2. **Synchronous/eager scan pipeline** — fine for demos, won't scale to enterprise
   inventories. Needs a real job queue + workers (see #16 hardening roadmap).
3. **CBOM depth.** External scanning ≠ enterprise CBOM — it misses internal keys, HSMs, code,
   and certificate stores. Real inventory needs an on-prem/agent discovery mode. Architectural.
4. **Enterprise table-stakes not built:** SSO, RBAC depth, audit logging, backups, and
   SIEM/GRC/ticketing integrations.
5. **Scanner accuracy/reliability** — origin assessment, CDN-detection confidence, error
   taxonomy (see docs/11).

## 5. Frontend strategy

Split the investment:
- **Marketing site → go big.** Scroll-driven storytelling (the 0%→60% mirage reveal),
  rich motion, a distinctive on-brand background — this converts the credibility we have.
  **No lattice WebGL** (never renders well; brittle). Use performant 2D/CSS/SVG/canvas motion.
- **Dashboard → stay clean.** Security buyers distrust flashy dashboards. Fast, dense,
  trustworthy > animated. Polish, not spectacle.

Animations win the demo; depth + remediation win the renewal. A gorgeous frontend on a
diagnosis-only tool still churns.

## 6. Product line (future)

- **SeQr Gateway** — NGINX PQC termination = the remediation product. High value.
- **pqcmap SDK** — code-level crypto migration.
- **GitHub App** — CI/CD crypto gating; the developer wedge.
- **Continuous crypto-agility monitoring** — the recurring-revenue layer.

## 7. The govt / air-gapped flagship play

Potentially the strongest India play, and we're close: on-prem Docker + offline Ed25519
licensing already exist. A fully air-gapped, zero-egress, made-in-India crypto-compliance
appliance for RBI / SEBI / PSUs / defence / CII carries a sovereignty premium, rides the
regulatory tailwind, and faces far less competition.

Trade-offs: long sales cycles; needs credibility (paper, pilots, likely CERT-In empanelment /
STQC). **Consider the air-gapped appliance as the flagship, with SaaS as the SMB/mid funnel
that feeds it.**

## 8. Prioritized roadmap (leverage order) — updated 2026-07

Direction finalized (see [`docs/13_Platform_Spine_PRD.md`](13_Platform_Spine_PRD.md)). The
remediation bridge is **no longer on hold** — but it's reframed. "Guide + verify" are not
products; they become internal steps of a real **migration engine**, and the whole line sits on a
shared **spine** (state graph + policy engine). Ecosystem: Discover → CBOM → Migrate → SDK → CI → Attest.

1. **Platform spine** — crypto-asset state graph (CBOM → persistent DB) + declarative policy
   engine. Build FIRST; everything else is a verb against policy. [NEXT]
2. **Deep-discovery agent** — on-prem infra inventory (hosts, cert stores, TLS endpoints, HSMs,
   internal PKI, load balancers, reverse proxies). Code repos excluded (SDK/CI own those).
3. **Migration engine** — signed change bundle + runbook, infra-first; converges actual → policy.
4. **pqcmap SDK** — enforce policy in application code.
5. **CI gate / app** — block drift from policy; developer wedge.
6. **Attestation** — signed posture snapshots + policy-compliance certificates + migration history.
7. **Data residency** — AWS Mumbai, or reframe around on-prem. Kills the contradiction.
8. Enterprise table-stakes (SSO/RBAC/audit) — as deals require.

On-prem / air-gapped appliance is the flagship (§7); SaaS is the funnel. Same engine, one codebase —
differentiate by deployment/governance/scale, not crippled features.

Cross-cutting rule: every customer-facing claim stays evidence-based (measured, not inferred).
