# SeQr — Post-Quantum Cryptography Assessment & Migration Platform

> **Source of truth.** This README is a maintained, external-safe overview of what SeQr is,
> what is built, and where it is going. For internal build rules and per-session context see
> [`CLAUDE.md`](CLAUDE.md); for GTM/marketing copy see [`MARKETING.md`](MARKETING.md).
> Last updated: 2026-07.

SeQr finds every quantum-vulnerable system in your infrastructure, builds the cryptographic
inventory (CBOM) that PCI DSS and SEBI already ask auditors to see, and is growing into the
platform that **migrates** you to post-quantum crypto and **proves** you stayed there.

Built for Indian financial services first. On-prem / air-gapped is the flagship; SaaS is the funnel.

---

## The problem, measured

We actively measured the TLS crypto behind 60+ Indian financial-services endpoints
(see the research paper). The headline:

- **Passive scanners report 0% post-quantum. Active probing shows 60%.**
- That 60% is a **CDN-edge mirage** — switched on by CloudFront/Cloudflare defaults, not a decision.
- **100% of certificates stay classical** (RSA/ECDSA).
- **51% of firms expose a non-CDN origin** (api., dev., sftp., mail. on raw IPs) that routes
  *around* the edge protection entirely (95% CI 42–60, n=118).
- **0% are end-to-end quantum-safe.**

Diagnosis alone has a ceiling — a CISO reads the report and asks *"now how do I fix it?"*
That question is the rest of this roadmap.

---

## Compliance hooks (accurate framing — see [`docs/09_Compliance_Frameworks.md`](docs/09_Compliance_Frameworks.md))

| Framework | Status | Hook |
|---|---|---|
| **PCI DSS 12.3.3** | **Live — mandatory since 2025-03-31** | Card-data environments must keep a documented cryptographic inventory, reviewed annually. |
| **SEBI CSCRF (PQC)** | **Live since Jun 2025 — binding on SEBI REs** | Regulated entities must inventory crypto assets and prioritise PQC migration by risk. |
| RBI Q-SAFE | Emerging — framework expected ~Nov 2026 | Financial-sector crypto review via CBOM + crypto-agility. |
| DST Task Force | **Recommendatory** — CII crypto inventory by 2027 | A by-2027 inventory milestone, **not** a statutory filing deadline. CII includes BFSI. |
| DPDP Act 2023 §8 | Future-dated — enforceable 2027-05-13 | Penalties up to ₹250 Cr for failing to protect PII in transit. |

> **CNSA 2.0 is excluded** — it governs US National Security Systems only and never appears in
> SeQr's Indian compliance output.

---

## The platform vision — one lifecycle, one spine

A company onboards once and SeQr carries them across the full quantum-readiness lifecycle:

```
Discover → Inventory (CBOM) → Prioritise → Migrate → Enforce (code) → Guard (CI) → Attest
```

Every stage reads and writes **one shared substrate** — this is what makes it a platform, not a
bag of tools:

1. **Crypto-asset state graph** — the CBOM as a living database (assets, crypto, owners,
   dependencies, *desired vs actual* state, history), not a per-scan export.
2. **Declarative policy engine** — "quantum-safe" defined once as policy. Every product is then
   one verb against that policy: scan = *measure*, migrate = *converge*, SDK = *enforce*,
   CI gate = *block*, monitor = *alert*.

---

## Build status

| Component | State |
|---|---|
| `shared-scanner` (seqr-scanner) — TLS/code/SSH/mail scanning, risk, CBOM, compliance | ✅ Complete (462 tests) |
| `seqr` CLI — scan / explain / migrate / history, air-gap capable | ✅ Complete (52 tests) |
| Audit backend — FastAPI + Celery, auth, assets, scans, CBOM, compliance, PDF, Ed25519 licensing | ✅ Complete (~96 tests) |
| Audit frontend — Next.js 14 marketing site + dashboard | 🔄 In progress |
| Research paper — active measurement of Indian fintech PQC | ✅ Draft; public data repo |
| **Platform spine** — crypto-asset state graph + policy engine | ⏭ **Next** ([`docs/13`](docs/13_Platform_Spine_PRD.md)) |
| Deep-discovery agent (on-prem, infra inventory) | ⏭ Planned |
| Migration engine (signed bundle + runbook, infra-first) | ⏭ Planned |
| pqcmap SDK (code-level crypto migration) | ⏭ Planned |
| CI gate / GitHub App (regression guard) | ⏭ Planned |
| Attestation (signed compliance artifacts) | ⏭ Planned (last stage) |

---

## Roadmap (leverage order)

0. **Platform spine** — crypto-asset state graph (CBOM → persistent DB) + declarative policy engine. *Foundation; build first.*
1. **Deep-discovery agent** — on-prem inventory of internal crypto (hosts, cert stores, TLS endpoints, HSMs, internal PKI, load balancers, reverse proxies). *The onboarding "assess every front" moment. Code repos are out of scope — those belong to the SDK/CI.*
2. **Migration engine** — turn findings + policy into an executed change: config synthesis (nginx/Apache/HAProxy, Cloudflare/CloudFront/ALB/App Gateway), origin hardening, mTLS, cipher-suite migration. Ships as a **signed change bundle + runbook** the customer's ops applies; the platform re-measures to confirm. Auto-apply is a later, opt-in enterprise capability.
3. **pqcmap SDK** — drop-in hybrid/PQC primitives for crypto that lives in application code.
4. **CI gate / app** — block PRs that regress crypto policy; the developer wedge.
5. **Attestation** — signed, timestamped posture snapshots, policy-compliance certificates, migration history, audit trails. The artifact that satisfies auditors and justifies the enterprise price.

ML-DSA (PQC) certificates are a **future module** — public CAs don't issue them yet; v1 migration
targets hybrid key exchange + origin hardening, not cert signatures.

---

## Deployment models — one engine, one codebase

Same platform; the difference is deployment and operational capability, **not** crippled features.

| Model | For | Notes |
|---|---|---|
| **Enterprise / On-Prem (flagship)** | RBI/SEBI REs, PSUs, defence, CII | Air-gapped, zero egress, internal discovery, HSM/PKI/AD-LDAP integration, HA/DR, RBAC, audit logging, offline Ed25519 licensing. The revenue engine. |
| **SaaS (funnel)** | SMB/mid fintech without a DevOps team | Cloud-hosted, auto-updates, full engine, AWS Mumbai (ap-south-1) — data stays in India. Feeds the on-prem upsell. |
| **CLI + CI** | Individual devs, entry point | `pip install seqr`, air-gap capable. Top of funnel. |

---

## Components

```
seqr-labs/
├── shared-scanner/   seqr-scanner core — TLS + code + SSH + mail scanning, risk, CBOM, compliance
├── cli/              seqr CLI — scan from terminal, air-gap capable
├── audit/            Audit platform — FastAPI + Celery backend, Next.js 14 frontend
├── research/         Measurement study + paper + public dataset
├── docs/             PRDs and reference docs (see index below)
└── gtm/              Go-to-market prospect DB + outreach (private)
```

## Quick start — CLI

```bash
pip install seqr
seqr scan domain yourcompany.com
seqr scan all ./path/to/repo
```

Passive by design (no OpenSSL-3.5 dependency); active ML-KEM probing runs server-side in the platform.

---

## Documentation index

| Doc | Covers |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Internal master context + build rules (source of truth for engineering) |
| [`MARKETING.md`](MARKETING.md) | Consolidated GTM/marketing/sales copy (source of truth for outreach) |
| [`docs/01_Audit_PRD.md`](docs/01_Audit_PRD.md) | Audit backend + frontend |
| [`docs/02_SDK_PRD.md`](docs/02_SDK_PRD.md) | pqcmap SDK |
| [`docs/03_Gateway_PRD.md`](docs/03_Gateway_PRD.md) | PQC gateway (superseded in part by the migration engine) |
| [`docs/04_Research_Paper.md`](docs/04_Research_Paper.md) | Research methodology + paper spec |
| [`docs/05_Business.md`](docs/05_Business.md) | GTM playbook — ⚠ partly stale, see MARKETING.md |
| [`docs/06_CLI_PRD.md`](docs/06_CLI_PRD.md) | seqr CLI |
| [`docs/07_GitHub_App_PRD.md`](docs/07_GitHub_App_PRD.md) | GitHub App / CI gate |
| [`docs/08_Scanner_Roadmap.md`](docs/08_Scanner_Roadmap.md) | Scanner improvements |
| [`docs/09_Compliance_Frameworks.md`](docs/09_Compliance_Frameworks.md) | All frameworks with accurate dates — **compliance source of truth** |
| [`docs/10_Competitive_Analysis.md`](docs/10_Competitive_Analysis.md) | Competitors + positioning |
| [`docs/11_Scanner_Hardening_Roadmap.md`](docs/11_Scanner_Hardening_Roadmap.md) | Scanner reliability |
| [`docs/12_Product_Strategy.md`](docs/12_Product_Strategy.md) | Honest strategy + direction |
| [`docs/13_Platform_Spine_PRD.md`](docs/13_Platform_Spine_PRD.md) | Crypto-asset graph + policy engine + discovery agent |
| [`docs/14_Migration_Engine_PRD.md`](docs/14_Migration_Engine_PRD.md) | Migration engine — converge Actual → Policy |

---

Made in India. Research-backed — every customer-facing number is measured, not inferred.
