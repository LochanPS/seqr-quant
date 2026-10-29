<div align="center">

# SeQr

### Post-Quantum Cryptography — Discover · Rank · Migrate · Prove

**Find every quantum-vulnerable system in your infrastructure, rank it by real-world risk, and migrate it to post-quantum cryptography in a provably safe order — before the quantum horizon arrives.**

[![Live](https://img.shields.io/badge/status-LIVE-3F6B4A?style=flat-square)](https://www.seqrlabs.com)
[![TLS](https://img.shields.io/badge/TLS%201.3-ML--KEM--768%20hybrid-2F5F63?style=flat-square)](https://www.seqrlabs.com)
[![CBOM](https://img.shields.io/badge/CBOM-CycloneDX%201.6-4A6378?style=flat-square)](#core-capabilities)
[![QpiAI](https://img.shields.io/badge/QpiAI-Opt%20%2B%20QCloud-629EA2?style=flat-square)](#qpiai--the-decision-engine)
[![Tests](https://img.shields.io/badge/tests-1000%2B%20passing-3F6B4A?style=flat-square)](#status--testing)

**[🌐 Live platform](https://www.seqrlabs.com)** · **[🔌 API](https://api.seqrlabs.com/api/v1/health)** · **[📊 Live QpiAI run log](https://api.seqrlabs.com/api/v1/remediation/qpiai/log)**

</div>

---

## What is SeQr?

SeQr is a post-quantum cryptography (PQC) platform for financial institutions. RSA and ECC — the
cryptography that protects every bank today — will be broken by a sufficiently large quantum
computer (CRQC). Attackers are already **harvesting encrypted traffic now to decrypt it later**
(HNDL), and banking data must stay secret for a decade or more.

SeQr answers the question a CISO actually asks:

> *"I have thousands of cryptographic assets I can't migrate all at once without breaking payments —
> which do I fix, in what order, and how do I prove it's safe?"*

It runs a single pipeline on a shared crypto-asset graph:

**Discover → Rank (context-aware) → Decide (QpiAI) → Migrate (verification-gated) → Prove (signed attestation).**

> **Try it now:** [www.seqrlabs.com](https://www.seqrlabs.com) · demo login `demo@seqrlabs.com` / `demodemo123`.
> Add any domain or database and scan it — the results are **real** (live TLS handshakes), not canned.

---

## Why SeQr is different

| | What everyone does | **What SeQr does** |
|---|---|---|
| **Risk** | "RSA = bad" — a flat list | **Context-aware risk**: scores each asset by *exposure × data sensitivity × HNDL × blast radius × controls*. A database's RSA is not an internet-facing RSA. |
| **Detection** | Passive scan (can't see hybrid PQC) | **Wire-level active probe**: hand-crafts a TLS 1.3 ClientHello with an ML-KEM-768 key share and reads what the server really negotiates — **no OpenSSL-3.5 dependency, runs anywhere**. |
| **Coverage** | Sees only the CDN edge | **Origin-leakage aware**: 51% of fintech domains expose a non-CDN origin; SeQr scans the real server, not just the edge. |
| **Migration** | A spreadsheet of "to-dos" | **Verification-gated migration**: applies real ML-KEM-768 hybrid, verifies the new handshake, and **auto-rolls-back on failure**. |
| **Prioritization** | Manual / heuristic | **QpiAI quantum optimization**: a genuine constrained HUBO that matches the certified optimum, plus QAOA on a quantum circuit. |
| **Proof** | A PDF | **Signed attestation** (Ed25519) — verifiable offline. |

---

## Core capabilities

### 🔍 Discover — inventory with evidence
- **Code scanner** — tree-sitter AST across Python, JS/TS, Java, Go. Finds RSA/ECC/DH usage with
  **file:line** evidence.
- **Network scanner** — TLS 1.3, certificates, and direct-TLS / STARTTLS services: HTTPS, PostgreSQL,
  MySQL, MongoDB, AMQP, gRPC, SMTP/IMAP/POP3, SSH, HSM.
- **Wire-level PQC probe** (`shared-scanner/scanner/wire_probe.py`) — our own TLS 1.3 ML-KEM
  ClientHello; detects `X25519MLKEM768` hybrid key exchange without any system OpenSSL dependency.
- **CBOM** — exports a CycloneDX 1.6 Cryptographic Bill of Materials.

### 📊 Rank — context-aware risk engine (`risk_v2`)
Every crypto asset is scored, not just flagged:

```
score = algorithm × role × exposure × data-sensitivity × HNDL × code-reality × blast-radius × controls
tiers:  IMMEDIATE (≥70) · URGENT (≥45) · PLANNED (≥20) · MONITOR
```
An internet-facing, harvest-now-decrypt-later key exchange ranks far above the same algorithm sitting
inside a segmented internal database. HNDL scoring applies only to key exchange / encryption on
long-lived data over reachable channels — with the standard disclaimer always shown.

### ⚛️ Decide — QpiAI optimization → *see [below](#qpiai--the-decision-engine)*

### 🔁 Migrate — verification-gated, with rollback
Real ML-KEM-768 hybrid key exchange is applied, the new handshake is **verified** (tampered and
forged handshakes are rejected), and a failed migration is **automatically rolled back** — so payment
services never go down mid-migration. This is PQC-01's "verification-gated" requirement, implemented.

### 🔐 Prove — compliance & attestation
- **Compliance mapping** — PCI DSS 12.3.3, SEBI CSCRF, RBI Q-SAFE, DST Task Force, DPDP Act.
- **Signed attestation** — an Ed25519-signed posture certificate, verifiable offline
  (`seqr verify-attestation`).

---

## QpiAI — the decision engine

> SeQr uses **both** QpiAI products for the *real* decision, not decoration.

### QpiAI Opt (HUBO) — which fixes, in what order
Given an engineer-hour budget, QpiAI Opt chooses the fixes that remove the most quantum risk, and the
safe migration wave order. It is a **genuine higher-order (HUBO)** problem: fixes overlap (e.g.
*lock-origin × hybrid-KEX × full-migrate* all cover the same slot → real degree-3 terms), and the
budget is encoded **exactly with slack qubits** (a Lagrangian penalty provably can't represent it).

**Verified live:** matches the **certified optimum (gap 0.00)**, removes **60.2%** of the risk at a
24-hour budget, and **beats a greedy heuristic by 15.5**.

### QpiAI QCloud (QAOA) — the quantum experiment
A CVaR-QAOA circuit (warm-started from the Opt plan) samples alternative feasible plans on the QpiAI
simulator. We report the result **honestly**: amplification ≈ ×1 (no advantage at 12 qubits) — a
correctly-run experiment, measured, not overclaimed.

**See it live:** every plan run on the website appends a branded, real log line here →
**[api.seqrlabs.com/api/v1/remediation/qpiai/log](https://api.seqrlabs.com/api/v1/remediation/qpiai/log)**

```
[QpiAI Opt] Received remediation request from website
[QpiAI Opt] Source: org-graph | 9 findings | budget 24.0h | total risk 524.7
[QpiAI Opt] Building constrained HUBO (overlapping fixes -> higher-order terms)
[QpiAI Opt] Solver status: OPTIMAL | residual 208.9 | 60.2% risk removed
[QpiAI QCloud] QAOA on 12 qubits | P(optimum) 0.017 vs uniform 0.016
```

---

## Architecture

```
                         ┌─────────────────────────────────────────────┐
  Code / TLS / DBs /     │                   SeQr                        │
  certs / SSH / HSM  ──▶ │                                               │
                         │  Scanner ─▶ Spine ─▶ Risk v2 ─▶ Remediation   │
  (tree-sitter AST,      │  (AST +    (crypto-   engine    API  [QpiAI]  │
   sslyze, wire-probe)   │  network)  asset                              │
                         │            graph)                    │        │
                         │                                      ▼        │
                         │  Attestation ◀── Dashboard ◀── Next.js UI     │
                         │  (Ed25519)       (posture, planner, CBOM)     │
                         └───────────┬───────────────────────────────────┘
       runtime:  Celery worker (async scans) · Redis · PostgreSQL · Caddy (auto-TLS)
       hosting:  AWS EC2 (Mumbai, ap-south-1)  →  https://www.seqrlabs.com
```

**Tech stack**

| Layer | Technology |
|---|---|
| PQC | ML-KEM-768 hybrid (`X25519MLKEM768`), ML-DSA, `cryptography` + OpenSSL 3.5 |
| Scanning | tree-sitter AST, sslyze 6.3.1, custom wire-level ML-KEM probe |
| **Optimization** | **QpiAI Opt** (`qpiai-opt[quantum]`) · **QpiAI QCloud** (`qpiai-quantum`) |
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), Celery + Redis, Alembic |
| Frontend | Next.js 14, TypeScript, Tailwind CSS (Fraunces / IBM Plex "instrument of record" design) |
| Data / standards | PostgreSQL 16, CycloneDX 1.6 CBOM, Ed25519 attestation |
| Infra | Docker Compose, AWS EC2 ap-south-1, Caddy (automatic Let's Encrypt TLS) |

---

## Quickstart

### Use the live platform
Open **[www.seqrlabs.com](https://www.seqrlabs.com)** → sign in `demo@seqrlabs.com` / `demodemo123`.
Add a domain or database under **Assets**, scan it, and watch it rank on the **Overview** page.
Run a plan on the **Remediation** page to see QpiAI Opt in action.

### Run it locally (no Docker)
```bat
:: backend  — SQLite + in-memory Redis + inline scans, seeds a demo bank
scripts\run-local-backend.cmd

:: frontend — dashboard at http://localhost:3000
scripts\run-local-frontend.cmd
```

### Share a public demo link (no hosting needed)
```bat
scripts\run-local-backend.cmd
scripts\run-public-frontend.cmd
scripts\run-public-tunnel.cmd     :: prints a public https://…trycloudflare.com URL
```

### CLI
```bash
seqr scan code <path> --ranked           # code inventory, context-ranked, file:line
seqr scan domain example.com             # live TLS / PQC posture
seqr scan all --path <repo>              # full inventory + CBOM
seqr verify-attestation <file>           # offline-verify a signed posture certificate
```

---

## Status & testing

- **Live in production** on AWS (Mumbai) at [seqrlabs.com](https://www.seqrlabs.com) with automatic HTTPS.
- **1,000+ automated tests passing:** 561 scanner · 284 backend · 169 CLI.
- Real measurements, not mocks: `cloudflare.com` → hybrid PQC, `github.com` → classical, `badssl.com`
  → static RSA — each result is a live handshake.

---

## Compliance

| Framework | Status | Hook |
|---|---|---|
| **PCI DSS 12.3.3** | Live (mandatory since 2025-03-31) | Documented cryptographic inventory, reviewed annually |
| **SEBI CSCRF** | Live (since Jun 2025) | Crypto-asset inventory + risk-prioritized PQC migration |
| RBI Q-SAFE | Emerging (~Nov 2026) | Financial-sector crypto review via CBOM + crypto-agility |
| DST Task Force | Recommendatory | CII crypto inventory by 2027 (BFSI is in scope) |
| DPDP Act §8 | Future-dated (2027-05-13) | Protect PII against interception |

> **HNDL disclaimer:** HNDL exposure scores are predictive cryptographic risk metrics based on
> data-type endurance, **not** indicators of active data interception or confirmed breaches.
> Indian compliance output never includes US-only CNSA 2.0.

---

## Repository layout

```
seqr-quant/
├── shared-scanner/     # scanner engine: AST (code.py), network, wire_probe, risk_v2, CBOM
├── cli/                # `seqr` CLI
├── audit/
│   ├── backend/        # FastAPI + Celery; risk, remediation (QpiAI), migration, attestation
│   └── frontend/       # Next.js 14 dashboard
├── deploy/aws/         # production Docker Compose, Caddy, bootstrap
├── docs/               # PRDs, compliance, demo script, PPT brief
└── examples/           # sample reports & CBOMs
```

---

## Security & responsible use

- **Multi-tenant isolation** — every API route is org-scoped; cross-tenant data access is tested.
- **The scanner is non-intrusive** — it performs the same TLS handshake a browser does; it
  authenticates nothing and extracts no private keys. Origin recon runs only on an org's own assets.
- **No secrets in the repo** — API keys live only in a git-ignored `.env`.

---

## Team

**Potato Rangers** — Team Lead: **P S Lochan** · Track: **Post-Quantum Cryptography (PQC)**
Founder, SeQr Labs (pre-incorporation) · IBM Qiskit Advocate · founder, Quantum Collective India.

---

<div align="center">

**SeQr** — *the quantum horizon is coming. Be ready, and prove it.*

[Live platform](https://www.seqrlabs.com) · [API health](https://api.seqrlabs.com/api/v1/health) · [QpiAI run log](https://api.seqrlabs.com/api/v1/remediation/qpiai/log)

</div>
