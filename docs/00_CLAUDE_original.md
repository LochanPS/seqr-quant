# SeQr — Master Context for Claude Code
**Read this first in every session before touching any file.**

---

## What This Project Is

SeQr is a Post-Quantum Cryptography (PQC) audit and migration platform for
Indian enterprises. It scans infrastructure for quantum-vulnerable cryptography
(RSA, ECC, ECDH, ECDSA) and produces compliance-mapped reports, migration roadmaps,
and tooling to fix the issues found.

The product suite has 5 components. They share one scanner codebase.

---

## Monorepo Structure

```
seqr/
├── CLAUDE.md                  ← you are here (read every session)
├── shared-scanner/            ← shared pip package, imported by audit + cli
│   ├── scanner/               (network.py, code.py, patterns/)
│   └── engines/               (classifier.py, risk.py, cbom.py)
├── audit/                     ← on-prem Docker audit platform (BUILD FIRST)
│   ├── backend/               (FastAPI + Celery + PostgreSQL)
│   └── frontend/              (Next.js 14)
├── cli/                       ← seqr pip package (BUILD THIRD)
│   └── seqr/
├── github-app/                ← GitHub Marketplace app (BUILD FOURTH)
│   └── app/
├── sdk/                       ← pqcmap open source library (BUILD FIFTH)
│   └── pqcmap/
├── gateway/                   ← NGINX + oqs-provider proxy (BUILD SIXTH)
│   ├── nginx/
│   └── management-api/
└── research/                  ← paper scanner (BUILD IN PARALLEL WITH AUDIT)
    └── scanner/
```

---

## Tech Stack — NEVER deviate from these decisions

| Layer | Technology |
|---|---|
| Backend language | Python 3.12 |
| API framework | FastAPI |
| Task queue | Celery + Redis |
| ORM | SQLAlchemy 2.0 + Alembic |
| Database | PostgreSQL 16 (on-prem) / SQLite (single-user) |
| Frontend | Next.js 14 App Router |
| Styling | Tailwind CSS + shadcn/ui |
| Charts | Recharts |
| TLS scanning | sslyze 6.0 |
| Crypto library | cryptography (PyCA) 43.0 |
| Code parsing | tree-sitter 0.23 |
| PQC algorithms | liboqs-python 0.11 |
| PDF generation | WeasyPrint (ReportLab fallback) |
| Auth | JWT (access) + API keys (CI/agent) |
| License validation | Ed25519 offline signature |
| Containerisation | Docker + Docker Compose + Helm |

---

## Build Status (update this as you build)

### shared-scanner: [ ] NOT STARTED
- [ ] scanner/network.py
- [ ] scanner/code.py
- [ ] scanner/patterns/ (python.json, javascript.json, java.json, go.json)
- [ ] engines/classifier.py
- [ ] engines/risk.py
- [ ] engines/cbom.py

### audit (MVP scope only): [ ] NOT STARTED
Backend:
- [ ] FastAPI app + config + database setup
- [ ] Auth (JWT login, register, API keys)
- [ ] Asset model + registration (domain type only for MVP)
- [ ] Network scanner integration (from shared-scanner)
- [ ] CBOM engine
- [ ] Risk engine
- [ ] Compliance engine (PCI DSS + DST)
- [ ] Report generator (Executive Summary PDF)
- [ ] Celery tasks
- [ ] License validator
- [ ] Docker Compose production

Frontend:
- [ ] Login + register pages
- [ ] Dashboard (risk score + component list)
- [ ] Asset wizard (add domain)
- [ ] Scan progress (WebSocket)
- [ ] Report download
- [ ] Settings

### cli: [ ] NOT STARTED
### github-app: [ ] NOT STARTED
### sdk: [ ] NOT STARTED
### gateway: [ ] NOT STARTED
### research scanner: [ ] NOT STARTED

---

## Key Business Context

Primary customer: Indian fintech/healthtech CTOs and CISOs
Primary product: On-premise Docker (annual license, ₹1.5L-10L/year)
Primary compliance driver: PCI DSS 12.3.3 (enforceable now) + India DST Task Force 2026
Primary differentiator: India-native, on-premise, compliance-mapped, mid-market priced

The three products solve one problem in sequence:
  Audit → finds all quantum-vulnerable components (CBOM)
  SDK   → lets developers fix code-level components
  Gateway → fixes API/TLS layer without code changes

---

## Critical Architectural Decisions

1. shared-scanner is a local pip package installed with `pip install -e ./shared-scanner`
   Both audit/backend and cli import from it. One scanner, two products.

2. Deployment mode is controlled by DEPLOYMENT_MODE env var:
   - onprem: SQLite/local PostgreSQL, local file storage, license key required
   - cloud: AWS RDS, S3, Stripe billing
   - demo: SQLite with seed data, no auth required

3. The free public scanner (seqr.in/scan) is just the network scanner
   running without auth, rate-limited, cached 24h in free_scan_cache table.

4. All credentials (GitHub tokens, AWS keys) go to AWS Secrets Manager (cloud)
   or AES-256-GCM encrypted DB field (on-prem). Never in plaintext DB columns.

5. License key format: SQ-{tier}-{base64_payload}.{ed25519_signature}
   Validated 100% offline. Air-gap mode: zero internet calls.

---

## Session Instructions for Claude Code

When I start a session, I will tell you:
  "Today we are building: [component name] — [specific module]"

You should:
1. Check the build status table above to understand what's already done
2. Ask clarifying questions before writing any code
3. Write complete, working code — not pseudocode or stubs
4. Follow the exact tech stack above — no substitutions
5. Update the build status checkboxes as you complete each item
6. Write tests alongside the implementation

Do NOT:
- Change the tech stack
- Skip error handling
- Write placeholder comments instead of real code
- Combine multiple unrelated modules in one session

---

## PRD File Reference

Full specifications for each component:
  01_SeQr_Audit_PRD.md      → audit/ backend + frontend
  02_SeQr_SDK_PRD.md        → sdk/ (pqcmap)
  03_SeQr_Gateway_PRD.md    → gateway/
  04_Research_Paper_Spec.md      → research/
  05_Business_Sales_Marketing.md → not for Claude Code (business reference)
  06_SeQr_CLI_PRD.md        → cli/
  07_SeQr_GitHub_App_PRD.md → github-app/

When building a component, I will paste the relevant PRD after this CLAUDE.md.

