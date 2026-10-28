# SeQr — Master Context for Claude Code
**Read this first in every session before touching any file.**

---

## Company & Brand

| Field | Value |
|---|---|
| Legal name | SeQr Labs Pvt Ltd (planned — pre-incorporation) |
| Product brand | SeQr |
| CLI command | `seqr` |
| Pip packages | `seqr` (CLI), `seqr-scanner` (shared scanner) |
| Docker org | `seqrlabs` |
| Domain | seqrlabs.com |
| Stage | MVP built, pre-revenue, pre-incorporation |
| Founder | Lochan (3rd year ECE, IBM Qiskit Advocate #116901, founder Quantum Collective India) |

**One-line pitch:**
"SeQr finds every quantum-vulnerable system in your infrastructure, maps it to Indian
compliance requirements, and gives you a migration roadmap — before your auditor asks for it."

**Primary urgency drivers (accurate framing — see `docs/09_Compliance_Frameworks.md`):**
- **LIVE NOW:** PCI DSS 12.3.3 (mandatory since 2025-03-31) and **SEBI CSCRF** (PQC
  crypto-asset inventory expected of SEBI REs since Jun 2025). These are the real
  "must do today" hooks — lead with them.
- **2026-2027 wave:** RBI **Q-SAFE** Committee framework expected ~Nov 2026; DST Task
  Force targets a cryptographic-asset inventory for CII (which includes BFSI per NCIIPC)
  **by 2027** (recommendatory, not a statutory filing deadline); DPDP Act §8 + ₹250 Cr
  penalties **enforceable 2027-05-13**.
- Sales pitch: "Your cryptographic inventory is already expected under PCI DSS and SEBI —
  and India's 2027 quantum-readiness milestone is next. SeQr builds the CBOM in minutes."
- ⚠ Do NOT call "Jan 1 2027" a hard CBOM *filing* deadline, and do NOT present DPDP as
  "in force now." Both were prior inaccuracies; corrected 2026-06-21.

---

## Monorepo Structure

```
seqr-labs/                         ← repo root (this directory)
├── CLAUDE.md                      ← you are here
├── shared-scanner/                ← seqr-scanner pip package
│   ├── scanner/                   (network.py, code.py, patterns/)
│   ├── engines/                   (classifier.py, risk.py, cbom.py, compliance.py)
│   └── seqr_scanner/             (public pip-importable package)
├── cli/                           ← seqr pip package
│   └── seqr/                     (cli.py, config.py, output/, _severity.py)
├── docs/                          ← all PRDs and reference docs
│   ├── 01_Audit_PRD.md
│   ├── 02_SDK_PRD.md
│   ├── 03_Gateway_PRD.md
│   ├── 04_Research_Paper.md
│   ├── 05_Business.md
│   ├── 06_CLI_PRD.md
│   ├── 07_GitHub_App_PRD.md
│   ├── 08_Scanner_Roadmap.md
│   ├── 09_Compliance_Frameworks.md
│   └── 10_Competitive_Analysis.md
└── research/                      ← paper scanner
    ├── domains.csv                (60+ Indian fintechs — ready to scan)
    ├── scan.py                    (fixed — reads CSV, scans each domain)
    └── checkpoint.json            (resume support)

audit/                             ← audit platform (Sessions 4–9 complete)
    ├── backend/                   (FastAPI + Celery + PostgreSQL)
    └── frontend/                  (Next.js 14, marketing landing + dashboard)
```

---

## Tech Stack — NEVER deviate from these decisions

| Layer | Technology |
|---|---|
| Backend language | Python 3.12 |
| API framework | FastAPI |
| Task queue | Celery + Redis (fakeredis in dev mode) |
| ORM | SQLAlchemy 2.0 + Alembic |
| Database | PostgreSQL 16 (prod) / SQLite (single-user dev) |
| Frontend | Next.js 14 App Router |
| Styling | Tailwind CSS + shadcn/ui |
| Animations | Framer Motion |
| Charts | Recharts |
| Data fetching | TanStack Query |
| Frontend language | TypeScript |
| TLS scanning | sslyze 6.0 |
| Crypto library | cryptography (PyCA) 43.0 |
| Code parsing | tree-sitter 0.23 |
| PQC algorithms | liboqs-python 0.11 |
| PDF generation | WeasyPrint (prod), ReportLab (dev fallback) |
| Auth | JWT (access tokens) + API keys (CI/agent) |
| License validation | Ed25519 offline signature |
| Containerisation | Docker + Docker Compose |

**Model selection:**
- Backend / scanner / CLI code → **claude-sonnet-4-6**
- Frontend (Session 9, Next.js) → **Mythos**

---

## Build Status

### shared-scanner (seqr-scanner pip package): ✅ COMPLETE
- Code scanner: AST + tree-sitter, 30 patterns, Python/JS/Java/Go
- Network scanner: sslyze 6.0, TLS/cert scanning, CDN detection, hybrid PQC via curve groups
- Risk engine: `pqc_migration_priority`, HNDL, `threat_timeline`, `crypto_agility_score`, `deployment_level` (0-4)
- CBOM engine: CycloneDX 1.5 export, JSON/CSV
- **A7 (2026-09-21): more TLS-bearing services.** Added direct-TLS scanners for **MongoDB**,
  **AMQP (RabbitMQ)**, and **gRPC-over-TLS**. These speak TLS immediately on connect (no
  STARTTLS), so they reuse the existing direct-TLS analysis + active PQC probe unchanged —
  only the default port differs. New `network._DIRECT_TLS_PROTOCOLS` (mongodb 27017 / amqp
  5671 / grpc 443+ALPN h2); `pqc_probe.probe_active_pqc(alpn=...)` adds `-alpn h2` for gRPC.
  Wired end-to-end: backend `assets._ASSET_TYPES` + `scan_tasks._TLS_PROTOCOLS`, frontend
  `AddAssetDialog.tsx`. Live-verified (grpcb.in TLS 1.3/RSA-2048/X25519; local self-signed
  servers on 27017/5671).
  New `tests/test_direct_tls_protocols.py` (mock + live per protocol) + probe/asset/routing tests.
- **A7+ (2026-09-30): MySQL-over-TLS scanner.** MySQL is NOT direct-TLS — it negotiates TLS
  mid-handshake (server Handshake v10 → client `SSLRequest` → TLS on the same socket), which
  sslyze cannot drive. New `scanner/mysql_probe.py` completes exactly that sequence (parses the
  handshake, checks the `CLIENT_SSL` capability, sends a 32-byte credential-free SSLRequest,
  upgrades to TLS) and reads the negotiated version/cipher + leaf cert; it authenticates
  nothing. New `network._STARTTLS_UPGRADE_PROTOCOLS` (`mysql` → 3306) routes to a dedicated
  `NetworkScanner._scan_starttls_upgrade` that reuses the shared cert analysis
  (`_parse_certificate`/`classify_*`), a new extracted `_finalize_crypto_fields` (HNDL/risk/
  recommendations/timeline — shared with the sslyze path), and the context computations
  (CDN/confidence/agility/deployment) → identical `DomainScanResult`/CBOM shape. Active PQC
  reuses `pqc_probe.probe_active_pqc(starttls="mysql")` (OpenSSL `s_client -starttls mysql`).
  Wired end-to-end: backend `assets._ASSET_TYPES` + `scan_tasks._TLS_PROTOCOLS`, frontend
  `AddAssetDialog.tsx` ("MySQL (TLS)"). New tests in `tests/test_direct_tls_protocols.py`:
  handshake/SSLRequest framing units, ERR/wrong-version rejection, mocked scan (cert + port +
  ssl-disabled), and integration against a fake MySQL-TLS server driving the real protocol +
  real TLS handshake (ssl-capable and ssl-disabled). **Note:** the STARTTLS upgrade is handled
  by the custom probe, not the direct-TLS path — MySQL stays out of `_DIRECT_TLS_PROTOCOLS` by
  design. Verifying against a production mysqld with TLS is the one remaining manual step.
- **502 tests passing** (non-integration; was 495 — +7 MySQL probe/scan/framing tests; the
  `_finalize_crypto_fields` extraction is regression-free)

### CLI (seqr pip package): ✅ COMPLETE
- `seqr scan domain / code / certs / all`
- `seqr explain <finding-id>` — offline static lookup dict (no API call, works air-gapped)
- `seqr migrate --finding <id>`
- `seqr history` and `seqr history diff <scan1> <scan2>`
- Professional terminal output (Rich), verbose mode `--verbose`
- **51 tests passing**
- Output: PLANNED language, deployment level 0-4, crypto agility score, CDN-specific remediation

### Audit Backend (FastAPI + Celery): ✅ COMPLETE (Sessions 4–8)
- Session 4: Auth, org, users, JWT, API keys (sq_live_ format, SHA-256 hashed)
- Session 5: Assets, scans, Celery tasks, WebSocket scan progress, fakeredis dev mode
- Session 6: CBOM API, risk score (0-100), compliance (5 frameworks), migration roadmap
- Session 7: PDF reports (ReportLab dev, WeasyPrint prod), executive + technical templates
- Session 8: Ed25519 license validator, docker-compose.prod.yml, Dockerfile, celery_worker.Dockerfile
- **A6 (2026-09-21): async scan workers at scale.** Real Celery worker pool (not eager):
  `deploy/worker/` (own Dockerfile installing shared-scanner + OpenSSL 3.5, `docker-compose.yml`
  backend+worker+redis+db, `CELERY_ALWAYS_EAGER=false`). `POST /assets/{id}/scan` enqueues +
  returns a job id immediately; the worker drives the existing `/ws/scans/{id}` channel with
  **live progress** — `{type:step}` phases + `{type:finding}` per component + `complete`/`failed`
  (frontend already parses these). **Per-org fairness cap** `MAX_CONCURRENT_SCANS_PER_ORG` (Redis
  inflight counter w/ TTL, over-cap tasks re-queue via Celery retry) so one tenant can't starve
  others; global via worker `--concurrency`; `prefetch=1` + `acks_late`. **Batch scan**
  `POST /assets/scan-all` (org-scoped). WS org-boundary check preserved. Load test
  `deploy/worker/loadtest.py` (~100 assets). New: `app/tasks/throttle.py`, `tests/test_scan_workers.py`.
- **A5 (2026-09-21): enterprise table-stakes.** Org RBAC depth + append-only audit log +
  verified backups + **OIDC SSO**. (SAML shipped 2026-09-30 — see A5+ below.) **RBAC:** central
  permission matrix `app/rbac.py` (roles `admin`/`analyst`/`auditor`/`viewer` + legacy
  `member`≡analyst; "operator" **renamed `analyst`** to avoid colliding with the platform
  `OPERATOR_EMAILS` operator). `deps.require_permission(perm)` factory replaces inline
  `role != "admin"` checks; writes gated across org/assets/scans/migration/attestation, so
  viewer/auditor are read-only and analyst can't manage users/org. Role strings now
  validated on invite/role-change; last-admin demotion blocked. **Audit log:** new
  append-only `audit_events` table (distinct from spine `events`) + HTTP middleware
  (`app/audit_log.py`) writing one row per authenticated mutating request (actor via
  `request.state`, set in `security.get_current_user`/`get_current_agent`); org-scoped read
  at `GET /api/v1/audit` gated by `audit:read` (admin+auditor), with actor/action/time
  filters — **not** under `/api/v1/admin` (that's the cross-tenant operator console).
  Alembic `a7b3e9c2f4d1`. **Backups:** portable `deploy/backup/{pg_backup.sh,pg_restore.sh}`
  + README — custom-format dump→gzip→SHA-256→optional S3 (any endpoint)→prune, and a
  **non-destructive `--verify` restore drill** (restore into scratch DB, sanity-check core
  tables, drop). **SSO (OIDC, Authlib):** per-org `oidc_providers` (client secret Fernet-
  encrypted at rest via `app/sso/crypto.py`; `users.oidc_subject` binds IdP identity),
  engine `app/sso/oidc.py` (discovery + JWKS id_token validation: sig/iss/aud/exp/nonce),
  router `app/routers/sso.py` — org-admin config CRUD (`/api/v1/sso/config`, `org:manage`,
  secret write-only) + public `/api/v1/sso/oidc/{start,callback}`; maps IdP groups→role
  (strongest wins, re-synced each login), JIT provisions, mints SeQr tokens to
  `{FE}/auth/sso/callback#access_token=…` (fragment). Feature-flag `SSO_ENABLED` +
  `OIDC_REDIRECT_BASE`. Alembic `a7b3e9c2f4d1` (audit), `b8c4f1a6d3e2` (sso). Ops:
  `docs/SSO_OPERATIONS.md`. Tenancy preserved throughout. New tests: `test_rbac.py`,
  `test_audit_log.py`, `test_sso_oidc.py` (real RS256 id_token, stubbed IdP HTTP).
- **A5+ (2026-09-30): SAML 2.0 SSO** (the last A5 auth gap — SAML is no longer a follow-on).
  Mirrors the OIDC structure. Per-org `saml_providers` (IdP EntityID/SSO/SLO + **public**
  signing cert `idp_x509_cert` — no secret to encrypt, unlike OIDC; `users.saml_subject`
  binds the NameID). Engine `app/sso/saml.py`: SP-initiated only (AuthnRequest over
  HTTP-Redirect, ACS over HTTP-POST), signed `RelayState` binds the response
  (`InResponseTo`). **Full assertion validation** — signature, single-Assertion, Issuer,
  Conditions time-window (+120 s skew), AudienceRestriction, SubjectConfirmationData
  Recipient/NotOnOrAfter/InResponseTo, and **single-use replay** (`saml_replay_ids` table).
  Signature verification is a local, XXE- + **XSW-hardened** XML-DSig
  (`app/sso/xmldsig.py`, lxml+cryptography — no native `xmlsec`/`signxml`, which don't fit
  the `cryptography<43` sslyze pin): enveloped RSA/ECDSA-SHA-256/384/512 only, SHA-1 rejected,
  exclusive C14N; the verifier returns the exact signed element and requires its ID be unique
  (duplicate-ID wrapping rejected); encrypted assertions rejected. Router `app/routers/sso`→
  `app/routers/saml.py` — org-admin config CRUD (`/api/v1/saml/config`, `org:manage`) + public
  `metadata` + `login`/`acs` + `logout`/`sls`; maps IdP groups→role (strongest wins, re-synced
  each login), JIT provisions, mints tokens to the same `{FE}/auth/sso/callback#…` fragment.
  Feature-flag `SAML_ENABLED` + `SAML_ACS_BASE`. Alembic `c9f2d7b4a1e6` (chain head; applies
  clean up/down). Tenancy preserved. New `tests/test_sso_saml.py` (locally-signed assertions
  driven through the real ACS: happy path, tampered, wrong-cert, XSW, expired, wrong audience,
  bad recipient/InResponseTo, replay, cross-org, unprovisioned; + XXE/DSig units). Ops:
  `docs/SSO_OPERATIONS.md` (SAML section). New deps: `python-multipart` (ACS Form), `lxml`.
- **264 tests passing** (was 206; +31 A5 OIDC, +27 A5+ SAML). New deps: `authlib==1.3.2`,
  `python-multipart`, `lxml`.

### Audit Frontend (Next.js 14): 🔄 IN PROGRESS (Session 9)
- Model: Mythos
- Pages: login, dashboard, assets, scan progress, CBOM viewer, reports, settings
- Stack: Next.js 14, TypeScript, Tailwind, shadcn/ui, Framer Motion, Recharts, TanStack Query
- Dark/light mode, premium design, animations

### Research Scanner: ⏳ READY TO RUN
- `research/scan.py` fixed — reads CSV, scans each domain, rate-limited (0.5s between)
- `research/domains.csv` ready — 60+ Indian fintech domains
- Checkpoint: `research/checkpoint.json` (resume support)
- Output: `research/results_YYYYMMDD_HHMM.json`
- Pre-scan of 5 Indian fintechs: all Level 1 Classical, all CDN-terminated, 0 hybrid PQC

### SeQr SDK (`pqcmap`): ✅ v0 BUILT (2026-08-20) — `pqcmap/`
- Drop-in PQC primitives (ML-KEM / ML-DSA via liboqs): KEM, Signature, HybridKEM
  (X25519+ML-KEM-768), PQCToken (ML-DSA JWT), LocalKeyStore (AES-GCM + PBKDF2).
- Runtime capability probe (`pqcmap.available()`) — no liboqs source-build side effect.
- **SDK-1 (2026-08-21):** PyPI-ready — `py.typed`, MIT LICENSE, full pyproject metadata,
  CHANGELOG/RELEASING; release workflow `.github/workflows/pqcmap.yml` (test matrix
  Linux/macOS/Windows × 3.10-3.12 on real backend; tag `pqcmap-v*` → build → TestPyPI
  dry-run → PyPI via OIDC trusted publishing). **Publish gated on founder pushing a tag.**
- **SDK-2 (2026-08-21):** policy enforcement — `pqcmap.policy` loads the spine's
  `{"rules":[...]}` body (`app/spine/policy.py`), `assert_compliant` / `@requires_pqc` /
  `pqcmap.compliant.{KeyEncapsulation,Signature}` raise `PolicyViolationError` below policy
  (default: no quantum-vulnerable families, NIST L3+).
- 99 tests passing (1 real-liboqs test skips when native lib absent).
- **SDK-5 (2026-08-21):** docs + proof. `pqcmap/docs/COOKBOOK.md` (RS256/ES256-JWT, RSA,
  ECDSA, ECDH/X25519, RSA-OAEP → pqcmap; snippets run for real by
  `examples/cookbook_recipes.py`); `pqcmap/benchmarks/benchmark.py` (live per-op timings,
  every installed backend + RSA baseline, no invented numbers) + `docs/BENCHMARKS.md`;
  `pqcmap/examples/worked_migration/` (`seqr scan code` → fix → re-scan clean). 160 tests / 1 skip.
- **SDK-6 (2026-08-21, in progress):** Node + Go ports (founder waived the PyPI-traction
  gate — pqcmap is not on PyPI yet). `pqcmap-js/` (`@seqr/pqc`) BUILT + verified: real FIPS via
  `@noble/post-quantum`; KEM/Signature/HybridKEM/PQCToken + PyJWT-shaped `/jwt` + policy engine +
  **LocalKeyStore** (interoperable on-disk format) + **HostedKMS** + **`/tls`** (X25519MLKEM768
  on OpenSSL 3.5+) + `index.d.ts` + benchmark; 42 node:test pass. `pqcmap-go/` BUILT + verified
  FULL parity (Go 1.27 / circl v1.6.1, `go test ./...` 24 tests): KEM/Signature/HybridKEM/JWT/
  policy/LocalKeyStore/HostedKMS/TLS. **Cross-language interop proven live** — KDF matches across
  Python/JS/Go, a Go-signed ML-DSA JWT verifies in Python + JS, and Python/Go keystores read
  cross-language. Pending: publish only (npm + pkg.go.dev tags). Plan: `PORTS.md`.
- hosted KMS client + TLS context builder shipped in SDK-3/SDK-4 (see docs/02).

### SeQr CI (`seqr ci`): ✅ v0 BUILT (2026-08-20) — `seqr ci` + `.github/actions/seqr-pqc`
- Diff-aware `seqr ci`: scans only PR-added lines, reuses --fail-on/--policy, exit 0
  by default, PR-style Markdown review (HNDL disclaimer, no CNSA). 34 tests.
- Composite GitHub Action + reference workflow (advisory by default; one line = hard gate).
- Hosted GitHub Marketplace app (webhook + Celery) still deferred; this covers the CI need.
- **CI-1 (2026-08-21):** policy-aware gate. New `--fail-on-drift` gates on drift from the
  org crypto policy (reuses the spine `{"rules":[...]}` shape via `seqr.ci.policy` — same
  contract pqcmap follows); `seqr-baseline.json` + `--update-baseline` accept legacy
  findings so only NEW drift fails; inline `# seqr:ignore[reason]`, `.seqrignore`, and an
  optional `seqr-ci.yml` for defaults (CLI flag > file > built-in). --fail-on/--policy and
  exit-0-default unchanged. Docs: `docs/CI_GATE.md`. CLI 136 tests passing.
- **CI-2 (2026-08-21):** richer output. SARIF hardened for GitHub code scanning
  (repo-relative URIs, `security-severity`, line-independent `partialFingerprints`;
  validates vs OASIS sarif-2.1.0) + `seqr ci --sarif-file`; the Action uploads it via
  `codeql-action/upload-sarif` → inline annotations on changed lines. Optional, feature-
  flagged dashboard push: Action `api-url`/`api-key` → backend `POST /api/v1/ci/findings`
  (auth JWT/`sq_live_`, org-scoped, `CI_INGEST_ENABLED`) → org CBOM/dashboard. CLI 146 +
  backend 131 tests passing. Permissions: `security-events: write`, `pull-requests: write`.
- **CI-3 (2026-08-21):** multi-platform reach. Composite action is Marketplace-prepped
  (`branding`, usage README, `action-release` workflow → `seqr-pqc-v*` + sliding
  `seqr-pqc-v1` tags; submit left manual/gated). One slim image `seqrlabs/seqr-ci`
  (`docker/seqr-ci/`, built from `./cli`) powers every non-GitHub consumer: a `seqr-ci`
  pre-commit hook (`.pre-commit-hooks.yaml`, docker_image), a reusable GitLab template
  (`ci/gitlab/seqr-ci.gitlab-ci.yml`, MR-scoped, diffs `CI_MERGE_REQUEST_DIFF_BASE_SHA`),
  and Jenkins/`docker run`. All advisory-by-default. Docs: `docs/CI_GATE.md` "Beyond
  GitHub". Manifest validated; gate verified via CliRunner (Docker daemon absent in the
  build env, so the container itself was not built here — `docker/seqr-ci/smoke-test.sh`
  covers that path).
- **CI-5 (2026-08-21):** trend + fail-budget. `seqr ci --snapshot` — scheduled, whole-tree
  drift-over-time (`seqr/ci/trend.py`): scans the tree vs policy, records a dated snapshot
  (`.seqr/snapshots/DATE.json`), diffs new-vs-resolved on the line-independent fingerprint,
  and gates on `--fail-budget N` (advisory/exit-0 by default). Markdown/JSON via `--output`,
  `--comment-file` for a weekly digest; HNDL disclaimer on any drift, no CNSA. Weekly
  reference workflow `.github/workflows/pqc-trend.yml`. Docs: `docs/CI_GATE.md`. CLI 165
  tests passing.
- **CI-4 (2026-09-08): hosted GitHub App BUILT** (deferral lifted). Zero-config PR scanning
  — the acquisition-channel half of CI. `audit/backend/app/github_app/`: webhook receiver
  (`routers/github_app.py`, HMAC-SHA256 verified, feature-flagged `GITHUB_APP_ENABLED`,
  404 when off) → Celery worker (`github_app/tasks.py`) that mints a short-lived
  installation token (`client.py`, RS256 App JWT via python-jose), fetches only changed
  files, scans PR-**added** lines with the shared `seqr-scanner` `CodeScanner`
  (`scan.py`+`diff.py`), and posts an inline review + `seqr/pqc` commit status
  (`review.py`, HNDL disclaimer, no CNSA, exit-0/advisory unless `GITHUB_APP_FAIL_ON` armed
  — severity via `severity.py` mirroring `seqr._severity`). Optional dashboard sync: a
  `github_installations` (installation→org) link → `CIReport` (`source="github-app"`).
  New Alembic revision `e7c2b9a4f1d8` adds `github_installations` **and** the never-migrated
  `ci_reports` (CI-2 gap). Ops runbook: `docs/GITHUB_APP_OPERATIONS.md`. Backend 168 tests
  passing (+37 `test_github_app.py`); full alembic chain applies clean. **Still gated:**
  register the App on GitHub + set env/secret + link installs (manual operator steps).

### Gateway: ⏸ DEFERRED (largely absorbed into the migration engine)
### Company registration (SeQr Labs Pvt Ltd): ⏸ PENDING
### Customer discovery (15 conversations): ⏸ PENDING

---

## Key Constants

```python
# License key format
LICENSE_FORMAT = "SQ-{TIER}-{base64_payload}.{ed25519_signature}"
# Examples: SQ-SMALL-..., SQ-MID-..., SQ-LARGE-..., SQ-ENT-...
GRACE_PERIOD_DAYS = 30  # read-only after expiry

# API key format (displayed prefix only — full key SHA-256 hashed in DB)
API_KEY_PREFIX = "sq_live_"  # e.g. sq_live_ab12cd34...

# Pricing tiers
PRICING = {
    "trial":      {"assets": 5,   "price_inr_year": 0},
    "small":      {"assets": 25,  "price_inr_year": 150000},
    "mid":        {"assets": 100, "price_inr_year": 400000},
    "large":      {"assets": 500, "price_inr_year": 800000},
    "enterprise": {"assets": -1,  "price_inr_year": 1500000},  # unlimited
}

# SaaS cloud deployment: AWS ap-south-1 (Mumbai) ONLY
# Reason: CERT-In / DPDP Act — data cannot leave India
CLOUD_REGION = "ap-south-1"
```

---

## Compliance Frameworks (Active in Product)

| Framework | Status | Key date / mandate | Source |
|---|---|---|---|
| PCI DSS 12.3.3 | ✅ ACTIVE — PASS if ≥1 scan / inventory | **Mandatory since 2025-03-31** | PCI DSS v4.0.1 |
| SEBI CSCRF (PQC) | ✅ ACTIVE — binding on SEBI REs | **Live since Jun 2025** — crypto-asset inventory + PQC priority | SEBI CSCRF circular + Jun 2025 update |
| RBI Q-SAFE | 🔵 MONITOR (emerging) | Framework expected **~Nov 2026** | RBI PR 25 May 2026 |
| DST Task Force | ⚠ ACTIVE driver — **recommendatory** | CII crypto inventory **by 2027**; CBOM in procurement FY2027-28 | DST report 4 Feb 2026 |
| DPDP Act 2023 § 8 | 🔵 MONITOR — **future-dated** | Enforceable **2027-05-13** (Rules 2025, Phase III) | DPDP Act s.8 + Rules 2025 |
| CERT-In | 🔵 MONITOR — **unverified** | No CERT-In PQC advisory confirmed | — |

**CNSA 2.0: EXCLUDED** — US National Security Systems only. Never show in Indian compliance output.

**DST is RECOMMENDATORY** (a Task Force report, not a statute — sectoral regulators enforce).
Never describe "Jan 1 2027" as a hard CBOM filing deadline; it is a *by-2027 inventory milestone*.
**CII includes BFSI** per NCIIPC (IT Act s.70A), so banks/NBFCs/insurers are in scope.

**DPDP Act wording in PDFs (future tense — §8 not yet enforceable):**
"From 13 May 2027, under Section 8 of DPDP Act 2023, failure to protect PII against
interception may risk statutory penalties up to ₹250 Crore (DPDP Rules 2025, Phase III)."

---

## Critical Technical Decisions

1. **Multi-tenant org boundary enforcement** (CRITICAL — before first enterprise customer)
   Every API route must enforce `org_id` WHERE clause.
   `GET /api/v1/assets/{id}` must verify `asset.org_id == current_user.org_id`.
   CBOM data leak = catastrophic.

2. **HNDL legal disclaimer everywhere**
   In all PDFs, CLI output, and API responses:
   "HNDL exposure scores are predictive cryptographic risk metrics based on data-type
   endurance, not indicators of active data interception or confirmed network breaches."

3. **CI/CD policy flags**
   `seqr scan code` exits 0 by default. Never break a build automatically.
   `--fail-on IMMEDIATE` / `--fail-on URGENT` / `--policy=strict` / `--policy=lax`

4. **Indian sovereign cloud**
   SaaS: AWS ap-south-1 only. On-prem Docker: zero data egress.

5. **CDN reframing**
   CDN-terminated domains = LOW remediation effort (opportunity, not warning).
   "One dashboard toggle when ML-KEM becomes available. No code changes required."

6. **HNDL path inference**
   HIGH persistence paths: /auth, /login, /kyc, /profile, /account, /user,
   /health-records, /archive, /vault, /backup, /export, /history
   LOW persistence: /ticker, /heartbeat, /static, /public, /images, /metrics

7. **Output language rules**
   NEVER: "QUANTUM: FAIL", "adopt immediately", CNSA 2.0, hardcoded "RSA" for TLS 1.3 key exchange
   ALWAYS: PLANNED (not CRITICAL) for modern TLS 1.3, PLANNED/URGENT/IMMEDIATE scale,
   "estimated" for HNDL, exit 0 by default

8. **License validation**
   100% offline Ed25519 signature check. Air-gap mode: `OFFLINE_MODE=true` — zero internet calls.

---

## PRD File Reference

| File | Covers | Status |
|---|---|---|
| `docs/01_Audit_PRD.md` | Audit backend + frontend | Sessions 4–8 done, Session 9 in progress |
| `docs/02_SDK_PRD.md` | pqcmap library | NOT STARTED — post first customer |
| `docs/03_Gateway_PRD.md` | NGINX PQC gateway | NOT STARTED — post first customer |
| `docs/04_Research_Paper.md` | Research methodology + paper spec | Scanner ready — scan immediately |
| `docs/05_Business.md` | GTM, pricing, sales, operations | Reference doc |
| `docs/06_CLI_PRD.md` | seqr CLI | COMPLETE — reference for features |
| `docs/07_GitHub_App_PRD.md` | GitHub Marketplace app | CI-4 BUILT 2026-09-08 (`app/github_app/`); Marketplace submit gated |
| `docs/08_Scanner_Roadmap.md` | v1.x–v3 scanner improvements | Reference |
| `docs/09_Compliance_Frameworks.md` | All frameworks with dates | Reference |
| `docs/10_Competitive_Analysis.md` | Competitors + market positioning | Reference |
| `docs/12_Product_Strategy.md` | Honest strategy + finalized 2026-07 direction | Reference |
| `docs/13_Platform_Spine_PRD.md` | Crypto-asset state graph + policy engine + discovery agent | Phase 1 + 1.5 DONE |
| `docs/14_Migration_Engine_PRD.md` | Migration engine — converge Actual → Policy (bundle+runbook) | Phase 2 DONE (Slices 1-5 + observability) |
| `docs/15_Discovery_Agent_Design.md` | On-prem discovery agent — implementation-ready design | Agent plane Slice 1 BUILT 2026-09-15 (`app/routers/agent.py` + `app/spine/agent_ingest.py`): agent-scoped credential mint/list/revoke + `POST /api/v1/agent/observations` ingest (source=discovery_agent, precedence 40) + `GET /api/v1/agent/status`; feature-flagged `AGENT_INGEST_ENABLED`; zero schema change. **Slice 2 (air-gap) + Slice 3 (agent runtime) BUILT 2026-09-21:** backend `POST /api/v1/agent/import` (signed-envelope verify → ingest, admin-gated, idempotent) + the agent is now a plugin package `deploy/agent/seqr_agent/` — plugin host + 4 collectors (`tls`, `cert_store` = filesystem PEM/DER + OS trust, `proxy_conf` = NGINX/HAProxy parse, `pkcs11` = HSM slot/mechanism stub, no key extraction), config file (JSON/YAML, `agent.example.yaml`), Ed25519 signing byte-matched to `app/spine/agent_sig.py`, connected + air-gap modes, CLI `seqr-agent {run,collect,export,verify}`, packaged (Dockerfile + PyInstaller `seqr-agent.spec`; image not built here — no Docker daemon). 28 agent tests (`deploy/agent/tests/`, air-gap round-trip verified against the platform's real verifier) + backend `test_agent_plane.py` covers import. `discovery_agent.py` kept as back-compat shim. **T7 (2026-09-30): extra collectors BUILT** — `ssh` (KEXINIT kex + host-key inventory, reuses shared `scanner.ssh_scanner`), `k8s` (kubernetes.io/tls Secrets [public `tls.crt` leaf only — never `tls.key`], cert-manager `Certificate` CRDs, Ingress TLS; read-only ServiceAccount/kubeconfig), and `cloud` (AWS **ACM** list+describe, read-only role/env creds; Azure/GCP slot in behind the `provider` switch). All on the same `base.py` contract + fixture-injection pattern (`_scanner`/`_client`, mirroring pkcs11's `_enumerator`) so tests never hit live k8s/cloud/SSH; each emits the standard observation shape and surfaces automatically in the data-driven `/connections` coverage (Slice 4 done). Registered in `plugins/__init__.py`; `agent.example.yaml` + optional deps documented. 49 agent tests (was 28; +21). PENDING: **real-HSM** `PyKCS11` path (pkcs11 stub kept per pilot decision 2026-09-30), extra cloud providers (Azure/GCP) per pilot |

**Also source-of-truth (external-safe):** `README.md` (project overview + roadmap),
`MARKETING.md` (consolidated GTM — use over the partly-stale `docs/05`).

---

## Next Steps (Priority Order) — updated 2026-07

Ecosystem direction finalized: **Discover → CBOM → Migrate → SDK → CI → Attest**, all on a shared
spine (state graph + policy engine). On-prem/air-gapped = flagship; SaaS = funnel; one engine,
one codebase. Full plan: `docs/13_Platform_Spine_PRD.md` + `docs/12_Product_Strategy.md` §8.

1. **Platform spine** — crypto-asset state graph (CBOM → persistent DB) + declarative policy
   engine. Build FIRST. See `docs/13`. [NEXT — awaiting founder greenlight]
2. **Multi-tenant audit** — enforce `org_id` on every API route; the spine must not weaken tenancy.
3. **Deep-discovery agent** — on-prem infra inventory (hosts, cert stores, TLS endpoints, HSMs,
   internal PKI, LBs, reverse proxies). Code repos excluded (SDK/CI own those).
4. **Migration engine** — signed change bundle + runbook, infra-first; converge actual → policy.
5. **SeQr SDK** (`pqcmap`) — enforce policy in application code.
6. **SeQr CI** (`seqr ci`; hosted GitHub App later) — block drift from policy.
7. **Attestation** — signed posture snapshots + policy-compliance certificates (last stage).
8. **15 customer discovery conversations** — run in parallel; validate migration-engine scope.
9. **Company registration + DPIIT** — needs paying customers first.

(SeQr Gateway is now largely absorbed into the migration engine; ML-DSA certs = future module.)

---

## QIntern 2026

First choice: **qi26_11** — Secure SDN + PQC (Abhishek N)
Second choice: **qi26_04** — Quantum-Anamorphic Encryption (Soumyadev Maity, Deep Raman)

---

## Changelog — 2026-06-21 (demo hardening · paper v2 · admin console)

- **Demo hardening:** fixed a hard blocker — backend created tables only in tests, so
  a fresh clone/dev run 500'd on register. Now `create_all` on SQLite startup (lifespan)
  + `BlogPost` registered in `app.models`. Verified the full flow live: register → asset
  → scan → CBOM → report PDF download → public scan → dashboard with data. (Dev scans run
  synchronously ~56s via eager Celery; prod is async + WS progress.)
- **Paper v2:** ran origin-leakage analysis (`research/origin_leakage.py`) — **51% of 118
  domains expose a non-CDN origin** (India 48%, intl 62%); folded into the paper as a 4th
  contribution. Polished the draft → `research/paper/PQC_India_Measurement.md` (v1.0
  submission candidate): consistent N (C1 n=53 / C2 n=118), real related work, data-avail
  → public `seqr-labs-research` repo, ethics/disclosure, 16 refs. **Before submitting:
  responsible disclosure + LaTeX conversion + affiliation.**
- **Admin console #14 (complete):** operator auth (OPERATOR_EMAILS) + org status/suspend;
  `routers/admin.py` (orgs+usage, plan/suspend, stats) + blog CMS (`models/blog_post.py`,
  post CRUD, public `routers/blog.py`); frontend `/admin` (operator console), `/admin/blog`
  (editor), `/blog` + `/blog/[slug]` (public SEO). Backend 96 tests.
- **Deployment gap (action needed):** auth backend isn't deployed — only `scan-demo-service`
  is. Live sign-in/dashboard/blog need `audit/backend` deployed (Postgres+Redis) + Vercel
  `NEXT_PUBLIC_API_URL` set. "Try It Live" works without it.

---

## Changelog — 2026-06-21 (origin-behind-CDN accuracy)

Closed the biggest scanner honesty gap: a CDN-fronted scan only sees the edge.
- `scanner/origin_discovery.py` (new): probes common origin-leak subdomains
  (origin./mail./ftp./api./dev. …) via DNS, flags non-CDN public IPs as candidate
  origins; optional crt.sh CT enrichment; bounded wall time; never raises.
- `DomainScanResult`: `scan_target` (direct|edge), `origin_assessed`,
  `origin_candidates`, `origin_note`. `NetworkScanner(discover_origin=...)`.
- **Honest labeling always** — CDN scans now say "edge, origin not assessed".
  Recon (candidate discovery) runs only for authenticated customer scans of their
  OWN assets; the public demo only labels edge/origin, never probes arbitrary domains.
- Live-verified: razorpay/paytm expose api./dev./sftp. origins on direct AWS IPs.
- Surfaced `scan_target`/`origin_assessed` in public scan responses. Vendored CLI re-synced.
- New paper angle: origin leakage (fold into paper v2).

---

## Changelog — 2026-06-21 (research study + protocol breadth #11)

**Research (powers the paper + GTM):**
- Ran the scanner over 61 Indian fintech endpoints, passive AND active. Headline:
  passive reports **0%** hybrid PQC, active confirms **60%** — the gap is CDN-edge
  (CloudFront 95%, Cloudflare 88%, direct origins 0%); certs 100% classical.
- Expanded corpus: `domains_india_extended.csv` (+40) and `domains_global.csv` (+24
  US/EU/UK/SG/BR). Combined India n=91 (56% PQC), Global n=24 (79%); India has a
  forward-secrecy gap (9 static-RSA endpoints) global doesn't.
- Artifacts: `research/FINDINGS_2026-06-21.md`, `research/paper/PQC_India_Measurement_draft.md`,
  `research/results_*.json`. `scan.py` gained `--active`, `--domains`, `--tag`.

**Protocol breadth #11 (engine done; product wiring pending):**
- `scanner/ssh_scanner.py` (new): SSH KEXINIT inventory — detects PQC KEX
  (mlkem768x25519, sntrup761x25519), flags classical host keys. Tested + live-verified.
- `scanner/network.py`: `scan_domain(protocol=...)` drives sslyze opportunistic TLS for
  **smtp/imap/pop3/postgres**, reusing full TLS analysis; active probe gained `-starttls`.
  Live-verified: Gmail SMTP → X25519MLKEM768. MySQL deferred (no sslyze support).
- LITE/PRO plan: passive SSH/SMTP to live in the free CLI (make LITE less thin);
  active PQC stays PRO/server-side.

See `docs/WHATS_BUILT_AND_HOW_TO_TEST.md` for the full component index + test commands.

---

## Changelog — 2026-06-21 (active PQC detection — scanner accuracy P1)

Closed the headline credibility hole: passive sslyze **cannot** confirm hybrid/ML-KEM
support. Added an active probe.

- `shared-scanner/scanner/pqc_probe.py` (new): drives **OpenSSL 3.5+** (native ML-KEM
  groups) to send a PQC ClientHello and read the negotiated group. Fail-safe — if
  OpenSSL 3.5+ is absent it reports `available=False` and the scan falls back to passive;
  never raises into the scan flow. 7 tests (mocked subprocess).
- `DomainScanResult` gained `pqc_active_probed/supported/group/note`; `NetworkScanner`
  gained `active_pqc=False`. When enabled and the server negotiates a hybrid PQC group,
  `hybrid_status` upgrades to "hybrid".
- Enabled server-side only (`active_pqc=True`): backend `public.py`, Celery `scan_tasks.py`,
  and `scan-demo-service`. Public scan responses now expose `pqc_active_supported`/
  `pqc_active_group`. **CLI stays passive** (no OpenSSL-3.5 dependency) — clean LITE/PRO split.
- `scan-demo-service/Dockerfile`: base → `python:3.12-slim-trixie` (OpenSSL 3.5.6).

Tests: shared-scanner 184 (sampled), backend 21 (sampled) — green. (Vendored CLI
`_scanner` intentionally NOT given the probe — CLI is passive by design.)

---

## Changelog — 2026-06-21 (security hardening pass — productization P0/P1)

Full backend security audit toward a sellable product. Tenancy was already solid
(every REST route scopes `org_id`, 404-not-403, `test_org_boundary.py`). Fixed real
holes found. Backend tests: 70 → **77 passing** (added config + SSRF-rebinding tests).

**P0 (security):**
- **WebSocket cross-tenant leak** (`main.py` `/ws/scans/{scan_id}`): validated JWT but
  never checked the scan's org — any user could subscribe to any org's live scan feed.
  Now loads the scan and verifies `scan.org_id == token org_id` before subscribing.
- **SSRF in public scanner** (`routers/public.py` + `scan-demo-service/main.py`): single
  `gethostbyname` check was bypassable via DNS rebinding + extra A/AAAA records. Now
  validates ALL `getaddrinfo` addresses (v4+v6) AND re-checks the actually-connected IP
  post-scan, discarding results from private/internal IPs.
- **Default SECRET_KEY** (`config.py`): added `validate_production()` — refuses to boot in
  production with the dev SECRET_KEY (forgeable JWTs = auth bypass), fakeredis, sqlite, or
  a localhost FRONTEND_URL. Called from `get_settings()`.

**P1 (hardening):**
- Security-headers middleware (`main.py`): X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, + HSTS in production. CORS no longer allows
  localhost in production.
- Auth rate limiting (`routers/auth.py`): per-IP limiter on `/login` + `/register`
  (10/15min) — production only. NOTE: in-memory per-process; move to Redis for multi-worker.
- Backend CBOM export (`routers/cbom.py`): CycloneDX `1.5 → 1.6` (matches engine).

**Known gaps — ALL FIXED 2026-06-21 (second security batch):**
- ✅ API-key auth wired — `get_current_user` accepts `sq_live_` keys (hash lookup, expiry, last_used).
- ✅ MFA login flow completed — `/auth/mfa/login` exchanges temp token + TOTP for tokens.
- ✅ Invite no longer leaks password in URL — returned once in response body.
- ✅ Real logout — `token_version` on User embedded in JWT; logout bumps it, invalidating all tokens.
- ✅ Rate limiting Redis-backed (`app/ratelimit.py`) when available, in-memory fallback for dev.
- Backend tests: 88 passing (added API-key/MFA/logout/invite regression tests).

---

## Changelog — 2026-06-21 (engine + compliance-accuracy pass)

Researched every framework against primary government/standards sources, then fixed
the engine + all customer-facing claims. Tests: 462 (shared-scanner) + 52 (CLI) + 5
(backend risk) all green.

**Compliance accuracy (highest priority — these were real, sellable-as-evidence errors):**
- `engines/compliance.py` (+ vendored copy): rewrote with accurate dates + per-framework
  `enforcement`/`effective_date`/`deadline`/`source` citation fields. Corrected DST to
  **recommendatory** (was "mandatory"); rewrote RBI as **Q-SAFE Committee** (real, May 2026);
  downgraded **CERT-In** (no verifiable PQC advisory exists); **added SEBI CSCRF** (live hook,
  was missing entirely); **added DPDP_2023** (enforceable 2027-05-13, not "in force"). Made the
  dead `_check_nist_reference` actually evaluate; added `_check_sebi_cscrf`.
- `audit/backend/app/routers/risk.py`: compliance endpoint now returns accurate SEBI + DPDP +
  Q-SAFE + recommendatory-DST messaging.
- Customer-facing copy corrected: `WhyNow.tsx` (added SEBI/Q-SAFE, fixed DST/DPDP, dropped
  unverified CERT-In), `DeadlineTag.tsx` + `FinalCTA.tsx` ("Jan 1 2027 CBOM deadline" →
  "DST 2027 quantum-readiness milestone"), `HowItWorks.tsx` (CERT-In → SEBI), CLI upsell footer.
- `docs/09_Compliance_Frameworks.md`: rewritten accurate, with a source-verification banner +
  SEBI section. **This is the source of truth — re-verify before each release.**

**Engine functional fixes:**
- `engines/cbom.py` (+ vendored): CycloneDX `specVersion` 1.5 → **1.6** (1.5 + `cryptographic-asset`
  fields = invalid BOM against its own declared schema).
- `engines/classifier.py` (+ vendored): `recommended_algorithm` now **strength-tiered**
  (RSA-4096/P-384 → ML-KEM-1024/ML-DSA-87 instead of always Level-3); **added real-world hybrid
  KEM groups** (SecP256r1MLKEM768, P-384/P-521 variants) that were being misclassified as "no PQC".

**Reviewed, not yet done (deliberately deferred — flagged honestly):**
- Surface `crypto_agility_breakdown` in CLI `--verbose`/TryItLive (it's computed, hidden) + add
  agility-score tier labels (today's best practice caps ~5.5/10 and reads as "fail").
- Let users tag asset `data_sensitivity` instead of the silent `internal` default on domain scans.
- Disclose `org_risk_score` top-20/HNDL-2× weighting as an uncalibrated heuristic in PDFs.
- Per-entry source citations in the classifier risk table.

---

## Session Instructions for Claude Code

When a session starts, I will tell you: "Today we are building: [component] — [module]"

1. Check build status above to understand what's done
2. Ask clarifying questions before writing any code
3. Write complete, working code — not pseudocode or stubs
4. Follow the exact tech stack above — no substitutions
5. Update build status checkboxes when complete
6. Write tests alongside implementation

**DO NOT:**
- Change the tech stack
- Use CNSA 2.0 in any Indian compliance output
- Hardcode "RSA" for TLS 1.3 key exchange
- Use "QUANTUM: FAIL" — use "PQC: MIGRATION REQUIRED"
- Break CI/CD by default
- Skip HNDL legal disclaimer in reports
