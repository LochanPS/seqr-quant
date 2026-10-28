# SeQr Audit — Engineering PRD v3.1
### On-Premise Docker · Post-Quantum Cryptography Audit Platform
**Hand this entire document to Claude Code. It contains everything needed to build.**

---

## BUILD STATUS (as of June 2026)

| Component | Status | Tests |
|---|---|---|
| shared-scanner (seqr-scanner pip pkg) | ✅ COMPLETE | 386 tests passing |
| CLI (seqr pip pkg) | ✅ COMPLETE | 51 tests passing |
| Audit backend Sessions 1-8 | ✅ COMPLETE | 50 tests passing |
| Audit frontend (Session 9) | 🔄 IN PROGRESS | Next.js 14, Mythos model |
| Research scanner | ⏳ READY TO RUN | domains.csv ready |
| GitHub App / SDK / Gateway | ⏸ DEFERRED | post-first-customer |

**Session 9 frontend model:** Mythos (not Sonnet 4.6 — see CLAUDE.md).
**Next milestone:** Complete Session 9 frontend → run research scanner → first customer demo.

---

## PRODUCT SUMMARY

SeQr Audit is an on-premise Docker application that scans an organisation's
infrastructure for quantum-vulnerable cryptography, generates a Cryptographic Bill
of Materials (CBOM), scores risk against compliance frameworks (PCI DSS 12.3.3,
India DST Task Force 2026, NIST FIPS 203/204/205), and produces PDF audit reports.

Primary deployment: Docker container running entirely inside the customer's network.
No data leaves their perimeter. License-key activated. Annual subscription.

Secondary deployment: Same codebase deployed as cloud SaaS for smaller customers
who don't need air-gap compliance.

---

## TECH STACK — DECISIONS ARE FINAL

**Backend:** Python 3.12, FastAPI, Celery, Redis, SQLAlchemy, Alembic, PostgreSQL 16
**Frontend:** Next.js 14 (App Router), Tailwind CSS, shadcn/ui, Recharts, NextAuth.js
**Scanning:** sslyze, cryptography (PyCA), tree-sitter, GitPython, boto3, liboqs-python
**PDF:** WeasyPrint (primary), ReportLab (fallback)
**Auth:** JWT (access tokens) + API keys (agent/CI)
**Containerisation:** Docker, Docker Compose, Helm chart (K8s)
**Storage (on-prem):** SQLite (single-user) or bundled PostgreSQL (team)
**Storage (cloud):** AWS RDS PostgreSQL, ElastiCache Redis, S3, Secrets Manager
**License validation:** Offline cryptographic signature check (Ed25519)

---

## PROJECT STRUCTURE

```
seqr-audit/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app entry point
│   │   ├── config.py                # Settings from env vars
│   │   ├── database.py              # SQLAlchemy engine + session
│   │   ├── models/
│   │   │   ├── organisation.py
│   │   │   ├── user.py
│   │   │   ├── asset.py
│   │   │   ├── scan.py
│   │   │   ├── crypto_component.py
│   │   │   ├── report.py
│   │   │   ├── suppression.py
│   │   │   ├── audit_log.py
│   │   │   └── vendor_assessment.py
│   │   ├── routers/
│   │   │   ├── auth.py
│   │   │   ├── assets.py
│   │   │   ├── scans.py
│   │   │   ├── cbom.py
│   │   │   ├── risk.py
│   │   │   ├── reports.py
│   │   │   ├── vendors.py
│   │   │   └── public.py            # Free scanner (no auth)
│   │   ├── scanners/
│   │   │   ├── __init__.py
│   │   │   ├── network.py           # TLS/cert scanner (sslyze)
│   │   │   ├── code.py              # AST code scanner (tree-sitter)
│   │   │   ├── cloud_aws.py         # AWS scanner (boto3)
│   │   │   ├── cloud_gcp.py         # GCP scanner
│   │   │   └── patterns/
│   │   │       ├── python.json      # Crypto patterns for Python
│   │   │       ├── javascript.json  # Crypto patterns for JS/TS
│   │   │       ├── java.json
│   │   │       └── go.json
│   │   ├── engines/
│   │   │   ├── cbom.py              # CBOM aggregation
│   │   │   ├── risk.py              # Risk scoring algorithm
│   │   │   ├── compliance.py        # Framework gap analysis
│   │   │   └── roadmap.py           # Migration roadmap generator
│   │   ├── tasks/
│   │   │   ├── __init__.py          # Celery app
│   │   │   ├── scan_tasks.py        # Celery scan task definitions
│   │   │   └── report_tasks.py      # Celery report generation tasks
│   │   ├── reports/
│   │   │   ├── generator.py         # WeasyPrint PDF engine
│   │   │   ├── templates/
│   │   │   │   ├── executive.html
│   │   │   │   ├── technical.html
│   │   │   │   ├── compliance_pci.html
│   │   │   │   └── base.html
│   │   │   └── static/
│   │   │       └── report.css
│   │   ├── license/
│   │   │   └── validator.py         # Offline license key validation
│   │   └── utils/
│   │       ├── crypto_classifier.py # Algorithm → vulnerability mapping
│   │       └── hndl_scorer.py       # Harvest Now Decrypt Later scorer
│   ├── migrations/                  # Alembic migrations
│   ├── tests/
│   │   ├── fixtures/
│   │   │   ├── tls/                 # Docker compose with test TLS servers
│   │   │   └── code/                # Sample files with known crypto patterns
│   │   ├── test_network_scanner.py
│   │   ├── test_code_scanner.py
│   │   ├── test_risk_engine.py
│   │   └── test_cbom.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── celery_worker.Dockerfile
├── frontend/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx                 # Landing / login redirect
│   │   ├── (auth)/
│   │   │   ├── login/page.tsx
│   │   │   └── register/page.tsx
│   │   ├── (dashboard)/
│   │   │   ├── layout.tsx
│   │   │   ├── dashboard/page.tsx   # Main dashboard
│   │   │   ├── assets/page.tsx      # Asset management
│   │   │   ├── cbom/page.tsx        # CBOM viewer
│   │   │   ├── reports/page.tsx     # Report download
│   │   │   ├── compliance/page.tsx  # Compliance gap view
│   │   │   ├── roadmap/page.tsx     # Migration roadmap
│   │   │   └── settings/page.tsx
│   │   └── scan/page.tsx            # Public free scanner (no auth)
│   ├── components/
│   │   ├── ui/                      # shadcn/ui components
│   │   ├── dashboard/
│   │   │   ├── RiskScoreGauge.tsx
│   │   │   ├── ComponentTable.tsx
│   │   │   ├── ComplianceMatrix.tsx
│   │   │   └── ScanProgress.tsx
│   │   └── onboarding/
│   │       └── AssetWizard.tsx
│   ├── lib/
│   │   ├── api.ts                   # API client
│   │   └── auth.ts                  # NextAuth config
│   ├── package.json
│   ├── next.config.js
│   └── Dockerfile
├── docker-compose.yml               # Full stack local dev
├── docker-compose.prod.yml          # On-prem production
├── helm/                            # Kubernetes Helm chart
│   └── seqr/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
└── .env.example
```

---

## ENVIRONMENT VARIABLES

```bash
# .env.example

# Core
DEPLOYMENT_MODE=onprem              # onprem | cloud
LICENSE_KEY=                        # Required for on-prem
SECRET_KEY=                         # JWT signing secret (generate: openssl rand -hex 32)
ENVIRONMENT=production              # development | production

# Database
DATABASE_URL=postgresql://seqr:password@db:5432/seqr
# For single-user on-prem: DATABASE_URL=sqlite:////data/seqr.db

# Redis (queue)
REDIS_URL=redis://redis:6379/0

# Storage
STORAGE_MODE=local                  # local | s3
LOCAL_STORAGE_PATH=/data/reports
# If cloud:
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=ap-south-1
S3_BUCKET=seqr-reports

# Email alerts
EMAIL_ENABLED=false
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=alerts@seqrlabs.com

# Scanning limits
MAX_DOMAINS_PER_SCAN=50
MAX_REPOS_PER_SCAN=20
MAX_REPO_SIZE_MB=500
SCAN_TIMEOUT_SECONDS=600
GITHUB_SCAN_CONCURRENCY=5

# License server (for cloud validation, disabled in air-gap mode)
LICENSE_SERVER_URL=https://license.seqrlabs.com
LICENSE_CHECK_INTERVAL_HOURS=24
OFFLINE_GRACE_PERIOD_DAYS=30

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXTAUTH_SECRET=
NEXTAUTH_URL=http://localhost:3000
```

---

## DOCKER COMPOSE (ON-PREM PRODUCTION)

```yaml
# docker-compose.prod.yml
version: '3.9'

services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_DB: seqr
      POSTGRES_USER: seqr
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U seqr"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: always
    volumes:
      - redis_data:/data

  backend:
    image: seqrlabs/audit-backend:latest
    restart: always
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    env_file: .env
    ports:
      - "8000:8000"
    volumes:
      - reports:/data/reports
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000

  worker:
    image: seqrlabs/audit-worker:latest
    restart: always
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    env_file: .env
    volumes:
      - reports:/data/reports
    command: celery -A app.tasks worker --loglevel=info --concurrency=4

  frontend:
    image: seqrlabs/audit-frontend:latest
    restart: always
    depends_on:
      - backend
    ports:
      - "80:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://backend:8000
      NEXTAUTH_URL: http://localhost

volumes:
  db_data:
  redis_data:
  reports:
```

**Installation command for customers:**
```bash
curl -sSL https://install.seqrlabs.com | bash
# OR manual:
docker compose -f docker-compose.prod.yml up -d
```

---

## DATABASE SCHEMA (COMPLETE)

```sql
-- Run via Alembic migrations. Schema for reference.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE organisations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    sector VARCHAR(100),              -- fintech, healthtech, govtech, other
    employee_count_range VARCHAR(50), -- 1-20, 21-50, 51-200, 201-500, 500+
    plan VARCHAR(50) DEFAULT 'trial', -- trial, small, mid, large, enterprise
    license_key_hash VARCHAR(255),    -- hashed license key
    license_expires_at TIMESTAMPTZ,
    quantum_risk_score INTEGER,       -- 0-100, recomputed after each scan
    asset_count INTEGER DEFAULT 0,
    logo_url VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),       -- bcrypt
    name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'member', -- admin, auditor, developer, member
    mfa_secret VARCHAR(255),          -- TOTP secret (encrypted)
    mfa_enabled BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    name VARCHAR(100) NOT NULL,       -- "GitHub Action - prod" etc
    key_hash VARCHAR(255) NOT NULL,   -- SHA-256 hash of actual key
    key_prefix VARCHAR(20) NOT NULL,  -- first 8 chars shown in UI: "sq_live_ab12..."
    scopes TEXT[],                    -- ['scan:read', 'scan:write', 'report:read']
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,        -- domain, github_repo, aws_account, gcp_project, agent
    name VARCHAR(255),
    identifier VARCHAR(500) NOT NULL, -- the URL/repo path/account ID
    credentials_ref VARCHAR(255),     -- Secrets Manager key OR encrypted local blob
    data_sensitivity VARCHAR(50),     -- public, internal, confidential, highly_confidential
    data_types TEXT[],                -- ['payment_data', 'health_records', 'pii', 'internal']
    status VARCHAR(50) DEFAULT 'pending',
    last_scanned_at TIMESTAMPTZ,
    scan_schedule VARCHAR(50),        -- daily, weekly, monthly, manual
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL,        -- network, code, aws, gcp, agent, full
    status VARCHAR(50) DEFAULT 'queued', -- queued, running, partial, complete, failed
    trigger VARCHAR(50),              -- manual, scheduled, webhook, api
    celery_task_id VARCHAR(255),
    pattern_library_version VARCHAR(20),
    components_found INTEGER DEFAULT 0,
    vulnerable_found INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE crypto_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- Where found
    location_type VARCHAR(50),        -- tls_cert, code, kms_key, ssh_key, config, jwt
    location_detail VARCHAR(1000),    -- api.company.com | src/auth/jwt.py:42 | alias/key
    location_file VARCHAR(500),       -- for code: file path
    location_line INTEGER,            -- for code: line number
    location_function VARCHAR(200),   -- for code: function/class context

    -- Algorithm details
    algorithm VARCHAR(100),           -- RSA-2048, ECDSA-P256, ML-KEM-768, AES-256
    algorithm_family VARCHAR(50),     -- RSA, ECC, AES, DH, ML-KEM, ML-DSA, SLH-DSA
    key_size INTEGER,
    library_name VARCHAR(100),
    library_version VARCHAR(50),
    protocol VARCHAR(50),             -- TLS, SSH, JWT, PGP
    tls_version VARCHAR(20),          -- TLS_1_0, TLS_1_2, TLS_1_3

    -- Certificate (if applicable)
    cert_expiry_date DATE,
    cert_issuer VARCHAR(255),
    cert_subject VARCHAR(255),
    cert_serial VARCHAR(255),
    cert_san TEXT[],                  -- Subject Alternative Names

    -- Risk scoring
    quantum_status VARCHAR(50),       -- vulnerable, safe, unknown, hybrid
    algorithm_risk_score INTEGER,     -- 0-10
    data_sensitivity_score INTEGER,   -- 0-10 (from asset data_sensitivity)
    final_risk_score DECIMAL(5,2),    -- algorithm_risk * data_sensitivity / 10
    hndl_risk BOOLEAN DEFAULT FALSE,  -- Harvest Now Decrypt Later flag
    confidence VARCHAR(20),           -- high, medium, low

    -- Compliance
    nist_compliant BOOLEAN,
    pci_compliant BOOLEAN,
    dst_compliant BOOLEAN,
    dpdp_risk BOOLEAN,               -- DPDP Act 2023 s.8 exposure (PII + quantum-vulnerable)

    -- Recommended fix
    recommended_algorithm VARCHAR(100), -- ML-KEM-768, ML-DSA-65, etc.
    recommended_fips VARCHAR(50),       -- FIPS 203, FIPS 204, FIPS 205
    estimated_effort_hours INTEGER,
    migration_priority VARCHAR(20),   -- critical, high, medium, low

    -- Lifecycle
    migration_status VARCHAR(50) DEFAULT 'open', -- open, in_progress, done, accepted_risk, false_positive
    migration_completed_at TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE suppression_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    component_id UUID REFERENCES crypto_components(id) ON DELETE CASCADE,
    rule_type VARCHAR(50),            -- false_positive, accepted_risk
    justification TEXT NOT NULL,
    created_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    type VARCHAR(50),                 -- executive_summary, technical_audit, compliance_pci, compliance_dst
    status VARCHAR(50) DEFAULT 'generating',
    storage_path VARCHAR(1000),       -- local path or S3 key
    scan_ids UUID[],
    component_count INTEGER,
    vulnerable_count INTEGER,
    risk_score_at_generation INTEGER,
    generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    metadata JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE free_scan_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL,
    result JSONB NOT NULL,
    ip_address INET,
    scanned_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours',
    converted_org_id UUID REFERENCES organisations(id)
);

-- Indexes
CREATE INDEX idx_crypto_components_org ON crypto_components(org_id);
CREATE INDEX idx_crypto_components_asset ON crypto_components(asset_id);
CREATE INDEX idx_crypto_components_status ON crypto_components(quantum_status);
CREATE INDEX idx_crypto_components_hndl ON crypto_components(hndl_risk) WHERE hndl_risk = TRUE;
CREATE INDEX idx_scans_org ON scans(org_id);
CREATE INDEX idx_audit_log_org ON audit_log(org_id);
CREATE INDEX idx_free_scan_domain ON free_scan_cache(domain);
```

---

## API ROUTES (COMPLETE)

```
BASE URL: /api/v1

─── PUBLIC (no auth) ──────────────────────────────────────────
GET  /health                          → health check
POST /public/scan                     → free domain scan (rate limited: 1/IP/10min)
GET  /public/scan/{domain}            → get cached free scan result

─── AUTH ──────────────────────────────────────────────────────
POST /auth/register                   → create account + org
POST /auth/login                      → returns access_token + refresh_token
POST /auth/refresh                    → refresh access token
POST /auth/logout                     → invalidate refresh token
POST /auth/mfa/setup                  → get TOTP QR code
POST /auth/mfa/verify                 → verify TOTP + enable MFA
POST /auth/api-keys                   → create API key
GET  /auth/api-keys                   → list API keys
DELETE /auth/api-keys/{id}            → revoke API key

─── ORGANISATION ───────────────────────────────────────────────
GET  /org                             → org details + risk score + license info
PATCH /org                            → update org name, logo, sector
GET  /org/users                       → list users
POST /org/users/invite                → invite user by email
PATCH /org/users/{id}/role            → change user role
DELETE /org/users/{id}                → remove user
GET  /org/audit-log                   → paginated audit log (admin only)
GET  /org/license                     → license status + expiry + limits

─── ASSETS ─────────────────────────────────────────────────────
GET  /assets                          → list assets (paginated)
POST /assets                          → register new asset
GET  /assets/{id}                     → asset detail + last scan summary
PATCH /assets/{id}                    → update asset (name, schedule, sensitivity)
DELETE /assets/{id}                   → remove asset (deletes credentials)
POST /assets/{id}/scan                → trigger manual scan → returns scan_id
POST /assets/{id}/test-connection     → verify credentials work without scanning
GET  /assets/{id}/history             → scan history for this asset

─── SCANS ──────────────────────────────────────────────────────
GET  /scans                           → list scans (paginated, filterable by status/type)
GET  /scans/{id}                      → scan detail + real-time status
GET  /scans/{id}/logs                 → scan execution logs (for debugging)
POST /scans/{id}/cancel               → cancel running scan

─── CBOM ───────────────────────────────────────────────────────
GET  /cbom                            → paginated CBOM (filterable by status, algorithm, risk)
GET  /cbom/summary                    → counts by algorithm family and quantum status
GET  /cbom/export                     → download CBOM (format: json|csv|cyclonedx)
GET  /cbom/{id}                       → single component detail
PATCH /cbom/{id}                      → update migration_status, data_sensitivity_score
POST /cbom/{id}/suppress              → create suppression rule (requires justification)
DELETE /cbom/{id}/suppress            → remove suppression rule

─── RISK ───────────────────────────────────────────────────────
GET  /risk/score                      → org quantum risk score (0-100) + breakdown
GET  /risk/hndl                       → HNDL-critical components
GET  /risk/history                    → risk score over time (for trend chart)
GET  /risk/compliance                 → compliance gap per framework
GET  /risk/compliance/{framework}     → detailed gap for one framework (pci|dst|nist|dpdp)

─── REPORTS ────────────────────────────────────────────────────
POST /reports/generate                → trigger report generation → returns job_id
GET  /reports                         → list generated reports
GET  /reports/{id}                    → report metadata + download status
GET  /reports/{id}/download           → download PDF (presigned URL or direct stream)
DELETE /reports/{id}                  → delete report

─── VENDORS ────────────────────────────────────────────────────
POST /vendors                         → create vendor assessment + send email
GET  /vendors                         → list vendors + PQC readiness scores
GET  /vendors/{id}                    → vendor detail + responses
DELETE /vendors/{id}                  → remove vendor
GET  /vendors/respond/{token}         → public: vendor sees their questionnaire
POST /vendors/respond/{token}         → public: vendor submits responses

─── AGENT (authenticated by API key, scope: agent) ─────────────
POST /agent/results                   → agent posts scan results
GET  /agent/config                    → agent fetches org config + asset list
POST /agent/heartbeat                 → agent health check

─── STALENESS INDEX ─────────────────────────────────────────────
GET  /cbom/staleness                  → components not rescanned in >30/60/90 days
  Response: {
    "stale_30d": [...],   # no rescan in 30 days — warning
    "stale_60d": [...],   # 60 days — urgent
    "stale_90d": [...]    # 90 days — compliance risk (PCI DSS 12.3.3 requires ongoing inventory)
  }
  Note: PCI DSS 12.3.3 does not specify rescan frequency but "ongoing" is implied.
        Recommend quarterly rescan at minimum for compliance evidence.
```

---

## MULTI-TENANT SECURITY REQUIREMENT (CRITICAL)

Every authenticated route MUST enforce org_id isolation. This is the single most
critical security requirement for the cloud SaaS deployment.

```python
# Every route dependency:
async def get_current_org(
    current_user: User = Depends(get_current_user)
) -> Organisation:
    return current_user.organisation

# Every DB query MUST include org_id filter:
# CORRECT:
components = db.query(CryptoComponent).filter(
    CryptoComponent.org_id == current_user.org_id,
    CryptoComponent.id == component_id
).first()

# WRONG (data leak):
component = db.query(CryptoComponent).filter(
    CryptoComponent.id == component_id
).first()

# Test for every route:
def test_org_isolation():
    """Org A cannot access Org B's data even with valid JWT."""
    org_a_token = login("user@org-a.com")
    org_b_scan_id = create_scan_for_org_b()
    response = client.get(f"/api/v1/scans/{org_b_scan_id}",
                          headers={"Authorization": f"Bearer {org_a_token}"})
    assert response.status_code == 404  # not 403 — don't reveal existence
```

---

## HNDL DISCLAIMER REQUIREMENT

Every HNDL risk mention in API responses, PDF reports, and email alerts MUST include:

```
"HNDL exposure scores are predictive cryptographic risk metrics based on
data-type endurance and endpoint exposure classification, not indicators of
active data interception or confirmed network breaches."
```

In JSON responses, add `hndl_disclaimer` field alongside any `hndl_risk: true` component.
In PDF reports, include as footnote on every page that shows HNDL findings.
In CLI terminal output, print disclaimer once per scan when any HNDL finding is shown.

---

## CORE SCANNER LOGIC

### Network Scanner (backend/app/scanners/network.py)

```python
"""
Build the network scanner using sslyze.
For each domain:
1. Connect and get TLS certificate chain
2. Run cipher suite enumeration
3. Check key exchange algorithm from ServerHelloMessage
4. Parse cert: algorithm, key size, expiry, issuer, SANs
5. Return structured result

Key imports:
  from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
  from sslyze.plugins.scan_commands import ScanCommand
  from cryptography import x509
  from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

Algorithm classification table (build this as a dict):
  RSA (any key size) → VULNERABLE, algorithm_risk=8 if >=2048 else 10
  ECDSA P-256, P-384 → VULNERABLE, algorithm_risk=7
  ECDSA secp256k1 → VULNERABLE, algorithm_risk=7
  DH, DHE → VULNERABLE, algorithm_risk=8
  Ed25519, Ed448 → VULNERABLE (quantum), algorithm_risk=6
  ML-KEM-512/768/1024 → SAFE, algorithm_risk=0
  ML-DSA-44/65/87 → SAFE, algorithm_risk=0
  SLH-DSA → SAFE, algorithm_risk=0
  AES-128 → LOW RISK (Grover), algorithm_risk=2
  AES-256 → SAFE, algorithm_risk=0
  SHA-1 → CRITICAL (classically broken), algorithm_risk=10
  SHA-256 → SAFE, algorithm_risk=0
  TLS 1.0, 1.1 → CRITICAL (deprecated), algorithm_risk=9
  TLS 1.2 → MODERATE (depends on cipher suite)
  TLS 1.3 → check key exchange specifically
"""
```

### Code Scanner — Pattern Library Format

```json
// backend/app/scanners/patterns/python.json
{
  "language": "python",
  "version": "1.4.0",
  "patterns": [
    {
      "id": "PY-RSA-001",
      "description": "RSA key generation via cryptography library",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["cryptography.hazmat.primitives.asymmetric.rsa"],
      "functions": ["generate_private_key", "generate_public_key"],
      "recommended_replacement": "ML-DSA (FIPS 204) for signatures, ML-KEM (FIPS 203) for key exchange",
      "estimated_effort_hours": 8
    },
    {
      "id": "PY-JWT-RS256",
      "description": "JWT signing with RSA (RS256/RS384/RS512)",
      "algorithm": "RSA-SHA256",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["jwt", "PyJWT"],
      "algorithm_strings": ["RS256", "RS384", "RS512"],
      "context": "algorithm parameter in jwt.encode() or jwt.decode()",
      "recommended_replacement": "ML-DSA-65 via seqr-pqc SDK",
      "estimated_effort_hours": 4
    },
    {
      "id": "PY-ECC-001",
      "description": "ECC key generation",
      "algorithm": "ECDSA",
      "algorithm_family": "ECC",
      "quantum_status": "vulnerable",
      "algorithm_risk": 7,
      "confidence": "high",
      "imports": ["cryptography.hazmat.primitives.asymmetric.ec"],
      "functions": ["generate_private_key", "SECP256K1", "SECP256R1", "SECP384R1"],
      "recommended_replacement": "ML-DSA (FIPS 204)",
      "estimated_effort_hours": 8
    },
    {
      "id": "PY-PARAMIKO-RSA",
      "description": "Paramiko RSA SSH key usage",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 7,
      "confidence": "medium",
      "imports": ["paramiko"],
      "functions": ["RSAKey", "generate_key"],
      "recommended_replacement": "Ed25519 (interim) → PQC SSH when OpenSSH adds support",
      "estimated_effort_hours": 6
    }
  ]
}
```

### Risk Engine (backend/app/engines/risk.py)

```python
"""
Risk Score Calculation:

HNDL Risk Conditions (all must be true):
  - quantum_status == 'vulnerable'
  - location_type in ['tls_cert', 'kms_key', 'jwt'] (key exchange or long-term encryption)
  - asset.data_sensitivity in ['confidential', 'highly_confidential']
  - asset is publicly accessible (domain asset or cloud asset with public endpoint)

Algorithm Risk Scores (0-10):
  SHA-1, TLS 1.0, RSA < 1024: 10 (critically broken)
  TLS 1.1, RSA-1024: 9
  RSA-2048: 8
  RSA-4096, ECDH, DHE-2048: 7
  ECDSA P-256, secp256k1: 7
  ECDSA P-384: 6
  Ed25519/Ed448: 5 (quantum vulnerable but not classically)
  AES-128: 2 (Grover halves, but still 64-bit quantum)
  AES-256, SHA-256+, ML-KEM, ML-DSA, SLH-DSA: 0

Data Sensitivity Scores (0-10):
  highly_confidential (health records, defense, financial): 10
  confidential (PII, payment data): 8
  internal (business data): 5
  public: 1

Final Risk Score = (algorithm_risk * data_sensitivity) / 10

Org-level Risk Score = weighted average of top 20 components by risk
  weighted toward HNDL-critical components (2x weight)

Compliance mapping:
  PCI DSS 12.3.3:
    FAIL if: no CBOM exists (first scan incomplete), or any RSA/ECC in payment API scope
    PASS if: full CBOM documented, all payment-scope endpoints using approved algorithms

  DST Task Force Phase 1:
    FAIL if: no migration plan documented, no risk assessment completed
    PASS if: CBOM complete, roadmap generated

  NIST SP 800-131A:
    FAIL if: RSA < 2048, SHA-1, TLS < 1.2, DH < 2048
    PASS if: all algorithms meet minimum requirements

  DPDP Act 2023 Section 8:
    FLAG if: quantum-vulnerable component handles PII data types
             (data_types contains 'pii' or 'health_records' or 'payment_data')
             AND quantum_status == 'vulnerable'
    Output label: "DPDP Risk — quantum-vulnerable PII endpoint (up to ₹250 Crore penalty)"
    Note: DPDP creates financial liability for inadequate security safeguards on PII.
          The Act does not specify PQC but Section 8 mandates 'reasonable security safeguards.'
          A quantum-vulnerable endpoint handling PII is an inadequate safeguard.

  CNSA 2.0: EXCLUDED — US National Security Systems only. Not applicable to
            Indian private companies. Do not show in any output.

pqc_migration_priority labels (use PLANNED language):
  IMMEDIATE: RSA/ECDSA TLS cert or JWT with PII in scope — file before Jan 1, 2027
  URGENT:    RSA/ECDSA without PII scope, HNDL exposure
  PLANNED:   All others — include in migration roadmap
  MONITORING: AES-128, classical-only but monitored
"""
```

---

## LICENSE VALIDATION SYSTEM

```python
"""
backend/app/license/validator.py

License key format: SQ-{TIER}-{base64_payload}.{ed25519_signature}

Example: SQ-MID-eyJvcmdfaWQiOiJ...base64...fQ==.MEUCIQDz...signature...

Payload (base64url encoded JSON):
  {
    "org_id": "uuid",
    "tier": "TRIAL|SMALL|MID|LARGE|ENTERPRISE",
    "asset_limit": 25,
    "issued_at": "2026-06-01T00:00:00Z",
    "expires_at": "2027-06-01T00:00:00Z",
    "features": ["network", "code", "cloud", "agent", "vendor_assessment"]
  }

Signature: Ed25519 signature of the base64url payload string
Validation: verify signature using SeQr's PUBLIC key (baked into binary)

Offline validation: no network call needed.
  1. Decode payload
  2. Verify Ed25519 signature against baked-in public key
  3. Check expiry date
  4. Check asset count against limit

Grace period: if license expired <= 30 days ago, allow read-only access
  (can view existing results, cannot run new scans)

Air-gap mode: OFFLINE_MODE=true skips any internet calls entirely.
  License must be valid. No phone-home ever.

For generating licenses (internal tool only, not in this repo):
  Use Ed25519 private key held by SeQr Inc.
  Script: scripts/generate_license.py (separate internal tool)
"""
```

---

## REPORT TEMPLATES

### Executive Summary Structure
```
Page 1: Cover (org name, date, SeQr logo, confidentiality notice)
Page 2: Executive Summary
  - Quantum Risk Score (large, with colour: red/amber/green)
  - 3 bullet key findings
  - HNDL Critical asset count
  - Compliance status table (framework | status | next deadline)
Page 3: Top 5 Priority Actions
  - Each with: what to do, estimated hours, deadline, which compliance it addresses
Page 4: About Post-Quantum Cryptography (1 page plain-English explainer)
```

### Technical Audit Structure
```
Pages 1-3: As above
Page 4+: Full CBOM (table: location | algorithm | risk score | status | recommendation)
  - Sorted by final_risk_score descending
  - Grouped by: HNDL Critical | High | Medium | Low | Safe
Page N: Migration Roadmap (phase by phase, with timeline and effort)
Page N+1: Compliance Detail per framework
Page N+2: Methodology note (what was scanned, how, pattern library version)
Page N+3: Signature block for assessor
```

---

## GITHUB APP SPECIFICATION

```
App name: SeQr PQC Scanner
Permissions needed (read-only):
  - contents: read
  - pull_requests: write (to post review comments)
  - statuses: write (to set commit status)

Webhook events: pull_request (opened, synchronize)

On PR webhook:
  1. Get list of changed files from GitHub API
  2. For each .py/.js/.ts/.java/.go file: fetch content, run code scanner
  3. Aggregate findings
  4. POST review comment with findings table
  5. If findings.severity >= fail_on setting: set commit status to failure
  6. Store results in SeQr org account (if connected)

Review comment format:
  ## SeQr PQC Scan Results
  Found 3 quantum-vulnerable cryptographic patterns in this PR.

  | File | Line | Algorithm | Risk | Recommendation |
  |------|------|-----------|------|----------------|
  | src/auth/jwt.py | 42 | RSA-2048 (RS256 JWT) | HIGH | Replace with ML-DSA-65 |
  | src/keys/gen.py | 17 | ECDSA P-256 | HIGH | Replace with ML-DSA-44 |
  | config/tls.py | 8 | TLS 1.2 DHE | MEDIUM | Upgrade to TLS 1.3 with ML-KEM |

  [View full report on SeQr →](https://app.seqrlabs.com/scans/xxx)

Marketplace listing:
  - Free tier: 3 repos, basic findings only
  - Paid (₹3,000/org/month): unlimited repos, full findings, SeQr dashboard sync
```

---

## BUILD AND RUN COMMANDS

```bash
# Development setup
git clone https://github.com/seqrlabs/audit
cd audit

# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload

# Worker (separate terminal)
celery -A app.tasks worker --loglevel=debug

# Frontend (separate terminal)
cd frontend
npm install
npm run dev

# Full stack with Docker
docker compose up

# Run tests
cd backend
pytest tests/ -v

# Build production images
docker build -t seqrlabs/audit-backend:latest -f backend/Dockerfile backend/
docker build -t seqrlabs/audit-worker:latest -f backend/celery_worker.Dockerfile backend/
docker build -t seqrlabs/audit-frontend:latest -f frontend/Dockerfile frontend/

# Generate license key (internal use only)
python scripts/generate_license.py \
  --org-id "uuid" \
  --tier mid \
  --asset-limit 100 \
  --expires "2027-06-12" \
  --output license.txt
```

---

## MVP SCOPE (Build This First)

Phase 1 (8 weeks) — minimum to get first paying customer:
1. Backend: FastAPI + PostgreSQL + Celery + Redis (Week 1-2)
2. Auth: JWT login, org creation, API keys (Week 2)
3. Asset registration: domain type only (Week 2)
4. Network scanner: sslyze TLS scan (Week 3-4)
5. CBOM + risk engine (Week 5)
6. Executive Summary PDF report (Week 6)
7. Frontend: login + dashboard + one asset + report download (Week 7)
8. Docker Compose on-prem packaging + license validation (Week 8)

NOT in MVP:
- Code scanner (V1, month 3)
- Cloud/AWS scanner (V1, month 3)
- Agent (V1, month 4)
- Vendor assessment (V1, month 4)
- GitHub App (V2, month 6)


---

## REQUIREMENTS.TXT (EXACT VERSIONS)

```txt
# backend/requirements.txt

# Web framework
fastapi==0.115.0
uvicorn[standard]==0.30.6
python-multipart==0.0.9

# Database
sqlalchemy==2.0.35
alembic==1.13.3
psycopg2-binary==2.9.9          # PostgreSQL driver
aiosqlite==0.20.0               # SQLite async (on-prem lite mode)

# Task queue
celery==5.4.0
redis==5.0.8

# Auth
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
pyotp==2.9.0                    # TOTP for MFA

# Scanning — TLS/Network
sslyze==6.0.0
cryptography==43.0.0

# Scanning — Code (AST)
tree-sitter==0.23.0
tree-sitter-python==0.23.0
tree-sitter-javascript==0.23.0
tree-sitter-java==0.23.0
tree-sitter-go==0.23.0
GitPython==3.1.43

# Scanning — Cloud
boto3==1.35.0                   # AWS
google-cloud-kms==2.24.0        # GCP

# PQC
liboqs-python==0.11.0

# PDF generation
weasyprint==62.3
reportlab==4.2.2                # fallback

# HTTP client
httpx==0.27.2

# Validation
pydantic==2.9.2
pydantic-settings==2.5.2

# Utilities
python-dotenv==1.0.1
email-validator==2.2.0
tqdm==4.66.5                    # progress bars for long scans

# Testing
pytest==8.3.3
pytest-asyncio==0.24.0
pytest-cov==5.0.0
moto[all]==5.0.14               # AWS mocking
httpx==0.27.2                   # for TestClient
```

---

## DOCKERFILES

```dockerfile
# backend/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# System deps for sslyze, cryptography, weasyprint
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libfontconfig1 \
    libcairo2 \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run database migrations on startup, then start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

EXPOSE 8000
```

```dockerfile
# backend/celery_worker.Dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libfontconfig1 \
    libcairo2 \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["celery", "-A", "app.tasks", "worker", "--loglevel=info", "--concurrency=4", "-Q", "scans,reports"]
```

```dockerfile
# frontend/Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
```

---

## main.py STRUCTURE

```python
# backend/app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import auth, assets, scans, cbom, risk, reports, vendors, public
from app.license.validator import validate_license_on_startup


@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup
    if settings.DEPLOYMENT_MODE == "onprem":
        validate_license_on_startup(settings.LICENSE_KEY)
    yield
    # On shutdown (cleanup if needed)


app = FastAPI(
    title="SeQr Audit API",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url=None,
    lifespan=lifespan
)

# CORS — critical for Next.js frontend to reach FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware (use slowapi)
# from slowapi import Limiter
# from slowapi.util import get_remote_address
# limiter = Limiter(key_func=get_remote_address)

# Routers
app.include_router(public.router, prefix="/api/v1/public", tags=["public"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(cbom.router, prefix="/api/v1/cbom", tags=["cbom"])
app.include_router(risk.router, prefix="/api/v1/risk", tags=["risk"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(vendors.router, prefix="/api/v1/vendors", tags=["vendors"])

# WebSocket for real-time scan progress
from app.ws.scan_progress import router as ws_router
app.include_router(ws_router)

@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "mode": settings.DEPLOYMENT_MODE}
```

---

## config.py (Pydantic Settings)

```python
# backend/app/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Core
    DEPLOYMENT_MODE: str = "onprem"          # onprem | cloud
    LICENSE_KEY: str = ""
    SECRET_KEY: str                           # Required — no default
    ENVIRONMENT: str = "production"
    FRONTEND_URL: str = "http://localhost:3000"

    # Database
    DATABASE_URL: str = "sqlite:////data/seqr.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Storage
    STORAGE_MODE: str = "local"              # local | s3
    LOCAL_STORAGE_PATH: str = "/data/reports"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "ap-south-1"
    S3_BUCKET: str = ""

    # Email
    EMAIL_ENABLED: bool = False
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "alerts@seqrlabs.com"

    # Scanning limits
    MAX_DOMAINS_PER_SCAN: int = 50
    MAX_REPOS_PER_SCAN: int = 20
    MAX_REPO_SIZE_MB: int = 500
    SCAN_TIMEOUT_SECONDS: int = 600
    GITHUB_SCAN_CONCURRENCY: int = 5

    # License
    LICENSE_SERVER_URL: str = "https://license.seqrlabs.com"
    OFFLINE_MODE: bool = False               # True = no internet calls ever
    OFFLINE_GRACE_PERIOD_DAYS: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
```

---

## WEBSOCKET — REAL-TIME SCAN PROGRESS

```python
# backend/app/ws/scan_progress.py
"""
WebSocket endpoint for real-time scan progress updates.
Frontend connects when a scan is triggered and receives events as they happen.

Connection: ws://backend:8000/ws/scans/{scan_id}
Auth: pass JWT as query param: ?token=xxx (WebSocket headers not supported in browser)

Events pushed to client:
  {"type": "progress", "message": "Scanning api.company.com...", "pct": 35}
  {"type": "finding", "algorithm": "RSA-2048", "location": "api.company.com", "risk": "high"}
  {"type": "complete", "components_found": 23, "vulnerable": 15}
  {"type": "error", "message": "Could not reach domain"}

Implementation:
  Use FastAPI WebSocket + Redis pub/sub.
  Celery worker publishes to Redis channel: f"scan:{scan_id}"
  WebSocket handler subscribes to channel, forwards to browser.

  Manager class:
    class ScanProgressManager:
        async def connect(self, websocket, scan_id)
        async def broadcast(self, scan_id, message: dict)
        async def disconnect(self, scan_id)

  In Celery scan tasks, after each finding:
    redis_client.publish(f"scan:{scan_id}", json.dumps(event))
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.config import settings
import redis.asyncio as aredis
import json

router = APIRouter()

@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str, token: str = Query(...)):
    # Validate JWT token from query param
    # Subscribe to Redis channel for this scan
    # Forward messages to WebSocket until scan completes or client disconnects
    await websocket.accept()
    r = arides.from_url(settings.REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"].decode())
    except WebSocketDisconnect:
        await pubsub.unsubscribe(f"scan:{scan_id}")
    finally:
        await r.close()
```

---

## JAVASCRIPT / TYPESCRIPT PATTERN LIBRARY

```json
// backend/app/scanners/patterns/javascript.json
{
  "language": "javascript_typescript",
  "version": "1.2.0",
  "patterns": [
    {
      "id": "JS-CRYPTO-RSA-001",
      "description": "Node.js built-in crypto RSA key generation",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["crypto"],
      "functions": ["generateKeyPair", "generateKeyPairSync"],
      "algorithm_strings": ["rsa", "RSA"],
      "recommended_replacement": "ML-DSA-65 via pqcmap SDK",
      "estimated_effort_hours": 8
    },
    {
      "id": "JS-JWT-RS256",
      "description": "jsonwebtoken with RSA algorithm",
      "algorithm": "RSA-SHA256",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["jsonwebtoken", "jose"],
      "algorithm_strings": ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
      "recommended_replacement": "ML-DSA-65 via pqcmap JWT module",
      "estimated_effort_hours": 4
    },
    {
      "id": "JS-JWT-ES256",
      "description": "jsonwebtoken with ECDSA algorithm",
      "algorithm": "ECDSA",
      "algorithm_family": "ECC",
      "quantum_status": "vulnerable",
      "algorithm_risk": 7,
      "confidence": "high",
      "imports": ["jsonwebtoken", "jose"],
      "algorithm_strings": ["ES256", "ES384", "ES512"],
      "recommended_replacement": "ML-DSA-44 or ML-DSA-65 via pqcmap",
      "estimated_effort_hours": 4
    },
    {
      "id": "JS-CRYPTO-ECDH",
      "description": "Node.js ECDH key agreement",
      "algorithm": "ECDH",
      "algorithm_family": "ECC",
      "quantum_status": "vulnerable",
      "algorithm_risk": 7,
      "confidence": "high",
      "imports": ["crypto"],
      "functions": ["createECDH"],
      "recommended_replacement": "ML-KEM-768 via pqcmap",
      "estimated_effort_hours": 6
    },
    {
      "id": "JS-NODE-RSA",
      "description": "node-rsa package usage",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["node-rsa"],
      "recommended_replacement": "pqcmap SDK",
      "estimated_effort_hours": 8
    },
    {
      "id": "JS-FORGE-RSA",
      "description": "node-forge RSA usage",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "imports": ["node-forge", "forge"],
      "functions": ["pki.rsa.generateKeyPair", "rsa.generateKeyPair"],
      "estimated_effort_hours": 10
    }
  ]
}
```

```json
// backend/app/scanners/patterns/java.json
{
  "language": "java",
  "version": "1.0.0",
  "patterns": [
    {
      "id": "JAVA-RSA-KEYGEN",
      "description": "Java RSA key pair generation",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "high",
      "class_patterns": ["KeyPairGenerator"],
      "algorithm_strings": ["RSA"],
      "estimated_effort_hours": 12
    },
    {
      "id": "JAVA-ECDSA",
      "description": "Java ECDSA signature",
      "algorithm": "ECDSA",
      "algorithm_family": "ECC",
      "quantum_status": "vulnerable",
      "algorithm_risk": 7,
      "confidence": "high",
      "class_patterns": ["Signature"],
      "algorithm_strings": ["SHA256withECDSA", "SHA384withECDSA", "EC"],
      "estimated_effort_hours": 12
    },
    {
      "id": "JAVA-SPRING-JWT",
      "description": "Spring Security JWT with RSA",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "algorithm_risk": 8,
      "confidence": "medium",
      "imports": ["io.jsonwebtoken", "com.nimbusds.jose"],
      "algorithm_strings": ["RS256", "RS384", "RS512"],
      "estimated_effort_hours": 16
    }
  ]
}
```

---

## MIGRATION ROADMAP GENERATOR SPEC

```python
# backend/app/engines/roadmap.py
"""
Migration Roadmap Generator.
Two-phase approach:

PHASE 1 — Deterministic Rule Engine (runs always):
  For each crypto_component in CBOM, sorted by final_risk_score desc:
    Look up effort_hours from algorithm_effort_lookup table
    Assign to migration phase based on:
      - Phase 1 (0-3 months): HNDL_CRITICAL or migration_priority == 'critical'
      - Phase 2 (3-6 months): priority == 'high' and location_type in ['tls_cert', 'jwt']
      - Phase 3 (6-18 months): priority in ['medium', 'high'] and location_type == 'code'
      - Phase 4 (18-36 months): priority == 'low', internal services, config files

  For each component, the rule engine generates:
    - what_to_do: template string based on algorithm + location_type
    - effort_hours: from lookup table
    - recommended_algorithm: from NIST mapping table
    - deadline: calculated from DST/PCI framework deadlines

PHASE 2 — Claude API Narrative (runs for paid tiers):
  After rule engine generates the structure, call Anthropic API
  to generate natural-language step-by-step remediation instructions
  specific to the detected tech stack.

  Prompt template:
    "You are a senior cryptography engineer.
     This component was found in a {tech_stack} application:
     {component_detail}
     Generate specific step-by-step migration instructions to replace
     {current_algorithm} with {recommended_algorithm}.
     Include: exact code changes, library versions, testing approach.
     Format as numbered steps. Be specific and technical."

  API call:
    model: claude-sonnet-4-6
    max_tokens: 800
    temperature: 0.1 (low — we want consistent, factual output)

  Store result in: crypto_components.migration_instructions (JSONB field, add to schema)

Effort lookup table (hours):
  tls_cert_rotation: 2-4 hours
  jwt_algorithm_swap_python: 3-5 hours
  jwt_algorithm_swap_node: 3-5 hours
  jwt_algorithm_swap_java: 8-16 hours
  kms_key_rotation_aws: 4-8 hours
  ssh_key_rotation: 1-2 hours
  ecc_keygen_replace_python: 6-10 hours
  rsa_keygen_replace_python: 8-12 hours
  tls_upgrade_nginx_config: 1-2 hours
  internal_service_mtls: 8-24 hours (depends on number of services)
"""
```

---

## ALEMBIC SETUP

```bash
# Initial setup (run once)
cd backend
alembic init migrations

# migrations/env.py — add this after the imports:
from app.models import Base          # import all models so Alembic sees them
from app.config import settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
target_metadata = Base.metadata

# Create first migration
alembic revision --autogenerate -m "initial_schema"

# Apply migrations
alembic upgrade head

# After any model change:
alembic revision --autogenerate -m "describe_change_here"
alembic upgrade head
```

---

## RATE LIMITING (Public Scanner)

```python
# Add to requirements.txt:
# slowapi==0.1.9

# backend/app/routers/public.py
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)

@router.post("/scan")
@limiter.limit("1/10minutes")           # 1 request per IP per 10 minutes
async def free_scan(request: Request, domain: str):
    # Check cache first (free_scan_cache table)
    # If cached and < 24 hours old: return cached result
    # Else: run network scanner on this one domain only
    # Store in free_scan_cache
    # Return: tls_version, cert_algorithm, key_size, quantum_status, expiry
    pass
```


---

## AWS IAM POLICY (Exact JSON for Cloud Scanner)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SeQrACMRead",
      "Effect": "Allow",
      "Action": [
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:GetCertificate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SeQrKMSRead",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:ListAliases",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SeQrCloudFrontRead",
      "Effect": "Allow",
      "Action": [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SeQrAPIGatewayRead",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET"
      ],
      "Resource": [
        "arn:aws:apigateway:*::/restapis",
        "arn:aws:apigateway:*::/restapis/*"
      ]
    },
    {
      "Sid": "SeQrRDSRead",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SeQrELBRead",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeSSLPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SeQrIAMCertRead",
      "Effect": "Allow",
      "Action": [
        "iam:ListServerCertificates",
        "iam:GetServerCertificate"
      ],
      "Resource": "*"
    }
  ]
}
```

Customer instruction: "Create an IAM role with this policy. Give SeQr the role ARN.
We assume the role with STS when scanning — no long-lived credentials stored."

---

## GITHUB OAUTH FLOW (Code Scanner)

```python
"""
GitHub OAuth for code scanning (different from GitHub App — this is for
customers connecting their GitHub account to SeQr Audit dashboard).

Flow:
  1. Customer clicks "Connect GitHub" in SeQr dashboard
  2. Frontend redirects to:
     https://github.com/login/oauth/authorize
       ?client_id={GITHUB_OAUTH_CLIENT_ID}
       &redirect_uri=https://app.seqrlabs.com/auth/github/callback
       &scope=repo,read:org
       &state={random_csrf_token}

  3. GitHub redirects back with code:
     https://app.seqrlabs.com/auth/github/callback?code=xxx&state=xxx

  4. Backend exchanges code for token:
     POST https://github.com/login/oauth/access_token
     {client_id, client_secret, code}
     Returns: access_token (store encrypted in Secrets Manager, ref in assets table)

  5. SeQr uses token to:
     - List repos: GET /user/repos + GET /orgs/{org}/repos
     - Fetch file content: GET /repos/{owner}/{repo}/contents/{path}
     - Rate limit: 5000 requests/hour (authenticated)

Scope rationale:
  'repo' — access private repos (customers need this for private code scanning)
  'read:org' — list org repos
  No write scopes — SeQr never modifies code

Token storage:
  Encrypted with AES-256-GCM using per-org key
  Stored in AWS Secrets Manager (cloud) or encrypted DB field (on-prem)
  Never logged, never in error messages
"""
```

---

## EMAIL NOTIFICATION TEMPLATES

```
All emails sent via AWS SES (cloud) or SMTP (on-prem).
From: SeQr Alerts <alerts@seqrlabs.com>
Unsubscribe: link in footer (required by email law)

─── TEMPLATE 1: Scan Complete ──────────────────────────────────────────────────

Subject: SeQr Scan Complete — {org_name} · {asset_name}

Hi {user_name},

Your scan of {asset_name} is complete.

  Quantum Risk Score:   {risk_score}/100  ({risk_level})
  Findings:             {total_count} ({critical} critical, {high} high)
  HNDL Critical:        {hndl_count} assets at immediate risk

[View Full Report →]

Top 3 priority actions:
  1. {action_1} — Est. {hours_1} hours
  2. {action_2} — Est. {hours_2} hours
  3. {action_3} — Est. {hours_3} hours

─── TEMPLATE 2: Certificate Expiry Alert ────────────────────────────────────────

Subject: ⚠️ Certificate expiring in {days} days — {domain}

Hi {user_name},

The TLS certificate for {domain} expires on {expiry_date} ({days} days).

  Certificate algorithm: {algorithm}
  Issued by: {issuer}

This is an opportunity to upgrade to an ML-DSA hybrid certificate
when renewing — the same effort, but quantum-safe.

[View Certificate Details →]   [See Migration Guide →]

─── TEMPLATE 3: New Critical Finding Alert ──────────────────────────────────────

Subject: 🔴 New HNDL-Critical finding — {org_name}

Hi {user_name},

A new critical finding was detected in your latest scan:

  Asset:      {asset_name}
  Finding:    {algorithm} in {location}
  Risk:       HNDL CRITICAL — adversaries may be collecting this
              encrypted traffic today for future decryption

  Recommended action: {recommendation}
  Estimated effort:   {effort_hours} hours

[View Finding →]   [Generate Report →]

─── TEMPLATE 4: Compliance Deadline Reminder ────────────────────────────────────

Subject: Compliance deadline in {days} days — {framework_name}

Hi {user_name},

{framework_name} requires action by {deadline_date} ({days} days away).

  Your current status: {compliance_status}
  Components to fix:   {non_compliant_count}

[View Compliance Dashboard →]   [Download Compliance Report →]

─── TEMPLATE 5: Weekly Summary (subscription customers) ─────────────────────────

Subject: SeQr Weekly Summary — {org_name}

Week of {week_start} – {week_end}

PROGRESS THIS WEEK:
  Components migrated:    {migrated_this_week}
  New findings:           {new_findings}
  Risk score change:      {score_change} ({score_direction})

UPCOMING:
  {cert_expiry_count} certificates expiring in 90 days
  Next compliance deadline: {next_deadline}

[Open Dashboard →]
```

---

## DEPLOYMENT MODES (How One Codebase Runs in All Contexts)

```python
# The same FastAPI + Celery codebase runs in three deployment modes.
# Mode is controlled by DEPLOYMENT_MODE env var.

# config.py additions:
class Settings(BaseSettings):
    DEPLOYMENT_MODE: str = "onprem"  # onprem | cloud | demo

# How each mode differs:

# ONPREM mode:
#   - License required (validates offline via Ed25519)
#   - Storage: local filesystem or PostgreSQL (no S3)
#   - No telemetry (OFFLINE_MODE=true possible)
#   - Customer manages their own Docker container
#   - Updates: manual (docker pull new image)

# CLOUD mode (seqrlabs.com SaaS):
#   - No license key (billing via Stripe/Razorpay subscription)
#   - Storage: AWS S3 + RDS + ElastiCache (production AWS)
#   - Auth: NextAuth with Google SSO option
#   - Updates: automatic (blue-green deploy via GitHub Actions → ECS)
#   - Multi-tenant: strict org isolation at database level

# DEMO mode (for sales calls):
#   - No auth required (pre-seeded with demo org data)
#   - Storage: SQLite with demo data pre-populated
#   - No email sending (all notifications suppressed)
#   - Auto-resets every 24 hours (cron job restores from seed)
#   - Access at: demo.seqrlabs.com (shareable link for sales calls)

# Code example — mode-aware storage:
def get_storage_client():
    if settings.DEPLOYMENT_MODE == "cloud":
        return S3StorageClient(bucket=settings.S3_BUCKET)
    else:  # onprem or demo
        return LocalStorageClient(path=settings.LOCAL_STORAGE_PATH)
```

---

## FAQ FOR SALES CONVERSATIONS (Technical Objection Responses)

**"Can AI break your PQC algorithms?"**
No. Language models cannot perform mathematical cryptanalysis. Breaking ML-KEM
requires solving the Module Learning With Errors problem — a computational math
problem with no known quantum speedup and no AI shortcut. NIST ran 8 years of
testing with hundreds of professional cryptanalysts before finalising FIPS 203.
If you want to understand the security proofs, we can walk through them —
but there is no "just use a better AI" attack on these algorithms.

**"Why not just wait until quantum computers actually exist?"**
Two reasons. First, PCI DSS 12.3.3 and India's DST Task Force mandate cryptographic
inventories NOW — before quantum computers exist. Second, adversaries are collecting
your encrypted traffic today. A database breach of your historical API traffic today
becomes a goldmine in 2030. The threat is present even if the quantum computer is not.

**"We scan internally — why do we need you?"**
A manual scan misses things. SeQr scans 200+ cryptographic patterns across 4
languages, your cloud KMS configuration, all TLS certificates, and your SSH keys —
simultaneously, in minutes. It also maps findings to PCI DSS and DST compliance
requirements with specific remediation steps. That combination takes a senior engineer
weeks to replicate manually.

**"How is this different from Snyk or SonarQube?"**
Snyk and SonarQube scan for classical security vulnerabilities (SQL injection, XSS,
CVEs in dependencies). They do not scan for quantum-cryptographic vulnerabilities —
that's not their focus. SeQr is specifically built for one problem: identifying
and remediating quantum-vulnerable cryptography before compliance deadlines.

