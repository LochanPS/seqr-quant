# SeQr — Build Roadmap (kickoff prompts per unbuilt item)

Each item below is self-contained: paste its **Kickoff prompt** into a fresh Claude Code session
(from the `seqr-labs/` repo root) and it has enough to do the work. Follow the repo's fixed tech
stack (Python 3.12 / FastAPI / SQLAlchemy async / Celery+Redis / Postgres / Next.js 14 / Tailwind+
shadcn). Global rules that apply to every item: never emit CNSA 2.0 in Indian compliance output;
keep the HNDL disclaimer in reports/CLI/API; `seqr scan code` stays exit-0 by default; every REST
route scopes `org_id`; write tests alongside code.

**Suggested sequence (leverage order):** B1 (SDK publish) → A6 (async workers) → A4 (AgentCore) →
A3 (agent plugins) → B2 (GitHub App live) → A5 (enterprise table-stakes) → A7 (more TLS services) →
B3 (appliance) → A2 (ML-DSA CA) → A1 (Gateway).

---

## A1 — SeQr Gateway (PQC-terminating reverse proxy)

**Goal:** an NGINX/reverse-proxy box that terminates client TLS with a hybrid PQC group and
re-originates to the (classical) backend, so a customer becomes "hybrid at the edge" with no app
change. **Status:** NOT STARTED (`docs/03_Gateway_PRD.md`); largely folded into the migration
engine, so scope it as a *migration-engine output*, not a separate SKU.

**Kickoff prompt:**
> Read `docs/03_Gateway_PRD.md` and `docs/14_Migration_Engine_PRD.md`. Build the SeQr Gateway as a
> generated artifact of the migration engine: given a target asset in the spine, emit a ready-to-run
> reverse-proxy bundle (NGINX or Caddy) configured for hybrid PQC key exchange (X25519MLKEM768 via
> OpenSSL 3.5) in front of a classical origin, plus a runbook. Add a `gateway` bundle type to the
> migration engine's change-bundle output (`app/spine/` migration code), a template config, and a
> smoke test that boots the proxy in Docker and confirms it negotiates the hybrid group with an
> OpenSSL 3.5 client. Do NOT build a hosted gateway service; this is a downloadable, self-hosted
> bundle. Keep it advisory: it generates config, it does not touch live infra.
**Acceptance:** `docker compose` boots the generated gateway; an OpenSSL 3.5 probe negotiates
`X25519MLKEM768`; bundle + runbook are produced from a spine asset; tests green.

---

## A2 — ML-DSA certificate issuance / PQC CA

**Goal:** issue post-quantum (ML-DSA / FIPS 204) certificates, the "future module" referenced in
`docs/13` and `docs/14`. **Status:** future module, not started.

**Kickoff prompt:**
> Read `docs/13_Platform_Spine_PRD.md` (policy `certificate.min`) and `docs/14`. Build a minimal
> internal PQC CA module: generate an ML-DSA-65 (and -87) CA keypair, issue X.509 certificates with
> ML-DSA signatures (use `cryptography` + liboqs where needed; if the native lib is absent, degrade
> gracefully and mark unavailable — mirror `pqcmap.available()`). Wire it as a migration-engine
> capability: for an asset whose policy requires PQC certs, emit an issued cert + chain into the
> change bundle. Add policy evaluation so an asset with a classical cert is flagged against
> `certificate.min`. Tests: issue → verify signature → verify chain; skip cleanly when liboqs is
> absent. This is internal PKI for pilots, not a public CA.
**Acceptance:** ML-DSA cert issues and verifies; policy flags classical certs; graceful skip without
liboqs; tests green.

---

## A3 — Discovery-agent plugins beyond TLS (+ air-gap import, runtime packaging)

**Goal:** extend the discovery agent from TLS-only (built) to cert stores, HSMs, internal PKI, load
balancers, reverse proxies; finish the signed air-gap import (Slice 2) and package a runtime binary
(Slice 3). **Status:** `docs/15` DEFERRED; only the TLS probe exists (`deploy/agent/discovery_agent.py`,
+ backend `app/routers/agent.py`, `app/spine/agent_ingest.py`, `app/spine/agent_sig.py`).

**Kickoff prompt:**
> Read `docs/15_Discovery_Agent_Design.md` end-to-end. The agent-ingest backend + Ed25519 signing +
> TLS probe already exist. Build: (1) a **plugin interface** so the agent runs multiple collectors;
> (2) collectors for **local certificate stores** (filesystem PEM/DER + OS trust store), **reverse
> proxies / load balancers** (parse NGINX/HAProxy configs for TLS params), and a **stub HSM/PKCS#11**
> collector (enumerate slots/mechanisms, no key extraction). Each collector emits `AgentObservationIn`
> records matching the existing schema. (3) Finish **Slice 2 signed air-gap import**: the agent writes
> a signed `AgentImportEnvelope` to a file offline; verify the `POST /api/v1/agent/import` path
> end-to-end. (4) **Slice 3 packaging**: build the agent into a single distributable (PyInstaller or a
> slim Docker image) with a config file for targets + credential. Keep the agent read-only (no infra
> changes) and every batch Ed25519-signed. Tests per collector + an air-gap import round-trip.
**Acceptance:** agent runs ≥3 collector types; air-gap envelope imports and verifies; a single
packaged binary/image runs from a config file; observations land in the spine; tests green.

---

## A4 — Bedrock AgentCore integration

**Goal:** run the discovery/analysis agent on **AWS Bedrock AgentCore Runtime** with a Bedrock model
as its reasoning engine, so it autonomously scans, assesses quantum risk, and proposes a migration
order. **Status:** not built (AWS roadmap).

**Kickoff prompt:**
> Read `docs/15` and the agent-ingest API (`app/routers/agent.py`). Wrap SeQr's scan + spine tools as
> an AgentCore agent: (1) enable Bedrock model access in `ap-south-1` (Claude on Bedrock or Nova);
> (2) expose SeQr capabilities as **AgentCore Gateway tools** — `scan_domain`, `get_cbom`,
> `get_policy_violations`, `propose_migration_order` — backed by the existing FastAPI endpoints or
> Lambda shims; (3) author an AgentCore Runtime entrypoint that, given a target org, calls the tools,
> reasons over the CBOM + HNDL + compliance data, and returns a prioritized migration plan; (4) use
> **AgentCore Memory** to persist scan context across turns; (5) surface the agent's trace in the
> dashboard (or CloudWatch). Deploy the runtime container to ECR → AgentCore. Keep it advisory: the
> agent proposes, humans apply. Provide IaC (or a scripted setup) + a demo script that runs one full
> autonomous audit. Do not hardcode credentials; use IAM roles.
**Acceptance:** the agent runs on AgentCore Runtime, calls ≥3 tools, returns a prioritized migration
plan for a real org, and its trace is viewable; teardown scripted.

---

## A5 — Enterprise table-stakes (SSO, RBAC depth, audit logging, backups)

**Goal:** the enterprise controls a regulated buyer requires (`docs/12 §8.8`). **Status:** not built;
today it's JWT + basic roles.

**Kickoff prompt:**
> Read `docs/12_Product_Strategy.md` §8 and the auth stack (`app/routers/auth.py`, `app/security.py`,
> `app/models/user.py`). Add, incrementally: (1) **SSO** via OIDC/SAML (start OIDC — Authlib) mapping
> IdP groups → SeQr roles; (2) **RBAC depth** — a permission matrix beyond admin/member (viewer,
> operator, auditor) enforced in `deps.py`; (3) **audit logging** — an append-only `audit_events`
> table capturing who/what/when for every mutating action, exposed at `/api/v1/admin/audit` with
> filters; (4) **backups** — a documented + scripted Postgres backup/restore (pg_dump to object
> storage) in `deploy/`. Preserve multi-tenant `org_id` scoping throughout; add tenancy tests for the
> new permission levels. Migrations via Alembic.
**Acceptance:** OIDC login works end-to-end; role matrix enforced with tests; every mutation writes an
audit event; backup + restore verified; tenancy tests green.

---

## A6 — Async scan workers at scale

**Goal:** move scans off the request thread to a real Celery worker pool so large inventories scan
concurrently with live WS progress. **Status:** currently `CELERY_ALWAYS_EAGER=true` (inline);
`docs/11`, `docs/12` flag the need for a job queue + paid worker.

**Kickoff prompt:**
> Read `docs/11_Scanner_Hardening_Roadmap.md`. The Celery tasks exist (`app/tasks/` / `scan_tasks.py`)
> but run eagerly. Stand up a real worker: (1) a `worker` service in `deploy/` (its own Dockerfile) on
> Redis; (2) set `CELERY_ALWAYS_EAGER=false`, verify `/api/v1/assets/{id}/scan` enqueues and returns a
> job id immediately; (3) drive the existing WS progress channel (`/ws/scans/{id}`) from the worker so
> the frontend scan page streams live steps; (4) add concurrency limits + a per-org rate cap so one
> tenant can't starve others; (5) a batch-scan endpoint to scan every asset in an org. Keep the WS
> org-boundary check intact. Load-test with ~100 assets. Provide compose for backend+worker+redis+db.
**Acceptance:** scans run on a separate worker (not eager); WS streams live progress; 100-asset batch
completes concurrently; per-org caps enforced; tenancy on WS preserved; tests green.

---

## A7 — More TLS-bearing services (MongoDB, AMQP, gRPC-over-TLS)

**Goal:** extend protocol coverage beyond web/SSH/SMTP/IMAP/POP3/Postgres. **Status:** `docs/11` P1;
MySQL deferred (sslyze limitation).

**Kickoff prompt:**
> Read `docs/11_Scanner_Hardening_Roadmap.md` P1 and `shared-scanner/scanner/network.py` (the
> `protocol=` STARTTLS/opportunistic-TLS path). Add scanners for **MongoDB** (TLS handshake + cert),
> **AMQP** (RabbitMQ over TLS), and **gRPC-over-TLS** (ALPN `h2`), reusing the existing TLS analysis +
> active PQC probe. For each: a protocol handler that opens the connection, extracts the cert +
> negotiated group, and returns a `DomainScanResult`. Add asset types in the backend `AssetCreate`
> path + `AddAssetDialog.tsx`. Live-verify against a public or Docker-hosted instance of each. Note
> MySQL stays deferred (sslyze can't). Tests per protocol (mock + one live/integration each).
**Acceptance:** MongoDB, AMQP, gRPC/TLS scan and produce cert + PQC-group results; new asset types
selectable in the UI; tests green; MySQL limitation documented.

---

## B1 — Publish pqcmap SDK (PyPI / npm / pkg.go.dev)

**Goal:** release the built SDK. **Status:** built + tested (`pqcmap/`, `pqcmap-js/`, `pqcmap-go/`),
release workflow exists (`.github/workflows/pqcmap.yml`), gated on a git tag.

**Kickoff prompt:**
> The SDK is built and tested in all three languages. Do a release readiness pass, do NOT invent
> functionality. Python: confirm `pqcmap/pyproject.toml` metadata, `py.typed`, LICENSE, CHANGELOG,
> and the `pqcmap-v*` tag → TestPyPI dry-run → PyPI (OIDC) workflow; run the full test matrix locally
> first. JS (`pqcmap-js/`, `@seqr/pqc`): verify `package.json`, types, `npm publish --dry-run`. Go
> (`pqcmap-go/`): verify module path + `go test ./...`, prep the `pkg.go.dev` tag. Produce a single
> `RELEASE_CHECKLIST.md` and the exact tag commands. Publishing itself is gated on the founder pushing
> the tag — stop at "ready to tag," do not publish.
**Acceptance:** all three dry-runs pass; `RELEASE_CHECKLIST.md` with exact tag/publish commands;
nothing published without an explicit founder tag.

---

## B2 — GitHub App: register + activate

**Goal:** take the built hosted GitHub App live (webhook → PR scan → inline review + status).
**Status:** code built (`app/github_app/`, `docs/07`, `docs/GITHUB_APP_OPERATIONS.md`); backend was
readied this session (`deploy/aws/configure_github_app.sh`, webhook secret set); needs registration.

**Kickoff prompt:**
> Read `docs/GITHUB_APP_OPERATIONS.md` and `app/github_app/`. The webhook receiver, installation-token
> minting, diff scan, and review/status posting are built and the deploy box has `GITHUB_WEBHOOK_SECRET`
> set + a `configure_github_app.sh` finalizer. Complete go-live: (1) register the GitHub App (permissions
> Contents:read, PRs:read/write, Statuses:read/write; subscribe to Pull request; webhook →
> `/api/v1/github/webhook`); (2) run `configure_github_app.sh <APP_ID> <pem>` to set env + enable; (3)
> install on a test repo, open a PR adding `RS256`/`import rsa`, and verify the inline review + `seqr/pqc`
> status appear; (4) confirm the optional dashboard sync writes a `CIReport`. Then prep (not submit) the
> Marketplace listing. Keep advisory-by-default (`GITHUB_APP_FAIL_ON` empty).
**Acceptance:** a real PR gets a SeQr review + commit status; dashboard sync verified; Marketplace
listing drafted but not submitted.

---

## B3 — On-prem / air-gapped appliance bundle

**Goal:** a Docker bundle a pilot runs fully offline (Milestone 2). **Status:** offline Ed25519 license
built; full packaging partial.

**Kickoff prompt:**
> Read `ROADMAP_SESSIONS.md` Milestone 2 and the license validator (`app/license/validator.py`,
> `OFFLINE_MODE`). Package the whole stack (backend + worker + Postgres + Redis + frontend) as an
> air-gapped bundle: pinned images (no pulls at runtime), a `.env` template, an offline license check
> at boot (`DEPLOYMENT_MODE=onprem` requires a valid `LICENSE_KEY`), zero outbound network calls
> (verify with an egress-blocked test), and a one-command installer + operator runbook. Include a
> smoke test that boots the bundle with network disabled and runs register → scan → CBOM → report.
> Data stays on the box (sovereignty). Reuse `docker-compose.oracle.yml` as the base.
**Acceptance:** bundle boots offline (egress blocked), enforces the license, and completes
scan→CBOM→report with no external calls; installer + runbook included.

---

*Generated 2026-09-20. Keep in sync with `docs/12 §8`, `ROADMAP_SESSIONS.md`, and `CLAUDE.md` build status.*
