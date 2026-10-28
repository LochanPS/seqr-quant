# SeQr — Execution Roadmap (session-by-session)

**Created:** 2026-08-20 · **Owner:** Lochan · **Repo:** `seqr-labs/` (git, branch `main`, HEAD `1d8032f`)

This is the operational plan. Each **Session** below is self-contained: copy its **Kickoff prompt**
into a fresh Claude Code session and it will have everything it needs to do that milestone's work.
Run sessions roughly in order — Milestone 0 unblocks everything else.

---

## 1. What we're building

**SeQr** — a post-quantum cryptography (PQC) migration platform for Indian regulated infra
(BFSI / PSU / govt). It:

1. **Discovers** quantum-vulnerable crypto (TLS, certs, code, SSH, SMTP) — active + passive scanner.
2. Builds a **CBOM** (CycloneDX 1.6 crypto bill of materials) mapped to Indian compliance
   (PCI DSS 12.3.3, SEBI CSCRF live now; RBI Q-SAFE / DST 2027 emerging).
3. **Migrates** — the migration engine converges *actual crypto posture → policy* via a signed
   change bundle + runbook. **This is the real product** (founder: verify/guide are internal steps,
   not SKUs).
4. **Attests** — signed, offline-verifiable posture certificates (Ed25519).

**Business shape:** on-prem / air-gapped appliance = flagship revenue (sovereignty premium); SaaS =
funnel feeding on-prem upsell. Ecosystem order: Scanner → Spine → **Migration Engine** → SeQr SDK → SeQr CI.

## 2. Where we are (stage)

- **MVP built, pre-revenue, pre-incorporation.** Hit **RC1 engineering-freeze 2026-07-12**.
- **Shipped (committed, HEAD `1d8032f`):** scanner, CLI (`seqr` on PyPI 0.1.1), audit backend
  (FastAPI, ~96 tests), audit frontend (Next.js dashboard + landing), platform spine (state graph +
  policy), migration engine Phase 2, SVG crypto-asset graph explorer, admin console, blog CMS.
- **Built but NOT committed (dirty working tree — verified 2026-08-20):**
  - Attestation module (signed cert + PDF + offline `seqr verify-attestation` + UI)
  - Oracle Mumbai deploy bundle (`docker-compose.oracle.yml`, `deploy/`)
  - Public "Try It Live" CBOM (`scan-demo-service/main.py`, `TryItLive.tsx`)
- **Built ahead of schedule (2026-08-20, uncommitted → now committed):** SeQr SDK v0
  (`pqcmap/`) and SeQr CI v0 (`seqr ci` + `.github/actions/seqr-pqc`). Both are local/static
  — no live backend needed. Not yet published (SDK → PyPI) / not yet enabled on this repo's PRs.
- **Deferred (post first customer):** discovery agent; hosted GitHub Marketplace app; pqcmap ports
  (Node/Go) + hosted KMS.

## 3. ⚠ Live-state reality check (verified 2026-08-20 — supersedes older memory)

| Thing | Status now | Action |
|---|---|---|
| Frontend `www.seqrlabs.com` | **UP** (Vercel static, 200) | but its API target is dead |
| Backend `seqr-backend.onrender.com` | **DOWN** — no response in 180s | Render free Postgres is deleted after 30 days; deploy was 2026-06-28 (~day 53). Backend almost certainly crash-loops on missing DB → login/dashboard broken |
| Uncommitted work | 3 finished modules sitting in dirty tree | **commit + push first** or it's one `git checkout` from gone |
| Public CBOM demo | built, **never deployed** | separate `seqr-scan-demo` Render service |

**Bottom line:** the app looks live (landing loads) but the authenticated product is down and three
finished features are uncommitted. Milestone 0 fixes both before any outreach.

---

# Roadmap

## Milestone 0 — Ship what's done + restore live (THIS WEEK, operational)
Goal: clean git tree, everything committed/pushed, a working live demo again.

## Milestone 1 — Migration engine → demoable, hardened core
Goal: the migration engine (the actual product) runs end-to-end as a clean, recorded demo on the
5 sector templates; edges/gaps hardened.

## Milestone 2 — On-prem appliance packaging
Goal: air-gapped Docker bundle a pilot can run offline (offline Ed25519 license already built).

## Milestone 3 — Customer discovery + GTM (parallel, non-code)
Goal: 15 discovery conversations; validate migration-engine scope; pick first discovery-agent source.

## Milestone 4 — Discovery agent v1 (only after a pilot commits)
## Milestone 5 — SeQr SDK / SeQr CI (v0 built; see Product tracks below)

---

# Sessions

> Each session is a fresh Claude Code run. Paste the **Kickoff prompt** verbatim. Every prompt tells
> the model to read `CLAUDE.md` + this file first, and to verify live state instead of trusting memory.

---

### Session 0.1 — Commit & push the three finished modules
**Milestone 0. ~30 min. No new code.**

Deliverables:
- [ ] Review dirty tree; group into 3 logical commits (attestation / oracle-bundle / public-CBOM-demo)
- [ ] Run the relevant test suites before committing (CLI `verify-attestation`, backend attest/spine)
- [ ] Commit + push to `origin/main`; confirm clean tree

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md and seqr-labs/docs/ROADMAP_SESSIONS.md first. We are doing Session 0.1.
The working tree has three finished-but-uncommitted modules: attestation, the Oracle deploy bundle,
and the public "Try It Live" CBOM. Run `git status`, review every changed/new file, run the
relevant tests (CLI verify-attestation tests, backend attest/spine tests, frontend tsc --noEmit),
then create three clean logical commits and push to origin/main. Do not change behavior — this is a
commit-hygiene session. Report the final `git log` and `git status`.
```

---

### Session 0.2 — Restore a live backend (Oracle Mumbai move)
**Milestone 0. Founder does account/DNS steps; I do deploy config + verify.**

Deliverables:
- [ ] Decide: revive Render (fast, ₹0 but 30-day-PG problem returns) **or** execute Oracle Mumbai
      move (permanent, ₹0, fixes data-residency). Roadmap recommends **Oracle**.
- [ ] Founder: Oracle A1 VM in `ap-mumbai-1`, ingress 80/443, A-record `api.seqrlabs.com` → VM IP
- [ ] Bring up `docker-compose.oracle.yml` (remember `--env-file deploy/oracle/.env`)
- [ ] Repoint Vercel `NEXT_PUBLIC_API_URL=https://api.seqrlabs.com/api/v1`, redeploy
- [ ] Live-verify: `/api/v1/health`, login `demo@seqrlabs.com`, posture → graph, zero console errors

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md and seqr-labs/docs/ROADMAP_SESSIONS.md first. Session 0.2: restore the
live backend. As of 2026-08-20 the Render backend is DOWN (free Postgres deleted after 30 days).
The Oracle Mumbai deploy bundle is already in the repo (docker-compose.oracle.yml + deploy/oracle/).
Walk me through executing the Oracle move: tell me exactly which account/DNS steps I (the founder)
must do myself, then help me bring up the stack and verify. Every compose command needs
`--env-file deploy/oracle/.env`. After it's up, repoint Vercel NEXT_PUBLIC_API_URL and live-verify
the full demo flow in real Chrome (login → posture → graph). If Oracle A1 hits "out of host
capacity", give me the Render-revival fallback instead.
```

---

### Session 0.3 — Deploy public CBOM demo + attest live-verify
**Milestone 0.**

Deliverables:
- [ ] Deploy `seqr-scan-demo` (scan-demo-service) → live "Try It Live" ending in downloadable CBOM
- [ ] Verify CBOM download (`.cdx.json`, CycloneDX 1.6, HNDL disclaimer present) in real Chrome
- [ ] Live-verify attestation: generate cert → download PDF + signed JSON → `seqr verify-attestation`

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md and seqr-labs/docs/ROADMAP_SESSIONS.md first. Session 0.3. Two deploys to
finish: (1) the public "Try It Live" CBOM lives in scan-demo-service (separate Render service
seqr-scan-demo, scan-demo-service/render.yaml) and was never deployed — deploy it and verify a live
scan ends in a downloadable CycloneDX 1.6 CBOM with the HNDL disclaimer. (2) Attestation was never
live-verified in a browser — on the now-live backend, generate an attestation, download the PDF +
signed JSON, and confirm `seqr verify-attestation <file>` returns exit 0 offline. Report proof
(screenshots / CLI output).
```

---

### Session 1.1 — Migration engine: end-to-end demo recording
**Milestone 1. Depends on 0.2 (live backend) or run locally.**

Deliverables:
- [ ] Drive the full migration lifecycle on all 5 sector templates: discover → policy → plan →
      bundle+runbook → verify → attest
- [ ] Record a clean walkthrough (GIF/video or screenshot sequence) — the sales demo asset
- [ ] Log any rough edges into a punch-list for 1.2

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/13_Platform_Spine_PRD.md, docs/14_Migration_Engine_PRD.md, and
docs/ROADMAP_SESSIONS.md first. Session 1.1. Migration engine Phase 2 is shipped (app/migration/,
app/spine/). Drive the complete lifecycle — discover → policy → plan → signed change bundle +
runbook → verify → attest — across all 5 sector templates, end to end. Produce a clean recorded
demo walkthrough (the core sales asset) and a punch-list of every rough edge, confusing label, or
gap you hit. Do not fix them yet — Session 1.2 does that. Deliver: demo asset + punch-list.
```

---

### Session 1.2 — Migration engine: harden the punch-list
**Milestone 1. Consumes 1.1's punch-list.**

Deliverables:
- [ ] Fix top correctness/UX issues from 1.1 (bundle/runbook clarity, policy edge cases, error states)
- [ ] Tests alongside each fix; keep suites green
- [ ] Update `docs/14_Migration_Engine_PRD.md` status if scope moved

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/14_Migration_Engine_PRD.md, and docs/ROADMAP_SESSIONS.md first.
Session 1.2. Take the migration-engine punch-list from Session 1.1 (ask me to paste it) and fix the
highest-impact correctness and UX issues in app/migration/ + app/spine/. Write tests alongside each
fix, keep all suites green, follow the tech-stack + output-language rules in CLAUDE.md (no
"QUANTUM: FAIL", HNDL disclaimer everywhere, exit 0 by default). Commit per logical fix.
```

---

### Session 2.1 — On-prem air-gapped appliance bundle
**Milestone 2.**

Deliverables:
- [ ] Air-gapped Docker Compose bundle (no external egress) that runs the full spine + migration engine
- [ ] Offline Ed25519 license gate wired (`DEPLOYMENT_MODE=onprem`, `OFFLINE_MODE=true`)
- [ ] `DEPLOY_ONPREM.md` install guide; smoke-test the bundle from a clean machine

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/12_Product_Strategy.md, and docs/ROADMAP_SESSIONS.md first.
Session 2.1. Build the on-prem / air-gapped appliance bundle — the flagship SKU. Produce a Docker
Compose stack with zero external egress that runs the full spine + migration engine + attestation,
gated by the existing offline Ed25519 license validator (DEPLOYMENT_MODE=onprem, OFFLINE_MODE=true).
Reuse docker-compose.oracle.yml as a starting point. Write DEPLOY_ONPREM.md and smoke-test from a
clean checkout. No cloud dependencies, no telemetry.
```

---

### Session 3.1 — Customer discovery kit + tracker (non-code)
**Milestone 3. Parallel with everything.**

Deliverables:
- [ ] 15-conversation discovery script targeting BFSI/PSU crypto+compliance owners
- [ ] Questions that validate migration-engine scope + surface first discovery-agent source
- [ ] Tracker (who / stage / notes / commit-to-pilot signal)

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/05_Business.md, MARKETING.md, and docs/ROADMAP_SESSIONS.md first.
Session 3.1. Build the customer-discovery kit: a 15-conversation interview script for Indian
BFSI/PSU crypto & compliance owners that (a) validates whether the migration engine solves a real
paid problem, and (b) surfaces which internal discovery-agent source to build first (K8s vs cloud
control-plane vs PKCS#11 HSM vs cert stores). Add a simple tracker. This is GTM, not code — no
repo changes needed beyond the doc.
```

---

### Session 4.1 — Discovery agent v1 (GATED — only after a pilot commits)
**Milestone 4. Do NOT start until Session 3.1 yields a committed pilot needing internal inventory.**

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/15_Discovery_Agent_Design.md, and docs/ROADMAP_SESSIONS.md first.
Session 4.1. GATE CHECK: only proceed if a design partner has committed to a pilot requiring
internal inventory (per docs/15 §1). If not, stop and tell me to run Milestone 3 first. If gated
open, build discovery-agent v1 for ONLY the source(s) the pilot needs — read-only, writes into the
spine via authenticated APIs, air-gap deployable. Infrastructure only (SDK/CI own code crypto).
```

---

### Session 5.1 — SeQr SDK / SeQr CI — ✅ v0 DONE 2026-08-20
**Milestone 5. Built early (both are local/static, no live backend needed).** SeQr SDK v0
(`pqcmap`) in `pqcmap/`; SeQr CI v0 = `seqr ci` + `.github/actions/seqr-pqc` (34 tests). Now split
into the two Product tracks below (SDK-1.. / CI-1..). Remaining: publish `pqcmap` to PyPI, enable
the PQC-scan workflow on this repo's PRs, then the deferred hosted pieces (Marketplace app, Node/Go
ports, hosted KMS) when a customer pulls.

**Kickoff prompt:**
```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, docs/07_GitHub_App_PRD.md, and
docs/ROADMAP_SESSIONS.md first. Session 5.1. This is deferred until a customer pulls for it —
confirm that's still true with me before writing code. If greenlit, scope pqcmap SDK v0 (enforce
policy in application code) from docs/02.
```

---

# Product tracks: SeQr SDK & SeQr CI

Two shipping products under the SeQr umbrella, each with a v0 already built + pushed
(2026-08-20). Each track below is a ladder of self-contained sessions — paste a
**Kickoff prompt** into a fresh Claude Code run to execute it. Every prompt tells the
model to read `CLAUDE.md` + this file first, verify current state, write tests
alongside, and commit per logical unit. Do NOT change the tech stack or output-language
rules in CLAUDE.md.

> **v0 state (both):** `pqcmap/` = SDK (KEM, Signature, HybridKEM, PQCToken,
> LocalKeyStore; real FIPS 203/204 via pure-python `kyber-py`+`dilithium-py`, liboqs
> optional; 58 tests). `seqr ci` + `.github/actions/seqr-pqc` = CI gate (diff-aware,
> `--fail-on`/`--policy`, Markdown review; 34 tests). Neither is published/enabled yet.

---

## Track A — SeQr SDK (`pqcmap`)
Goal: turn the v0 library into a published, policy-enforcing OSS product — the
code-level arm of the lifecycle (docs/02, docs/13).

### SDK-1 — Publish to PyPI + release automation  ✅ DONE 2026-08-21
Deliverables: `py.typed`, LICENSE (MIT), classifiers, long-description; a
build+test+publish GitHub Actions matrix (Linux/macOS/Windows × 3.10-3.12) that runs
the suite on the real backend and publishes wheels/sdist on tag; TestPyPI dry-run;
`seqr`/`pqcmap` version policy. Result: `pip install pqcmap` works for anyone.
Shipped: `pqcmap/{py.typed,LICENSE,CHANGELOG.md,RELEASING.md}`, expanded pyproject,
`.github/workflows/pqcmap.yml` (OIDC trusted publish, tag `pqcmap-v*`). Build + clean-venv
install verified locally; twine check PASSED. **Real upload still gated on pushing the tag.**

```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, and docs/ROADMAP_SESSIONS.md first.
Session SDK-1. pqcmap v0 lives in pqcmap/ (real FIPS crypto via kyber-py+dilithium-py,
liboqs optional, 58 tests). Prepare it for PyPI publication: add py.typed, an MIT
LICENSE file, full pyproject metadata (classifiers, urls, long_description from
README), and a GitHub Actions workflow that (a) runs the pqcmap suite on Linux/macOS/
Windows across Python 3.10-3.12 on the real backend, and (b) builds sdist+wheels and
publishes to PyPI on a version tag (via trusted publishing / OIDC, no stored token),
with a TestPyPI dry-run job. Do not publish for real — leave the final upload gated on
me pushing the tag. Verify the build locally (python -m build) and that the wheel
installs+imports in a clean venv. Commit per logical unit.
```

### SDK-2 — Policy enforcement in code  ✅ DONE 2026-08-21
Deliverables: `pqcmap.policy` — load a SeQr crypto policy (algorithms allowed/required,
min NIST level), and enforce it in application code: `assert_compliant(alg)`, a
`@requires_pqc` guard, and a checked factory (`pqcmap.compliant.KeyEncapsulation()` that
refuses a below-policy algorithm). Ties the SDK to the spine policy schema (docs/13).
Shipped: reuses the spine `{"rules":[...]}` body (`family_in`/`family_not_in`/`min_key_size`
+ new `min_nist_level`; slots → kind), `PolicyViolationError`, active-policy + `PQCMAP_POLICY`
env, default = no quantum-vulnerable families / NIST L3+. 41 new tests (99 total, green).

```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, docs/13_Platform_Spine_PRD.md, and
docs/ROADMAP_SESSIONS.md first. Session SDK-2. Add policy enforcement to pqcmap so
application code cannot silently fall back to quantum-vulnerable crypto. Build a
pqcmap.policy module that loads a crypto policy (reuse the spine's policy shape from
docs/13 / app/spine where practical — read it, don't invent a parallel schema) and
enforces it: assert_compliant(algorithm), a decorator/guard for functions that mint
keys or sign, and policy-checked constructors that raise a clear PolicyViolationError
for a below-policy algorithm (e.g. min NIST level). Tests alongside; keep the real
backend green. Commit per logical unit.
```

### SDK-3 — Framework drop-ins (JWT / TLS / HTTP)  ✅ DONE 2026-08-21
Deliverables: a PyJWT-compatible `algorithms` shim + a FastAPI/Flask auth example on
`PQCToken`; a best-effort PQC TLS context builder (`pqcmap.tls`, liboqs/OpenSSL 3.5+);
httpx/requests helper. Real migration ergonomics for the most common cases.
Shipped: `pqcmap.jwt` PyJWT-shaped `encode`/`decode`/`get_unverified_header` + PyJWT-named
errors (also `PQCTokenError`), `examples/fastapi_auth.py`; `pqcmap.tls.build_client_context`
(negotiates X25519MLKEM768 when the runtime allows, degrades to classical TLS 1.3) +
honest `capabilities()`/`report()`; `pqcmap.tls.http` httpx/requests helpers +
`examples/tls_client.py`. MTU/fragmentation caveat documented. +53 tests (152 total).

```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, and docs/ROADMAP_SESSIONS.md first.
Session SDK-3. Add drop-in framework integrations to pqcmap so migrating is a few-line
change: (1) a PyJWT-shaped adapter around PQCToken plus a runnable FastAPI auth example
(login issues an ML-DSA JWT, a dependency verifies it); (2) pqcmap.tls — a best-effort
PQC-hybrid TLS context builder that negotiates X25519MLKEM768 when the runtime supports
it (OpenSSL 3.5+/liboqs) and degrades cleanly otherwise, with an honest capability
report; (3) a small httpx/requests helper using that context. Tests + examples;
document the MTU/fragmentation caveat from docs/02. Commit per logical unit.
```

### SDK-4 — Key management: hosted KMS client + local-store hardening  ✅ DONE 2026-08-21
Deliverables: `pqcmap.kms.hosted` (the PRD's HostedKMS client — authenticated, envelope
encryption, key ids), rotation policies, and hardening of LocalKeyStore (per-key
metadata, export/import, audit log). Pairs with the SeQr hosted KMS SKU.
Shipped: `HostedKMS` (bearer `sq_live_` auth, envelope encryption under a KMS-held master
key, key-id addressing, self-describing encrypt/decrypt, status→KMSError/KMSAuthError/
KMSKeyNotFoundError, pluggable/mockable transport over PQC-hybrid TLS); LocalKeyStore
`RotationPolicy` (age/usage) + `needs_rotation`/`rotate_if_needed`, `export_key`/
`import_key`, and an append-only hash-chained tamper-evident audit log. Offline paths stay
real; hosted HTTP mocked. On-disk schema v2 (v1 still loads).

```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, and docs/ROADMAP_SESSIONS.md first.
Session SDK-4. Build the key-management layer. Implement pqcmap.kms.hosted.HostedKMS
(the PRD's hosted client): authenticated calls to a SeQr KMS endpoint, envelope
encryption of data keys under a KMS-held master key, key-id addressing, and the
KMSError/KMSAuthError paths already defined. Harden LocalKeyStore: rotation policy
(age/usage), export/import of a single key, and an append-only local audit log of
key operations. Mock the hosted HTTP in tests; keep offline paths fully real. Commit
per logical unit.
```

### SDK-5 — Docs, benchmarks, migration cookbook  ✅ DONE 2026-08-21
Deliverables: a docs site (or docs/ markdown set) with the migration cookbook, a
benchmark script producing real pure-python-vs-liboqs numbers on this machine, and a
"find with `seqr` → fix with `pqcmap`" worked example end to end.
Shipped (4 commits): `pqcmap/docs/COOKBOOK.md` (RS256/ES256-JWT, RSA-sign, ECDSA,
ECDH/X25519, RSA-OAEP → pqcmap; every "after" snippet run for real by
`examples/cookbook_recipes.py`); `pqcmap/benchmarks/benchmark.py` (live keygen/encap/
decap/sign/verify for every installed backend + RSA-2048 baseline, no invented numbers)
with a committed `docs/BENCHMARKS.md` snapshot; `pqcmap/examples/worked_migration/`
(`seqr scan code` → 5 findings → pqcmap fix → re-scan clean); README/CHANGELOG wired.
Suite 160 pass / 1 skip (liboqs). liboqs absent on the build machine, so the benchmark
reports pure-python only, honestly labelled.

```
Read seqr-labs/CLAUDE.md, docs/02_SDK_PRD.md, and docs/ROADMAP_SESSIONS.md first.
Session SDK-5. Produce the SDK's docs + proof. Write a migration cookbook (RSA/ECDSA/
RS256-JWT/ECDH → pqcmap equivalents), a runnable benchmark script that reports real
keygen/encap/sign/verify timings for both backends on the current machine (no invented
numbers), and an end-to-end worked example that runs `seqr scan code` on a small vuln
sample then fixes it with pqcmap and re-scans clean. Wire it into the README/docs.
Commit per logical unit.
```

### SDK-6 — Node + Go ports  🔄 IN PROGRESS 2026-08-21 (founder waived the PyPI-traction gate)
Gate note: pqcmap is 404 on PyPI (never published → zero installs). The founder confirmed
the traction gate is a prioritisation signal, not a technical prerequisite, and greenlit
starting. Full plan + interop contracts: `PORTS.md`. **Three-way interop proven live** (see
below): the hybrid KDF matches across Python/JS/Go byte-for-byte, and a Go-signed ML-DSA JWT
verifies in both Python and JS.
- **`@seqr/pqc` (npm) — built + verified (42 node:test pass).** `pqcmap-js/`: real FIPS via
  `@noble/post-quantum` (no mock). KeyEncapsulation / Signature / HybridKEM / KeyPair / meta /
  error family; PQCToken + PyJWT-shaped `@seqr/pqc/jwt`; policy engine (CryptoPolicy over the
  spine `{rules:[...]}`, assertCompliant, requiresPqc, `compliant.*`); **LocalKeyStore**
  (AES-256-GCM, rotation, export/import, hash-chained audit — on-disk format interoperable with
  Python), **HostedKMS** (envelope, pluggable transport), **`@seqr/pqc/tls`** (X25519MLKEM768 on
  OpenSSL 3.5+); `index.d.ts`; benchmark + `docs/BENCHMARKS.md` + examples. Pending: npm publish.
- **`pqcmap-go` — built + verified, FULL parity (`go test ./...`, 24 tests, vet clean).**
  `pqcmap-go/` (Go 1.27 / circl v1.6.1): metadata + error family; KeyEncapsulation/Signature
  (circl kem.Scheme/sign.Scheme); HybridKEM (stdlib crypto/ecdh + crypto/hkdf);
  EncodeToken/DecodeToken (ML-DSA JWT); policy engine; **LocalKeyStore** (AES-256-GCM,
  rotation, export/import, audit — on-disk format interoperable with Python), **HostedKMS**
  (envelope, pluggable transport), **PQC-hybrid TLS** (X25519MLKEM768 via stdlib crypto/tls).
  Interop: a Go-written keystore reads in Python. Pending: publish (tag → pkg.go.dev).

---

## Track B — SeQr CI (`seqr ci` + GitHub integration)
Goal: turn the v0 gate into a policy-aware, multi-platform CI product and (later) a
hosted GitHub App — the regression guard of the lifecycle (docs/07, docs/13).

### CI-1 — Policy-aware gate + baseline/suppressions  ✅ DONE 2026-08-21
Deliverables: gate on *drift from the org's declared crypto policy* (not just
severity); a baseline file that accepts known/legacy findings so only NEW drift fails;
inline `# seqr:ignore` suppressions and a `.seqrignore`; a `seqr-ci.yml` config.
Shipped: `seqr.ci.policy` (reuses the spine `{"rules":[...]}` shape — `family_in`/
`family_not_in`/`min_key_size`), `--fail-on-drift`; `seqr.ci.baseline` + `seqr-baseline.json`
+ `--update-baseline` (line-independent fingerprints); `seqr.ci.suppress` (inline markers
+ `.seqrignore`); `seqr.ci.config` (`seqr-ci.yml`, flag > file > default). Action inputs
`policy-file`/`baseline`/`fail-on-drift`/`config`. Docs `docs/CI_GATE.md`. CLI 136 tests.
--fail-on/--policy + exit-0-default intact.

```
Read seqr-labs/CLAUDE.md, docs/07_GitHub_App_PRD.md, docs/13_Platform_Spine_PRD.md,
and docs/ROADMAP_SESSIONS.md first. Session CI-1. Make `seqr ci` policy-aware. Today it
gates on severity; add gating on drift from the org's crypto policy (reuse the spine
policy shape from docs/13 — read it, don't fork it). Add a baseline file (seqr-baseline
.json) that records accepted existing findings so only NEW policy drift fails the build,
plus inline `# seqr:ignore[reason]` suppressions, a `.seqrignore`, and an optional
seqr-ci.yml config for defaults. Tests + docs; keep exit 0 by default and the existing
--fail-on/--policy behaviour intact. Commit per logical unit.
```

### CI-2 — GitHub code scanning + dashboard sync  ✅ DONE 2026-08-21
Deliverables: upload SARIF to GitHub code scanning (inline annotations on exact lines),
richer than the summary comment; optional push of findings to the audit backend so PR
crypto lands in the org's CBOM/dashboard.
Shipped: hardened `seqr.output.sarif` (repo-relative URIs, `security-severity`,
`partialFingerprints`; validates vs OASIS sarif-2.1.0) + `seqr ci --sarif-file`; Action
uploads via `codeql-action/upload-sarif` (category seqr-pqc). Optional feature-flagged
dashboard push: Action `api-url`/`api-key` → `POST /api/v1/ci/findings` (auth JWT/`sq_live_`,
org-scoped 404-not-403, `CI_INGEST_ENABLED`) + `GET /ci/reports`. Permissions
`security-events: write`. Docs in `docs/CI_GATE.md`. CLI 146 + backend 131 tests.

```
Read seqr-labs/CLAUDE.md, docs/07_GitHub_App_PRD.md, docs/01_Audit_PRD.md, and
docs/ROADMAP_SESSIONS.md first. Session CI-2. Enrich the CI gate's output. Make the
GitHub Action upload `seqr ci --output sarif` to GitHub code scanning so findings show
as inline annotations on the exact changed lines (not just the summary comment). Add an
optional step that pushes the PR's findings to the audit backend (authenticated, feature
-flagged) so they appear in the org's CBOM/dashboard. Verify the SARIF validates and the
annotations render. Tests for the SARIF shape; document required permissions. Commit per
logical unit.
```

### CI-3 — Multi-platform + Marketplace  ✅ DONE 2026-08-21
Deliverables: publish the composite Action to the GitHub Marketplace; add a
pre-commit hook, a GitLab CI template, and a generic Docker image running `seqr ci`
so non-GitHub shops can adopt it.
Shipped: action `branding` + usage README + `action-release` workflow (tags
`seqr-pqc-v*.*.*` → GitHub Release + sliding `seqr-pqc-v1`; Marketplace submit left
manual). One slim image `seqrlabs/seqr-ci` (`docker/seqr-ci/`) drives a `seqr-ci`
pre-commit hook (`.pre-commit-hooks.yaml`), a reusable GitLab template
(`ci/gitlab/seqr-ci.gitlab-ci.yml`), and Jenkins/`docker run`. Docs: `docs/CI_GATE.md`
"Beyond GitHub". Manifest validated; gate verified via CliRunner (no Docker daemon in
the env — `docker/seqr-ci/smoke-test.sh` covers the container path).

```
Read seqr-labs/CLAUDE.md, docs/07_GitHub_App_PRD.md, and docs/ROADMAP_SESSIONS.md
first. Session CI-3. Broaden CI reach. Prepare the .github/actions/seqr-pqc composite
action for GitHub Marketplace (branding, versioned release tags, README with usage).
Add a .pre-commit-hooks.yaml entry, a reusable GitLab CI template (.gitlab-ci.yml
include), and a slim Docker image that runs `seqr ci` for Jenkins/other runners. Smoke
-test each path. Do not submit to Marketplace for real — leave that gated on me. Commit
per logical unit.
```

### CI-4 — Hosted GitHub App  *(gated — big; do after a customer pulls)*
Deliverables: the PRD's hosted service — FastAPI webhook (HMAC-verified) + Celery
worker fetching changed files + posting reviews/commit-status, installation tokens,
Marketplace billing. Tech stack identical to the audit backend.

```
Read seqr-labs/CLAUDE.md, docs/07_GitHub_App_PRD.md, and docs/ROADMAP_SESSIONS.md
first. Session CI-4. GATE CHECK: only build the hosted GitHub App once someone wants
zero-config install (the `seqr ci` Action already covers self-hosted CI). If greenlit,
implement the PRD's service: FastAPI webhook with HMAC-SHA256 signature validation,
Celery worker that gets an installation token, fetches only changed files, runs the
scanner on added lines, and posts an inline review + commit status; reuse the audit
backend stack. Mock GitHub in tests. Do not register the real App — give me the exact
registration + Marketplace steps. Commit per logical unit.
```

### CI-5 — Trend + fail-budget reporting  ✅ DONE 2026-08-21
Deliverables: a periodic (non-PR) job that reports crypto-drift trend over time and a
configurable fail-budget, so teams see whether they're getting more or less
quantum-safe release over release.
Shipped: `seqr ci --snapshot` (`seqr/ci/trend.py`) — whole-tree scan vs policy → dated
snapshot (`.seqr/snapshots/DATE.json`), new-vs-resolved drift diff on the line-independent
fingerprint, `--fail-budget N` gate (advisory/exit-0 default), Markdown/JSON report +
`--comment-file`. Weekly workflow `.github/workflows/pqc-trend.yml`. Docs: `docs/CI_GATE.md`
"Trend + fail-budget". +19 tests (CLI 165 total green).

```
Read seqr-labs/CLAUDE.md, docs/07_GitHub_App_PRD.md, and docs/ROADMAP_SESSIONS.md
first. Session CI-5. Add trend + fail-budget reporting to the CI product. Build a
scheduled (non-PR) `seqr ci` mode that scans the whole tree against policy, records a
dated snapshot, and reports drift over time (new vs resolved findings) plus a
configurable fail-budget. Emit a Markdown/JSON report suitable for a weekly summary.
Tests + docs. Commit per logical unit.
```

---

## Session dependency order

```
0.1 (commit) ──> 0.2 (live backend) ──> 0.3 (deploy demos + attest verify)
                        │
                        └─> 1.1 (migration demo) ──> 1.2 (harden) ──> 2.1 (on-prem bundle)

3.1 (discovery) runs in parallel from day 1 ──> gates ──> 4.1 (discovery agent)

SeQr SDK track:  v0 ✅ ──> SDK-1 (PyPI) ──> SDK-2 (policy) ──> SDK-3 (drop-ins) ──> SDK-4/5 ✅ ──> SDK-6 (ports: npm ✅ full, go ✅ verified; both need publish)
SeQr CI track:   v0 ✅ ──> CI-1 (policy+baseline) ──> CI-2 (code-scanning) / CI-3 (marketplace) ──> CI-5 (trend) ; CI-4 (hosted app) gated
```

**Do first:** 0.1 → 0.2 → 0.3. Start 3.1 in parallel immediately (non-code, no dependency).
**SDK/CI tracks** are independent of the live backend (local/static) — run SDK-1, SDK-2,
CI-1 whenever; they don't wait on Oracle.
