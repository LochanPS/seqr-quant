# SeQr CI — Engineering PRD v1.0
### Product: **SeQr CI** (`seqr ci` + GitHub Action; hosted GitHub App). Automated PQC Code Review for Pull Requests

> **Status update — CI-4 hosted GitHub App BUILT 2026-09-08.** The webhook receiver +
> Celery scan worker + review/commit-status poster below are implemented in
> `audit/backend/app/github_app/` (feature-flagged `GITHUB_APP_ENABLED`, off by default),
> reusing the shared `seqr-scanner` code engine. Operator setup: `docs/GITHUB_APP_OPERATIONS.md`.
> The "Deferral Rationale" section below is retained for history — the deferral is now lifted.

**Status: CI-gate v0 BUILT 2026-08-20 (`seqr ci` + `.github/actions/seqr-pqc`).** This is the
regression guard of the lifecycle — it **blocks PRs that violate the crypto policy** (`docs/13`)
so migrated code stays migrated. Pairs with the pqcmap SDK (`docs/02`) as the application-code half
of the platform. v0 is the pragmatic no-infra path: a diff-aware `seqr ci` command (scans PR-added
lines, --fail-on/--policy gating, PR-style Markdown review, exit 0 by default) wrapped by a reusable
GitHub Action + reference workflow (34 tests). The **hosted GitHub Marketplace app** below (webhook +
Celery, billing) remains deferred until a customer pulls for it — the spec is kept as the design
reference.

---

## Deferral Rationale

The GitHub App depends on a stable `seqr-scanner` package. The scanner is now stable
(386 tests passing). However, the current product focus is:
1. Complete Session 9 (Next.js frontend)
2. Run research paper scanner
3. 15 customer discovery conversations
4. First paying customer on audit backend

GitHub App will be revisited after first paying customer is signed.
It is an acquisition channel — not a prerequisite for revenue.

---

## Product Summary

SeQr GitHub App is a GitHub Marketplace application that automatically scans every
pull request for new quantum-vulnerable cryptographic patterns and posts a detailed
review comment. Think CodeRabbit but specifically for PQC security.

Zero setup beyond clicking "Install" on GitHub Marketplace. No CLI, no Docker,
no configuration files.

**Distribution:** GitHub Marketplace
**Billing:** GitHub handles payments; SeQr Labs receives 75% of revenue
**Pricing:**
- Free: 3 repos, findings summary only, no dashboard sync
- Pro: ₹3,000/org/month — unlimited repos, full findings, SeQr dashboard sync, historical data

---

## How It Works (End-to-End Flow)

```
1. Developer opens PR on GitHub adding new auth code

2. GitHub sends webhook to SeQr:
   POST https://github-app.seqrlabs.com/webhooks/github
   Event: pull_request (action: opened | synchronize)

3. SeQr webhook handler:
   a. Validates webhook signature (HMAC-SHA256 with webhook secret)
   b. Extracts: repo, PR number, changed files, installation_id
   c. Queues scan job in Celery

4. Celery worker:
   a. Gets GitHub App installation token (short-lived, scoped to this repo)
   b. Fetches changed file contents via GitHub API (only changed files, not full repo)
   c. Runs seqr-scanner code scanner on each file
   d. Aggregates findings

5. SeQr posts review:
   a. Findings: POST /repos/{owner}/{repo}/pulls/{pr}/reviews
      with inline comments on exact lines + summary review comment
   b. No findings: POST single comment "✅ No quantum-vulnerable patterns found"
   c. Sets commit status: success/failure based on severity threshold

6. If org has SeQr Audit account linked:
   a. Sync findings to their CBOM
   b. Show PR findings in audit dashboard
```

---

## Architecture

**Stack:** FastAPI (webhook receiver) + Celery (scan worker) + PostgreSQL + Redis
**Scanner:** Imports `seqr-scanner` (shared-scanner package)
**Deployment:** Docker + AWS ECS (cloud only — no on-prem GitHub App)

---

## GitHub App Registration (When Building)

```
App name: SeQr PQC Scanner
Webhook URL: https://github-app.seqrlabs.com/webhooks/github
Webhook secret: openssl rand -hex 32

Permissions:
  Contents: Read
  Pull requests: Read & Write
  Commit statuses: Read & Write
  Metadata: Read (mandatory)

Subscribe to events: Pull request
```

---

## Review Comment Format

```markdown
## 🔐 SeQr PQC Scan Results

Found **2 quantum-vulnerable** cryptographic patterns introduced in this PR.

| File | Line | Algorithm | Severity | Est. Fix |
|------|------|-----------|----------|----------|
| `src/auth/jwt.py` | 42 | RSA-SHA256 (RS256 JWT) | 🔴 CRITICAL | 3–5h |
| `src/keys/gen.py` | 17 | ECDSA secp256k1 | 🔴 CRITICAL | 6–8h |

### ⚡ HNDL Risk
`src/auth/jwt.py:42` — This JWT endpoint is public-facing.
*HNDL exposure scores are predictive cryptographic risk metrics based on data-type
endurance, not indicators of active data interception or confirmed network breaches.*

### Recommended Fixes
**jwt.py:42** — Replace PyJWT RS256 with pqcmap:
\`\`\`python
# Before
token = jwt.encode(payload, rsa_private_key, algorithm='RS256')
# After
from pqcmap.jwt import PQCToken
token = PQCToken.encode(payload, mldsa_private_key)  # pip install pqcmap
\`\`\`

---
*Powered by [SeQr](https://seqrlabs.com) · [Docs](https://docs.seqrlabs.com)*
```

---

## Key Design Decisions

1. **Scan only new lines** — Parse PR diff. Only flag findings on new lines (lines starting
   with `+`). Avoids noise from pre-existing issues. Focuses on what THIS PR introduced.

2. **Exit 0 by default** — Consistent with CLI. Never block a PR automatically unless
   `fail_on` is explicitly configured.

3. **HNDL disclaimer** — Include disclaimer in every HNDL risk mention.

4. **No CNSA 2.0** — No US NSS compliance references in review comments.

---

## GitHub Marketplace Listing Copy

```
Name: SeQr PQC Scanner
Tagline: Catch quantum-vulnerable cryptography in every pull request

Why it matters:
NIST finalised post-quantum standards in August 2024. PCI DSS 12.3.3 requires
cryptographic inventories. India's DST Task Force published a migration mandate
with CII deadline Jan 1, 2027. The quantum threat is a compliance reality now.

What it finds:
• RSA key generation and signing (RS256 JWTs, RSA-2048 certs)
• ECDSA / ECDH / secp256k1 usage
• JWT algorithm confusion vulnerabilities
• 30+ patterns across Python, JavaScript, Java, Go

Free: 3 repositories, summary comment only
Pro (₹3,000/month): Unlimited repos, inline comments, dashboard sync, compliance mapping
```

---

## Build Order

When building (after first paying customer):
1. Register GitHub App at github.com/settings/apps/new
2. Implement webhook receiver (FastAPI)
3. Implement Celery scan task (reuse seqr-scanner)
4. Implement GitHub review poster
5. Test with mock PR webhooks
6. Submit to GitHub Marketplace

See full implementation spec above. Tech stack identical to audit backend.
