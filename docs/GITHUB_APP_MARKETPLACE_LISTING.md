# SeQr PQC Scanner — GitHub Marketplace Listing (DRAFT — NOT SUBMITTED)

> **Status: prepared, not submitted.** This is the copy + configuration to paste into
> the GitHub Marketplace listing form once the App is registered, installed, and verified
> on a live PR (see `docs/GITHUB_APP_OPERATIONS.md`). Do **not** click *Submit for review*
> until the acceptance checklist at the bottom is green. Marketplace publishing requires a
> verified publisher (org, not personal account) — see "Publisher prerequisites".

---

## Basic listing

| Field | Value |
|---|---|
| **App name** | SeQr PQC Scanner |
| **Tagline** (short description) | Catch quantum-vulnerable cryptography in every pull request |
| **Primary category** | Code review |
| **Secondary category** | Security |
| **Supported languages** | Python, JavaScript/TypeScript, Java, Go |
| **Homepage URL** | https://seqrlabs.com |
| **Support / documentation URL** | https://seqrlabs.com/docs/github-app (fallback: repo `docs/GITHUB_APP_OPERATIONS.md`) |
| **Privacy policy URL** | https://seqrlabs.com/privacy |
| **Publisher** | SeQr Labs (verified org — see prerequisites) |

---

## Permissions & events (MUST match the registered App exactly)

Repository permissions:
- **Contents** — Read-only
- **Pull requests** — Read & write
- **Commit statuses** — Read & write
- **Metadata** — Read-only (mandatory)

Subscribed events: **Pull request**

Webhook URL: `https://api.seqrlabs.com/api/v1/github/webhook`

> Advisory by default (`GITHUB_APP_FAIL_ON` empty) — the `seqr/pqc` commit status is always
> `success`; the review is informational and never blocks a merge unless the installer opts in.

---

## Long description (listing body)

**SeQr PQC Scanner reviews every pull request for new quantum-vulnerable cryptography — and
tells you exactly what to migrate to.** Think CodeRabbit, but for post-quantum readiness.

Zero setup beyond clicking **Install**. No CLI, no Docker, no config files. Open a PR and
SeQr posts an inline review on the exact lines that introduce classical crypto, plus a
`seqr/pqc` commit status.

**Why it matters now**
- **NIST** finalised the post-quantum standards (ML-KEM / ML-DSA) in August 2024.
- **PCI DSS 12.3.3** has required a cryptographic-asset inventory since 31 March 2025.
- **SEBI CSCRF** expects a PQC crypto-asset inventory of regulated entities (live since Jun 2025).
- India's **DST Task Force** targets a cryptographic-asset inventory for critical infrastructure
  **by 2027** (a recommendatory readiness milestone — regulators enforce sectorally).

The quantum threat is already a compliance reality. SeQr helps you keep new code from adding to
the backlog.

**What it finds**
- RSA key generation and signing (RS256 JWTs, RSA-2048 certificates)
- ECDSA / ECDH / secp256k1 usage
- JWT algorithm-confusion patterns
- 30+ patterns across Python, JavaScript, Java, and Go

**What it does with them**
- Comments only on the lines your PR **adds** — pre-existing crypto never fails an unrelated build.
- Suggests the strength-matched PQC replacement (e.g. RSA-4096 → ML-KEM-1024 / ML-DSA-87).
- Advisory by default; flip one setting to make it a hard gate.

**Privacy**
SeQr scans only the changed files in the PR that triggered the webhook, in memory, to produce the
review. It does not clone your repository or persist source code. Optional dashboard sync (Pro)
stores only findings metadata (file, line, pattern, severity) for organisations that link an
installation to a SeQr account.

> HNDL exposure scores are predictive cryptographic risk metrics based on data-type endurance,
> not indicators of active data interception or confirmed network breaches.

---

## Pricing plans (GitHub-billed; SeQr Labs receives 75%)

| Plan | Price | Includes |
|---|---|---|
| **Free** | ₹0 | 3 repositories · summary review comment only · no dashboard sync |
| **Pro** | ₹3,000 / org / month | Unlimited repositories · inline per-line comments · SeQr dashboard sync · compliance mapping · historical findings |

> Plan gating (Free = 3 repos / summary-only) is a **Marketplace-billing feature not yet
> enforced in code** — the current build posts full inline reviews for every install. Enforce
> the Free/Pro split before enabling paid plans, or launch **Free-only** first (recommended for
> the acquisition-channel goal) and add Pro when billing webhooks are wired. Tracked as a
> follow-on; do not advertise Pro until enforced.

---

## Screenshots to capture (from the verification PR)

1. Inline review comment on an RS256 / `import rsa` line.
2. The summary review comment (findings count + HNDL disclaimer).
3. The `seqr/pqc` commit status (advisory `success`) in the PR checks list.
4. (Pro) The SeQr dashboard showing the synced `CIReport`.

---

## Publisher prerequisites (before *Submit for review*)

- App owned by an **organization** account (personal-account apps can't be listed), org
  verified with billing/contact details.
- Homepage, Privacy policy, and Support URLs all resolve.
- Webhook host reachable 24/7. **The laptop bridge is not 24/7** — GitHub's Marketplace review
  will exercise the webhook, so bring up the always-on host (Oracle) before submitting. The bridge
  is fine for install/verify testing, not for a live Marketplace listing.
- Terms of service for the listing.

---

## Acceptance checklist (gate for submission)

- [ ] App registered; App ID + private key in place; `GITHUB_WEBHOOK_SECRET` set.
- [ ] `configure_github_app.sh` run; unsigned webhook POST returns **401** (not 404).
- [ ] Installed on a test repo; PR adding `jwt.encode(p, k, algorithm="RS256")` gets an inline
      review + a `seqr/pqc` commit status.
- [ ] Pre-existing crypto on unchanged lines is **not** flagged.
- [ ] Dashboard sync verified: installation linked (`app.github_app.link set`) → a `CIReport`
      row is written (`source="github-app"`).
- [ ] Always-on host live (not the bridge) with a stable `api.seqrlabs.com`.
- [ ] Free/Pro plan gating enforced in code **OR** listing launches Free-only.
- [ ] Screenshots 1–4 captured; homepage/privacy/support URLs resolve; publisher org verified.

When every box is checked: GitHub App settings → **Marketplace** → *Create/Edit listing* → paste
the copy above → *Submit for review*. **Not before.**
