# SeQr Hosted GitHub App — Operations Runbook (CI-4)

The hosted App scans every pull request for **new** quantum-vulnerable crypto and posts an
inline review + commit status. It is **feature-flagged off** and only reacts to signed
webhooks. Nothing in the codebase registers, deploys, or lists anything on GitHub — the
steps below are the manual operator actions that stand it up.

Design spec: `docs/07_GitHub_App_PRD.md`. Implementation: `audit/backend/app/github_app/`.

---

## 1. Register the GitHub App (one time, manual)

At `github.com/settings/apps/new`:

```
App name:      SeQr PQC Scanner
Homepage URL:  https://seqrlabs.com
Webhook URL:   https://<backend-host>/api/v1/github/webhook
Webhook secret: <openssl rand -hex 32>     # keep this — it is GITHUB_WEBHOOK_SECRET

Permissions (repository):
  Contents ............ Read-only
  Pull requests ....... Read & write
  Commit statuses ..... Read & write
  Metadata ............ Read-only (mandatory)

Subscribe to events:  Pull request
Where can it be installed:  Any account (for Marketplace) or Only on this account (private)
```

After creation, note the **App ID** and generate a **private key** (`.pem` download).

---

## 2. Configure the backend

Set on the backend service (Render/Oracle/compose). The App stays hidden (404 on the
webhook route) until `GITHUB_APP_ENABLED=true`.

| Env var | Meaning |
|---|---|
| `GITHUB_APP_ENABLED` | `true` to accept webhooks. Off by default. |
| `GITHUB_APP_ID` | Numeric App ID from step 1. |
| `GITHUB_APP_PRIVATE_KEY` | Contents of the `.pem`. Newlines may be flattened to literal `\n` — the client restores them (`github_app.client.restore_pem`). |
| `GITHUB_WEBHOOK_SECRET` | The webhook secret from step 1 (`openssl rand -hex 32`). |
| `GITHUB_API_URL` | Default `https://api.github.com`; set for GitHub Enterprise. |
| `GITHUB_APP_FAIL_ON` | Severity threshold that marks the commit status `failure` (`low`/`medium`/`high`/`critical`). **Empty = advisory** (never fails a build — the default, exit-0-by-default posture). |
| `GITHUB_APP_PERSIST_REPORTS` | `true` (default) to store each scan as a `CIReport` when the installation is linked to an org (step 4). |

Apply the DB migration so `github_installations` + `ci_reports` exist:

```bash
cd audit/backend && alembic upgrade head
```

---

## 3. Install the App on a repo/org

The customer (or operator, for a private install) clicks **Install** and selects repos.
GitHub sends an `installation` webhook and, on each PR, a `pull_request` webhook. No scan
runs until a PR is opened/updated.

---

## 4. Link an installation to a SeQr org (enables dashboard sync)

The webhook carries a GitHub `installation_id`, not a SeQr identity. To sync a PR scan into
a customer's CBOM, map the installation to their org **once**. Without a mapping the App
still posts its review + commit status — it just skips dashboard persistence.

Find the `installation_id` in the webhook delivery (GitHub App → Advanced → Recent
Deliveries) or the App's Installations page, then run the link CLI on the box. The org is
resolved by one of `--org-email` (an existing user's email → their org), `--org-id`, or
`--org-name`:

```bash
docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml \
    exec backend python -m app.github_app.link set \
    --installation-id <installation_id> \
    --org-email you@yourorg.com \
    --account-login <github-login> --account-type Organization
```

`set` is idempotent (re-running updates the mapping). Inspect or remove links with:

```bash
... exec backend python -m app.github_app.link list
... exec backend python -m app.github_app.link unset --installation-id <installation_id>
```

(An onboarding UI is a later nicety; this row is the source of truth today. If you prefer
raw SQL, the table is `github_installations(installation_id, org_id, account_login, account_type)`.)

---

## 5. Verify

1. **Ping** — GitHub sends a `ping` when the webhook is saved. A signed ping returns
   `{"ok": true, "pong": true}`. A bad/missing signature returns `401`; a disabled App
   returns `404`.
2. **Open a test PR** that adds a vulnerable line (e.g. `jwt.encode(p, k, algorithm="RS256")`).
   Expect an inline review comment on that line, a summary review, and a `seqr/pqc` commit
   status (`success` in advisory mode, `failure` if `GITHUB_APP_FAIL_ON` is armed and met).
3. **Pre-existing issues** on unchanged lines must NOT be flagged — only PR-added lines are.

---

## Guarantees / non-goals

- **Scan only new lines** — findings are filtered to the diff's added lines (PRD design
  decision), so old code never fails an unrelated build.
- **Exit 0 by default** — with `GITHUB_APP_FAIL_ON` empty, the commit status is always
  `success`; the review is advisory. Matches the CLI gate.
- **HNDL disclaimer** accompanies every HNDL mention; **no CNSA 2.0** references appear
  (Indian-compliance rule).
- The webhook route is verified by HMAC-SHA256 before the body is parsed; an unsigned or
  mis-signed request never reaches the scanner.
- The App never writes to a repo beyond a review + commit status, and never registers or
  removes anything on GitHub's side.
