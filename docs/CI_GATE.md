# SeQr CI Gate (`seqr ci`) — Usage

The regression-guard arm of the SeQr lifecycle: scan the crypto a change **introduces**,
evaluate it against your org's declared crypto policy, and (optionally) fail the build on
**new drift** — so migrated code stays migrated. Pairs with the pqcmap SDK (which
*enforces* the same policy in application code).

> **Exit 0 by default.** `seqr ci` never breaks a build unless you arm a gate. Everything
> below is opt-in.

---

## Two gating axes

| Flag | Fails the build when… |
|---|---|
| `--fail-on <sev>` | any finding is at severity `low\|medium\|high\|critical` or above |
| `--policy strict\|lax` | severity shorthand: `strict` = high+, `lax` = critical only |
| `--fail-on-drift` | any **new** finding drifts from the declared crypto policy |

Severity gating (`--fail-on` / `--policy`) is the original v0 behaviour and is unchanged.
`--fail-on-drift` is the policy-aware gate added in CI-1 — it is independent, so you can
arm either, both, or neither.

---

## The crypto policy

The policy is the **same declarative shape as the platform spine** (`docs/13`,
`app/spine/policy.py`) — a `{"rules": [...]}` body. The CI gate reads it, it does not fork
it; a policy authored for the spine or the pqcmap SDK is ingestible here (rules that
describe network/graph posture simply don't apply to code findings).

Resolution order: `--policy-file PATH` → auto-discovered `seqr-policy.json` → the built-in
baseline (**no quantum-vulnerable families** — RSA/ECC/ECDSA/ECDH/EdDSA/DSA/DH; derived
from PCI DSS 12.3.3 + SEBI CSCRF intent).

### Rule vocabulary

| `type` | Meaning |
|---|---|
| `family_not_in` | the algorithm's family must **not** be in `forbidden` |
| `family_in` | the algorithm's family **must** be in `allowed` |
| `min_key_size` | for a classical `family`, the key size must be `>= min` |

Example `seqr-policy.json` — tolerate strong RSA, forbid ECC, require ML-KEM elsewhere:

```json
{
  "name": "acme crypto policy",
  "version": "1",
  "rules": [
    { "key": "no_ecc", "type": "family_not_in", "forbidden": ["ECC", "ECDSA", "ECDH"],
      "severity": "immediate", "target": "ML-KEM (KEM) / ML-DSA (signatures)" },
    { "key": "rsa_min_3072", "type": "min_key_size", "family": "RSA", "min": 3072,
      "severity": "planned", "target": "RSA-3072+ (ML-DSA later)" }
  ]
}
```

---

## Baseline — only NEW drift fails

A fresh gate on a legacy codebase would fail on crypto that predates the policy. The
baseline (`seqr-baseline.json`) records the findings you've already accepted; the gate
subtracts them so only crypto a change *introduces* can trip it.

```bash
seqr ci --update-baseline      # accept the current tree, write seqr-baseline.json
git add seqr-baseline.json     # commit it
```

Thereafter `seqr ci --fail-on-drift` passes on the accepted findings and fails only on new
ones. A finding is fingerprinted by `(path, pattern, algorithm, code snippet)` — **not its
line number**, so reformatting or moving code never silently un-baselines it.

- `--baseline PATH` — use a non-default baseline location.
- `--no-baseline` — ignore the baseline (treat every finding as new).

---

## Suppressions

**Inline** — accept one finding where it lives:

```python
token = jwt.encode(payload, key, algorithm="RS256")  # seqr:ignore[legacy vendor auth]
```

The marker may sit on the finding's line or the line directly above it; the `[reason]` is
optional and is surfaced in the report. Works with `#`, `//`, and `--` comment styles.

**Path** — a `.seqrignore` file (gitignore-style globs) excludes whole files/dirs:

```gitignore
vendor/
third_party/
*.min.js
/generated/
```

---

## `seqr-ci.yml` — repo defaults

Configure the gate once instead of threading flags through CI. Every key is optional and
mirrors a flag; a **command-line flag always overrides the file**.

```yaml
fail_on_drift: true          # arm the drift gate
policy_file: seqr-policy.json
baseline: seqr-baseline.json
exclude:                     # directories to skip
  - vendor
  - third_party
# fail_on: high             # or use severity gating instead
# policy: strict
# language: python
```

---

## GitHub Action

The composite action `.github/actions/seqr-pqc` wraps `seqr ci`. Relevant inputs:

| Input | Maps to |
|---|---|
| `fail-on` / `policy` | severity gating |
| `fail-on-drift: "true"` | `--fail-on-drift` |
| `policy-file` | `--policy-file` |
| `baseline` | `--baseline` |
| `config` | `--config` (a `seqr-ci.yml`) |

See `.github/workflows/pqc-scan.yml` for a reference PR workflow (advisory by default; flip
one comment to a hard gate). Required permissions: `contents: read`,
`pull-requests: write` (to post the review comment).

---

## GitHub code scanning (inline annotations)

Beyond the summary comment, the Action uploads SARIF so each finding appears as a code
scanning alert **on the exact changed line**. This is automatic — the composite action
writes SARIF and calls `github/codeql-action/upload-sarif` itself. The workflow only needs
the permission:

```yaml
permissions:
  contents: read
  pull-requests: write     # post the review comment
  security-events: write   # upload SARIF to code scanning
```

Notes:
- Alerts are relativised to the repo root and carry a numeric `security-severity`, so they
  colour and sort correctly in the Security tab.
- Stable `partialFingerprints` mean code scanning tracks one alert across pushes instead of
  reopening it each run.
- To generate SARIF outside the Action: `seqr ci . --sarif-file results.sarif` (or
  `--output sarif` to stdout).

## Dashboard / CBOM sync (optional)

The Action can push a PR's findings to the SeQr audit backend so application-code crypto
lands in the org's CBOM/dashboard alongside infra scans. It is **feature-flagged on both
ends** and best-effort (a push failure never fails the build):

```yaml
      with:
        api-url: "https://api.seqrlabs.com/api/v1"
        api-key: ${{ secrets.SEQR_API_KEY }}   # sq_live_...; omit to disable
```

Backend: set `CI_INGEST_ENABLED=true` on the deployment to accept pushes. The endpoint
`POST /api/v1/ci/findings` is authenticated (the `sq_live_` key) and strictly org-scoped;
`GET /api/v1/ci/reports` backs the dashboard list view.

Required GitHub permissions summary:

| Purpose | Permission / secret |
|---|---|
| Post the review comment | `pull-requests: write` |
| Inline code-scanning alerts | `security-events: write` |
| Dashboard push | repo secret `SEQR_API_KEY` (+ backend `CI_INGEST_ENABLED`) |

---

## Beyond GitHub: pre-commit, GitLab, Jenkins/other

The same gate runs off GitHub through one slim image, **`seqrlabs/seqr-ci`**
(`docker/seqr-ci/`) — build it with the CLI as the context:

```bash
docker build -f docker/seqr-ci/Dockerfile -t seqrlabs/seqr-ci:latest ./cli
```

The image's `ENTRYPOINT` is `seqr`, so every consumer calls `seqr ci …`. All three paths
are **advisory by default** (exit 0) and armed the same way (`--fail-on` / `--policy` /
`--fail-on-drift`); keep a `seqr-baseline.json` so only NEW drift trips an armed gate.

### pre-commit

`.pre-commit-hooks.yaml` (repo root) exposes a `seqr-ci` docker_image hook. Consumers:

```yaml
repos:
  - repo: https://github.com/LochanPS/SeQr-Labs
    rev: seqr-pqc-v1.0.0
    hooks:
      - id: seqr-ci
        # args: ["ci", ".", "--all", "--fail-on-drift"]   # arm the gate
```

pre-commit only shows a hook's output when it exits non-zero, so the signal appears once
the gate is armed. Needs Docker locally.

### GitLab CI

`include` the reusable template `ci/gitlab/seqr-ci.gitlab-ci.yml`; it defines a `seqr-pqc`
job that runs on merge requests, diffs against `CI_MERGE_REQUEST_DIFF_BASE_SHA`, and
uploads the Markdown report + SARIF as artifacts:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/LochanPS/SeQr-Labs/seqr-pqc-v1.0.0/ci/gitlab/seqr-ci.gitlab-ci.yml'
variables:
  SEQR_CI_ARGS: "--fail-on-drift"   # empty = advisory
```

### Jenkins / other runners

Run the image directly (see `docker/seqr-ci/README.md` for a declarative pipeline):

```bash
docker run --rm -v "$PWD:/src" seqrlabs/seqr-ci:latest \
  ci . --base origin/main --fail-on-drift \
  --comment-file seqr-pqc-report.md --sarif-file seqr-pqc.sarif
```

### GitHub Marketplace (composite action)

The composite action carries `branding` + a usage README, and the `action-release` workflow
cuts versioned/sliding tags (`seqr-pqc-v1.0.0` + `seqr-pqc-v1`). Marketplace lists an action
only from a **repo root**, so a monorepo subdir action must be mirrored to a dedicated repo
(or the repo root) first; the one-time submit is a manual UI step. Details in
`.github/actions/seqr-pqc/README.md`.

---

## Trend + fail-budget (scheduled, non-PR)

The PR gate stops *new* drift landing on a change. `seqr ci --snapshot` is the
complementary **whole-tree, scheduled** view — run it on a cron and it answers "are we
getting more or less quantum-safe over time?".

```bash
seqr ci . --snapshot                      # advisory report; records a dated snapshot
seqr ci . --snapshot --fail-budget 0      # fail if ANY new drift since the prior snapshot
seqr ci . --snapshot --output json        # machine-readable (dashboard / digest)
seqr ci . --snapshot --comment-file weekly.md
```

What it does:

1. Scans the **whole tree** against the crypto policy (ignores `--base`/`--diff` and
   PR-added-line narrowing; suppressions and `.seqrignore` still apply).
2. Records a dated snapshot at `.seqr/snapshots/<YYYY-MM-DD>.json` (a re-run the same day
   overwrites it) — the drift set, fingerprinted line-independently, plus severity totals.
3. Diffs against the **previous** snapshot → **new** vs **resolved** drift, and the net
   movement. A same-day re-run still compares against the previous *day*.
4. Applies the **fail-budget**: `--fail-budget N` exits non-zero when **more than N** new
   drift findings appeared. No budget → advisory (exit 0), consistent with the PR gate.

| Flag | Meaning |
|---|---|
| `--snapshot` | Enable scheduled trend mode (whole tree). |
| `--snapshot-dir PATH` | Where snapshots live (default `.seqr/snapshots`). |
| `--fail-budget N` | Fail if new drift > N. `0` = fail on any regression; omit = advisory. |

Commit the `.seqr/snapshots/` directory so trend history accrues. The reference weekly
workflow is [`.github/workflows/pqc-trend.yml`](../.github/workflows/pqc-trend.yml)
(Mondays 06:00 UTC): it writes the report to the job summary and commits the snapshot back.

## Pipeline order (what the gate does)

1. Scan the tree for quantum-vulnerable patterns.
2. Drop paths matched by `.seqrignore`.
3. Drop findings with an inline `# seqr:ignore`.
4. Narrow to PR-added lines (unless `--all`).
5. Subtract baselined findings (unless `--no-baseline`).
6. Evaluate the survivors against the crypto policy → **drift**.
7. Decide exit code: severity gate **or** drift gate. Exit 0 if neither is armed.
