# SeQr PQC Gate — GitHub Action

Scan a pull request for **quantum-vulnerable cryptography introduced on the changed
lines** and (optionally) fail the build. Wraps the [`seqr ci`](../../../docs/CI_GATE.md)
command — the regression-guard arm of the SeQr lifecycle, so migrated code stays migrated.

> **Exit 0 by default.** The gate never breaks a build unless you arm it with `fail-on`,
> `policy`, or `fail-on-drift`. Everything below is opt-in.

---

## Quick start

```yaml
# .github/workflows/pqc-scan.yml
name: PQC Scan
on:
  pull_request:
    paths: ["**/*.py", "**/*.js", "**/*.ts", "**/*.java", "**/*.go"]

permissions:
  contents: read
  pull-requests: write     # post the review comment
  security-events: write   # upload SARIF → inline code-scanning annotations

jobs:
  pqc-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # the gate diffs against the base branch
      - uses: LochanPS/SeQr-Labs/.github/actions/seqr-pqc@seqr-pqc-v1
        with:
          base: ${{ github.event.pull_request.base.ref }}
          # policy: strict               # arm the gate (fail on high+), OR:
          # fail-on-drift: "true"        # fail on NEW drift from the crypto policy
```

Pin to the sliding major tag `@seqr-pqc-v1` (moves with each `v1.x.y` release) or to an
exact release tag `@seqr-pqc-v1.0.0` for a fully reproducible pipeline.

---

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `base` | *(auto)* | Base git ref to diff against. Auto-detects `origin/main` → `main` → `HEAD~1`. |
| `fail-on` | — | Fail on findings at this severity or above (`low\|medium\|high\|critical`). |
| `policy` | — | Severity shorthand: `strict` (high+) or `lax` (critical only). |
| `policy-file` | *(auto)* | Declarative crypto policy (`{"rules":[…]}` spine shape). Auto-discovers `seqr-policy.json`, else the built-in baseline. |
| `fail-on-drift` | — | `true`/`false` — fail on NEW findings that drift from the crypto policy. |
| `baseline` | *(auto)* | Accepted-findings baseline; only findings absent from it can fail. Auto-discovers `seqr-baseline.json`. |
| `config` | *(auto)* | `seqr-ci.yml` defaults. |
| `language` | — | Restrict to one language (`python\|javascript\|java\|go\|all`). |
| `install-spec` | `seqr` | pip target for the CLI. Pass `./cli` to build from an in-repo checkout. |
| `api-url` | — | SeQr audit backend base URL. Set with `api-key` to push PR findings into the org CBOM/dashboard. Omit to disable. |
| `api-key` | — | SeQr API key (`sq_live_…`) for the dashboard push. Pass from a repo secret; the push never fails the build. |

## Outputs

| Output | Description |
|---|---|
| `comment-file` | Path to the generated Markdown review (post it as a PR comment). |
| `sarif-file` | Path to the SARIF 2.1.0 file (uploaded to code scanning automatically). |

---

## Not on GitHub?

The same gate runs anywhere via one slim Docker image (`seqrlabs/seqr-ci`):

- **pre-commit** — [`.pre-commit-hooks.yaml`](../../../.pre-commit-hooks.yaml)
- **GitLab CI** — [`ci/gitlab/seqr-ci.gitlab-ci.yml`](../../../ci/gitlab/seqr-ci.gitlab-ci.yml)
- **Jenkins / other runners** — [`docker/seqr-ci/`](../../../docker/seqr-ci/)

See [`docs/CI_GATE.md`](../../../docs/CI_GATE.md) for the full multi-platform guide.

---

## Publishing to the GitHub Marketplace

GitHub Marketplace lists an action from the **root of a repository tag** — it cannot list
an action that lives in a monorepo subdirectory (`.github/actions/seqr-pqc/`). Two paths:

1. **Dedicated action repo (recommended).** Mirror this directory to the root of a
   standalone repo (e.g. `seqr-labs/seqr-pqc-action`), tag it `v1.0.0` + sliding `v1`, and
   publish that. Consumers then use `seqr-labs/seqr-pqc-action@v1`.
2. **Root of this repo.** Move `action.yml` (and this README) to the repo root on a release
   tag. Not recommended for a monorepo.

The [`action-release`](../../workflows/action-release.yml) workflow cuts the versioned +
sliding-major tags and a GitHub Release. **The Marketplace *submit* step is a manual
one-time UI action (Releases → "Publish this Action to the Marketplace") and is left for
the founder** — it requires accepting the Marketplace Developer Agreement on the account.

Marketplace readiness checklist (all satisfied here): unique action name, `branding.icon`
+ `branding.color` set, a README with usage, and a semver release tag.
