"""Trend + fail-budget reporting: is the codebase getting more or less quantum-safe?

The PR gate (``seqr ci`` on a diff) stops *new* drift landing. This module is the
complementary **scheduled, whole-tree** view: run it on a cron (weekly, nightly), and it
records a dated snapshot of every finding that drifts from the org crypto policy, then
reports the movement since the previous snapshot — which drift was **resolved** (migrated)
and which is **new** — plus a configurable **fail-budget** so a team can hold the line
("no more than N new drifts per week") without the noise of a per-line PR gate.

Design choices, consistent with the rest of the CI package:

* **Line-independent identity.** Snapshots diff on :func:`seqr.ci.baseline.fingerprint`
  (path + pattern + algorithm + snippet, *not* line number), so reformatting or moving
  code never shows as a spurious resolve+new pair.
* **Policy is the yardstick.** A snapshot records the findings that violate the *same*
  declarative crypto policy the PR gate, the spine, and pqcmap use — not a parallel notion
  of "bad crypto".
* **Exit 0 by default.** With no ``--fail-budget`` the report is advisory; a build only
  breaks when the caller sets a budget and new drift exceeds it.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from seqr._severity import SEVERITY_ORDER, severity_for_risk
from seqr.ci.baseline import _rel_posix, fingerprint
from seqr.ci.policy import CryptoPolicy
from seqr.ci.report import HNDL_DISCLAIMER

SNAPSHOT_SCHEMA_VERSION = 1
DEFAULT_SNAPSHOT_DIR = ".seqr/snapshots"


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def git_commit(cwd: str | None = None) -> str | None:
    """Best-effort short commit SHA for the snapshot, or None outside a git repo."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=cwd, capture_output=True, text=True,
        )
    except FileNotFoundError:
        return None
    sha = proc.stdout.strip()
    return sha if proc.returncode == 0 and sha else None


def _record(finding, root: str | None) -> dict:
    """A stable, human-readable snapshot entry for one drifting finding."""
    return {
        "fingerprint": fingerprint(finding, root),
        "file": _rel_posix(getattr(finding, "file_path", ""), root),
        "line": getattr(finding, "line_number", None),
        "algorithm": getattr(finding, "algorithm", ""),
        "pattern_id": getattr(finding, "pattern_id", ""),
        "severity": severity_for_risk(getattr(finding, "algorithm_risk", 0)),
    }


def build_snapshot(
    findings: list,
    policy: CryptoPolicy,
    *,
    root: str | None = None,
    commit: str | None = None,
    now: _dt.datetime | None = None,
) -> dict:
    """Render a dated snapshot: every finding in ``findings`` that drifts from ``policy``.

    ``findings`` is the whole-tree scan (already suppressed / path-ignored by the caller).
    Only findings the policy flags are recorded — that is the drift set the trend tracks.
    Duplicate fingerprints are collapsed. Entries are sorted by fingerprint for a stable,
    reviewable file.
    """
    now = now or _utc_now()
    seen: dict[str, dict] = {}
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if not policy.evaluate_finding(f):
            continue  # compliant — not drift
        rec = _record(f, root)
        fp = rec["fingerprint"]
        if fp in seen:
            continue
        seen[fp] = rec
        sev_counts[rec["severity"]] = sev_counts.get(rec["severity"], 0) + 1

    drift = [seen[k] for k in sorted(seen)]
    return {
        "version": SNAPSHOT_SCHEMA_VERSION,
        "tool": "seqr ci --snapshot",
        "date": now.date().isoformat(),
        "timestamp": now.isoformat(),
        "commit": commit,
        "policy": policy.name,
        "totals": {
            "scanned": len(findings),
            "drift": len(drift),
            "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITY_ORDER},
        },
        "drift": drift,
    }


def snapshot_path(snapshot_dir: str | Path, snap: dict) -> Path:
    """File path for a snapshot: ``<dir>/<date>.json`` (a re-run same day overwrites)."""
    return Path(snapshot_dir) / f"{snap['date']}.json"


def save_snapshot(snapshot_dir: str | Path, snap: dict) -> Path:
    """Persist ``snap`` under ``snapshot_dir`` and return the written path."""
    d = Path(snapshot_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = snapshot_path(d, snap)
    path.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
    return path


def load_snapshots(snapshot_dir: str | Path) -> list[dict]:
    """Return all valid snapshots under ``snapshot_dir``, oldest first (by date then ts).

    Files that are not parseable snapshots are skipped rather than raising, so one bad
    file never breaks a scheduled report.
    """
    d = Path(snapshot_dir)
    if not d.is_dir():
        return []
    snaps: list[dict] = []
    for p in d.glob("*.json"):
        try:
            body = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(body, dict) and "drift" in body and body.get("date"):
            snaps.append(body)
    snaps.sort(key=lambda s: (s.get("date", ""), s.get("timestamp", "")))
    return snaps


def prior_snapshot(snapshots: list[dict], current: dict) -> dict | None:
    """The most recent snapshot strictly older than ``current`` (by date), or None.

    ``snapshots`` is the full list (as from :func:`load_snapshots`); ``current`` is the
    just-recorded one. Snapshots sharing ``current``'s date are ignored so a same-day
    re-run compares against the previous *day*, not itself.
    """
    older = [s for s in snapshots if s.get("date", "") < current.get("date", "")]
    return older[-1] if older else None


@dataclass(frozen=True)
class TrendDiff:
    new: list[dict]          # drift present now, absent in prior
    resolved: list[dict]     # drift present in prior, absent now
    unchanged: int           # drift present in both

    @property
    def net(self) -> int:
        """Net change in drift count (positive = regressed, negative = improved)."""
        return len(self.new) - len(self.resolved)


def diff_snapshots(prior: dict | None, current: dict) -> TrendDiff:
    """Compare two snapshots on drift fingerprints → new / resolved / unchanged."""
    cur = {r["fingerprint"]: r for r in current.get("drift", [])}
    prev = {r["fingerprint"]: r for r in (prior.get("drift", []) if prior else [])}
    new = [cur[fp] for fp in cur if fp not in prev]
    resolved = [prev[fp] for fp in prev if fp not in cur]
    unchanged = sum(1 for fp in cur if fp in prev)
    # Sort by severity (most urgent first) for readable reports.
    key = lambda r: SEVERITY_ORDER.index(r.get("severity", "low")) * -1
    new.sort(key=key)
    resolved.sort(key=key)
    return TrendDiff(new=new, resolved=resolved, unchanged=unchanged)


@dataclass(frozen=True)
class BudgetDecision:
    should_fail: bool
    reason: str
    budget: int | None
    new_count: int


def budget_decision(new_count: int, budget: int | None) -> BudgetDecision:
    """Decide the exit code against a fail-budget of NEW drift.

    ``budget`` is the maximum number of *new* drift findings tolerated since the prior
    snapshot. ``None`` = advisory (never fails). A budget of 0 fails on any regression.
    """
    if budget is None:
        return BudgetDecision(False, "advisory (no --fail-budget)", None, new_count)
    if new_count > budget:
        return BudgetDecision(
            True,
            f"{new_count} new drift finding(s) exceed the fail-budget of {budget}",
            budget, new_count,
        )
    return BudgetDecision(
        False, f"{new_count} new drift finding(s) within the fail-budget of {budget}",
        budget, new_count,
    )


# -- reports ---------------------------------------------------------------------

def _arrow(net: int) -> str:
    if net > 0:
        return f"🔺 +{net} (regressed)"
    if net < 0:
        return f"🔻 {net} (improved)"
    return "➖ 0 (flat)"


def build_trend_markdown(
    current: dict, prior: dict | None, diff: TrendDiff, decision: BudgetDecision
) -> str:
    """Render the weekly-summary Markdown report."""
    t = current["totals"]
    lines: list[str] = ["## 🔐 SeQr PQC Drift Trend", ""]
    scope = current.get("date", "")
    commit = f" · `{current['commit']}`" if current.get("commit") else ""
    lines.append(f"Snapshot **{scope}**{commit} — policy: _{current.get('policy','')}_")
    lines.append("")

    if prior is None:
        lines.append(
            "First snapshot — no prior to compare against. Future runs report movement "
            "since the previous snapshot."
        )
    else:
        lines.append(f"Since **{prior.get('date','')}**: {_arrow(diff.net)}")
    lines.append("")

    # Totals table.
    by = t.get("by_severity", {})
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Drift findings (vs policy) | **{t.get('drift', 0)}** |")
    lines.append(f"| Resolved since prior | {len(diff.resolved)} |")
    lines.append(f"| New since prior | {len(diff.new)} |")
    lines.append(f"| Unchanged | {diff.unchanged} |")
    lines.append(
        f"| By severity | "
        + ", ".join(f"{s}: {by.get(s, 0)}" for s in reversed(SEVERITY_ORDER))
        + " |"
    )
    lines.append("")

    if diff.new:
        lines.append("### 🔺 New drift")
        lines.append("| File | Line | Algorithm | Severity |")
        lines.append("|------|------|-----------|----------|")
        for r in diff.new:
            lines.append(
                f"| `{r['file']}` | {r.get('line','')} | {r.get('algorithm','')} | "
                f"{r.get('severity','').upper()} |"
            )
        lines.append("")

    if diff.resolved:
        lines.append("### 🔻 Resolved")
        for r in diff.resolved:
            lines.append(f"- `{r['file']}` — {r.get('algorithm','')} (was {r.get('severity','')})")
        lines.append("")

    # HNDL disclaimer accompanies any drift report (per CLAUDE.md output rules).
    if t.get("drift", 0):
        lines.append(f"> *{HNDL_DISCLAIMER}*")
        lines.append("")

    verdict = "❌ **Over budget:** " if decision.should_fail else "✅ "
    lines.append(f"> {verdict}{decision.reason}.")
    lines.append("")
    lines.append(
        "See [`pqcmap`](https://seqrlabs.com/sdk) for drop-in ML-KEM / ML-DSA "
        "replacements. Scheduled scan — exit 0 unless a fail-budget is set."
    )
    lines.append("")
    lines.append("---\n*Powered by [SeQr](https://seqrlabs.com).*")
    return "\n".join(lines)


def build_trend_json(
    current: dict, prior: dict | None, diff: TrendDiff, decision: BudgetDecision
) -> dict:
    """Machine-readable trend report (for a dashboard or a weekly digest job)."""
    return {
        "snapshot": current,
        "prior_date": prior.get("date") if prior else None,
        "trend": {
            "new": diff.new,
            "resolved": diff.resolved,
            "unchanged": diff.unchanged,
            "net": diff.net,
        },
        "budget": {
            "should_fail": decision.should_fail,
            "reason": decision.reason,
            "budget": decision.budget,
            "new_count": decision.new_count,
        },
    }


__all__ = [
    "SNAPSHOT_SCHEMA_VERSION",
    "DEFAULT_SNAPSHOT_DIR",
    "git_commit",
    "build_snapshot",
    "snapshot_path",
    "save_snapshot",
    "load_snapshots",
    "prior_snapshot",
    "TrendDiff",
    "diff_snapshots",
    "BudgetDecision",
    "budget_decision",
    "build_trend_markdown",
    "build_trend_json",
]
