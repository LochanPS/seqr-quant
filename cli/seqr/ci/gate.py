"""CI gate logic: restrict findings to PR-added lines and decide the exit code.

Reuses the CLI's existing severity model (``seqr._severity``) and the same
``--fail-on`` / ``--policy`` semantics as ``seqr scan code``, so the gate never
invents a second, divergent notion of severity. Default posture is **exit 0** — a
build only breaks when the caller opts in with ``--fail-on`` or ``--policy``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from seqr._severity import SEVERITY_ORDER, severity_for_risk


def normalize_path(path: str, root: str | None = None) -> str:
    """Return ``path`` as a repo-root-relative POSIX string for diff matching."""
    root = root or os.getcwd()
    try:
        rel = os.path.relpath(path, root)
    except ValueError:  # e.g. different drive on Windows
        rel = path
    return PurePosixPath(Path(rel).as_posix()).as_posix()


def filter_to_added(findings: list, added: dict[str, set[int]], root: str | None = None) -> list:
    """Keep only findings on lines the PR added.

    Matches a finding to the diff first by its repo-relative path, then falls back to
    basename — so it still works when the scan root and the repo root differ.
    """
    if not added:
        return []
    by_basename: dict[str, set[int]] = {}
    for p, lines in added.items():
        by_basename.setdefault(PurePosixPath(p).name, set()).update(lines)

    kept = []
    for f in findings:
        norm = normalize_path(f.file_path, root)
        lines = added.get(norm)
        if lines is None:
            lines = by_basename.get(PurePosixPath(norm).name)
        if lines and f.line_number in lines:
            kept.append(f)
    return kept


@dataclass(frozen=True)
class GateDecision:
    should_fail: bool
    reason: str
    threshold: str | None  # severity name that tripped the gate, if any
    drift_count: int = 0    # number of NEW policy-drift findings that tripped the gate


def decide(
    findings: list,
    fail_on: str | None,
    policy: str | None,
    *,
    drift: list | None = None,
    fail_on_drift: bool = False,
) -> GateDecision:
    """Decide whether the gate should fail the build.

    Two independent gating axes, either of which can fail the build:

    * **Severity** — ``fail_on`` fails when any finding is at that severity or above;
      ``policy`` is the shorthand shared with ``seqr scan code`` (``strict`` = fail on
      ``high``+, ``lax`` = fail on ``critical`` only).
    * **Policy drift** — with ``fail_on_drift``, any NEW finding that violates the org's
      declared crypto policy (``drift``, already narrowed to new/un-baselined findings by
      the caller) fails the build.

    With no axis engaged the gate never fails (advisory). When both engage, the reason
    names whichever tripped.
    """
    drift = drift or []
    drift_trips = bool(fail_on_drift and drift)

    severity_trip = None
    if fail_on or policy:
        thresholds: list[str] = []
        if fail_on:
            thresholds.append(fail_on)
        if policy:
            thresholds.append("high" if policy == "strict" else "critical")
        # Fail if EITHER flag would trip, matching `seqr scan code` (which exits on
        # --fail-on or --policy independently). That is the lowest-severity threshold.
        threshold = min(thresholds, key=lambda s: SEVERITY_ORDER.index(s))
        idx = SEVERITY_ORDER.index(threshold)
        tripped = [
            f for f in findings
            if SEVERITY_ORDER.index(severity_for_risk(f.algorithm_risk)) >= idx
        ]
        severity_trip = (threshold, len(tripped)) if tripped else (threshold, 0)

    if not (fail_on or policy) and not fail_on_drift:
        return GateDecision(False, "advisory mode (no --fail-on/--policy/--fail-on-drift)", None)

    # Build the outcome, preferring the most actionable reason.
    reasons: list[str] = []
    should_fail = False
    threshold_name = severity_trip[0] if severity_trip else None
    if severity_trip and severity_trip[1]:
        should_fail = True
        reasons.append(f"{severity_trip[1]} finding(s) at or above '{severity_trip[0]}'")
    if drift_trips:
        should_fail = True
        reasons.append(f"{len(drift)} new finding(s) drift from the crypto policy")

    if should_fail:
        return GateDecision(True, "; ".join(reasons), threshold_name, drift_count=len(drift) if drift_trips else 0)

    # Nothing tripped — describe what was checked.
    parts: list[str] = []
    if severity_trip:
        parts.append(f"no findings at or above '{severity_trip[0]}'")
    if fail_on_drift:
        parts.append("no new policy drift")
    return GateDecision(False, "; ".join(parts) or "advisory mode", threshold_name)
