"""Render scan findings into a GitHub PR review + commit status (PRD 07, CI-4).

Pure formatting/decision logic — no network, no DB — so it is unit-testable in isolation.
The worker (``tasks.py``) feeds it the findings the PR added and posts the result.

Design rules from the PRD are enforced here: scan only new lines (the caller passes only
added-line findings), exit-0-by-default (an empty ``fail_on`` never fails a status), the
HNDL disclaimer accompanies every HNDL mention, and no CNSA 2.0 / US-NSS references appear.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.github_app.severity import at_or_above, severity_for_risk

_HNDL_DISCLAIMER = (
    "*HNDL exposure scores are predictive cryptographic risk metrics based on data-type "
    "endurance, not indicators of active data interception or confirmed network breaches.*"
)

_SEVERITY_EMOJI = {"critical": "🔴", "high": "🔴", "medium": "🟠", "low": "🟡"}

_FOOTER = "*Powered by [SeQr](https://seqrlabs.com) · [Docs](https://docs.seqrlabs.com)*"


@dataclass
class ScanReview:
    body: str
    comments: list[dict[str, Any]]
    event: str                       # COMMENT (never REQUEST_CHANGES — advisory posture)
    status_state: str                # success | failure
    status_description: str
    findings_count: int
    max_severity: str | None
    summary: dict[str, Any] = field(default_factory=dict)


def _severity(f: Any) -> str:
    return severity_for_risk(getattr(f, "algorithm_risk", 0) or 0)


def _emoji(sev: str) -> str:
    return _SEVERITY_EMOJI.get(sev, "🟡")


def _effort(f: Any) -> str:
    hrs = getattr(f, "estimated_effort_hours", 0) or 0
    return f"{hrs}h" if hrs else "—"


def _gate(findings: list[Any], fail_on: str) -> tuple[str, str, str | None]:
    """Return (status_state, description, max_severity).

    ``fail_on`` empty → advisory: the status is always ``success`` (exit-0-by-default).
    Otherwise the status fails when any finding is at or above the threshold.
    """
    if not findings:
        return "success", "No new quantum-vulnerable patterns", None
    severities = [_severity(f) for f in findings]
    order = ["low", "medium", "high", "critical"]
    max_sev = max(severities, key=order.index)
    n = len(findings)
    if not fail_on:
        return "success", f"{n} advisory PQC finding(s) — max {max_sev}", max_sev
    tripped = [s for s in severities if at_or_above(s, fail_on)]
    if tripped:
        return "failure", f"{len(tripped)} finding(s) at or above '{fail_on}'", max_sev
    return "success", f"{n} finding(s), none at or above '{fail_on}'", max_sev


def build_review(findings: list[Any], *, fail_on: str = "") -> ScanReview:
    """Build the review body, inline comments, and commit-status decision."""
    state, description, max_sev = _gate(findings, fail_on)

    if not findings:
        body = (
            "## 🔐 SeQr PQC Scan Results\n\n"
            "✅ No quantum-vulnerable patterns found in this PR.\n\n"
            f"---\n{_FOOTER}"
        )
        return ScanReview(
            body=body, comments=[], event="COMMENT", status_state=state,
            status_description=description, findings_count=0, max_severity=None,
            summary={"findings": 0},
        )

    lines = [
        "## 🔐 SeQr PQC Scan Results",
        "",
        f"Found **{len(findings)} quantum-vulnerable** cryptographic pattern(s) "
        "introduced in this PR.",
        "",
        "| File | Line | Algorithm | Severity | Est. Fix |",
        "|------|------|-----------|----------|----------|",
    ]
    hndl_notes: list[str] = []
    fix_notes: list[str] = []
    comments: list[dict[str, Any]] = []

    for f in findings:
        sev = _severity(f)
        path = getattr(f, "file_path", "")
        line = getattr(f, "line_number", 0)
        algo = getattr(f, "algorithm", "") or getattr(f, "algorithm_family", "") or "unknown"
        lines.append(
            f"| `{path}` | {line} | {algo} | {_emoji(sev)} {sev.upper()} | {_effort(f)} |"
        )

        if getattr(f, "hndl_risk", False):
            hndl_notes.append(f"`{path}:{line}` — {algo} is exposed to harvest-now-decrypt-later risk.")

        replacement = getattr(f, "recommended_replacement", "") or ""
        if replacement:
            fix_notes.append(f"**{path}:{line}** — {replacement}")

        # Inline review comment on the exact added line (RIGHT side of the diff).
        comment_body = f"{_emoji(sev)} **{sev.upper()}** — `{algo}` is quantum-vulnerable."
        if replacement:
            comment_body += f"\n\n**Recommended:** {replacement}"
        comments.append({"path": path, "line": line, "side": "RIGHT", "body": comment_body})

    if hndl_notes:
        lines += ["", "### ⚡ HNDL Risk", *hndl_notes, "", _HNDL_DISCLAIMER]
    if fix_notes:
        lines += ["", "### Recommended Fixes", *fix_notes]

    lines += ["", "---", _FOOTER]

    summary = {
        "findings": len(findings),
        "max_severity": max_sev,
        "by_severity": _count_by_severity(findings),
        "gate": {"state": state, "fail_on": fail_on or None, "description": description},
    }
    return ScanReview(
        body="\n".join(lines), comments=comments, event="COMMENT", status_state=state,
        status_description=description, findings_count=len(findings), max_severity=max_sev,
        summary=summary,
    )


def _count_by_severity(findings: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        s = _severity(f)
        counts[s] = counts.get(s, 0) + 1
    return counts


def finding_to_dict(f: Any) -> dict[str, Any]:
    """Serialise a CodeFinding for persistence as a CIReport row (JSON-safe)."""
    return {
        "pattern_id": getattr(f, "pattern_id", None),
        "file_path": getattr(f, "file_path", None),
        "line_number": getattr(f, "line_number", None),
        "algorithm": getattr(f, "algorithm", None),
        "algorithm_family": getattr(f, "algorithm_family", None),
        "quantum_status": getattr(f, "quantum_status", None),
        "algorithm_risk": getattr(f, "algorithm_risk", None),
        "severity": _severity(f),
        "confidence": getattr(f, "confidence", None),
        "recommended_replacement": getattr(f, "recommended_replacement", None),
        "estimated_effort_hours": getattr(f, "estimated_effort_hours", None),
        "hndl_risk": getattr(f, "hndl_risk", None),
        "library_name": getattr(f, "library_name", None),
    }
