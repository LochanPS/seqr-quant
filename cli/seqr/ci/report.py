"""Render CI-gate findings as a PR-style Markdown comment.

Format follows docs/07_GitHub_App_PRD.md. Honours the CLAUDE.md output rules: the
HNDL legal disclaimer accompanies every HNDL mention, no CNSA 2.0 references, and the
severity language stays on the CLI's low/medium/high/critical scale.
"""
from __future__ import annotations

from seqr._severity import severity_for_risk

HNDL_DISCLAIMER = (
    "HNDL exposure scores are predictive cryptographic risk metrics based on "
    "data-type endurance, not indicators of active data interception or confirmed "
    "network breaches."
)

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _effort(hours: float) -> str:
    if not hours:
        return "—"
    if hours < 1:
        return "<1h"
    lo = int(hours)
    return f"{lo}–{lo + 2}h"


def _accepted_note(suppressed: int, baselined: int) -> str | None:
    """One line accounting for findings the gate consciously set aside, or None."""
    bits = []
    if baselined:
        bits.append(f"{baselined} accepted via baseline")
    if suppressed:
        bits.append(f"{suppressed} suppressed inline")
    return "*" + "; ".join(bits) + ".*" if bits else None


def build_markdown(
    findings: list,
    *,
    base: str | None = None,
    gate=None,
    suppressed: int = 0,
    baselined: int = 0,
    drift_ids: set | None = None,
) -> str:
    """Return the Markdown review body for ``findings`` (PR-added crypto only).

    ``suppressed`` / ``baselined`` account for findings the gate set aside (inline
    ``# seqr:ignore`` and the baseline). ``drift_ids`` is the set of ``id(finding)`` that
    violate the org crypto policy — those rows are flagged so a reviewer sees policy drift
    distinctly from advisory severity.
    """
    drift_ids = drift_ids or set()
    note = _accepted_note(suppressed, baselined)
    lines: list[str] = ["## 🔐 SeQr PQC Scan Results", ""]

    if not findings:
        lines += [
            "✅ No quantum-vulnerable cryptographic patterns introduced in this change.",
        ]
        if note:
            lines += ["", note]
        lines += ["", _footer()]
        return "\n".join(lines)

    n = len(findings)
    scope = f" against `{base}`" if base else ""
    lines.append(
        f"Found **{n} quantum-vulnerable** cryptographic "
        f"{'pattern' if n == 1 else 'patterns'} introduced in this change{scope}."
    )
    lines.append("")

    if note:
        lines.append(note)
        lines.append("")

    # Findings table. A ⛔ marks a finding that drifts from the org crypto policy.
    has_drift = any(id(f) in drift_ids for f in findings)
    drift_col = " Policy |" if has_drift else ""
    drift_sep = "--------|" if has_drift else ""
    lines.append(f"| File | Line | Algorithm | Severity |{drift_col} Est. Fix |")
    lines.append(f"|------|------|-----------|----------|{drift_sep}----------|")
    for f in sorted(findings, key=lambda x: -x.algorithm_risk):
        sev = severity_for_risk(f.algorithm_risk)
        icon = _SEV_ICON.get(sev, "")
        drift_cell = (" ⛔ drift |" if id(f) in drift_ids else " — |") if has_drift else ""
        lines.append(
            f"| `{f.file_path}` | {f.line_number} | {f.algorithm} | "
            f"{icon} {sev.upper()} |{drift_cell} {_effort(f.estimated_effort_hours)} |"
        )
    lines.append("")

    # HNDL section — only if any finding carries HNDL risk; disclaimer always attached.
    hndl = [f for f in findings if getattr(f, "hndl_risk", None)]
    if hndl:
        lines.append("### ⚡ HNDL Risk")
        for f in hndl:
            lines.append(
                f"- `{f.file_path}:{f.line_number}` — {f.hndl_risk} harvest-now, "
                "decrypt-later exposure."
            )
        lines.append("")
        lines.append(f"> *{HNDL_DISCLAIMER}*")
        lines.append("")

    # Recommended fixes
    lines.append("### Recommended Fixes")
    for f in findings:
        rec = getattr(f, "recommended_replacement", None) or "a NIST PQC algorithm"
        lines.append(f"- **{f.file_path}:{f.line_number}** — replace {f.algorithm} with {rec}.")
    lines.append("")
    lines.append(
        "See [`pqcmap`](https://seqrlabs.com/sdk) for drop-in ML-KEM / ML-DSA "
        "replacements (`pip install pqcmap`)."
    )
    lines.append("")

    if gate is not None and gate.should_fail:
        lines.append(f"> ❌ **Gate failed:** {gate.reason}.")
        lines.append("")

    lines.append(_footer())
    return "\n".join(lines)


def _footer() -> str:
    return "---\n*Powered by [SeQr](https://seqrlabs.com) · scan only, exit 0 by default.*"
