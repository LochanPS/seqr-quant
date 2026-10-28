"""SARIF 2.1.0 output for GitHub Code Scanning upload.

Uploaded via ``github/codeql-action/upload-sarif``, this renders each finding as a code
scanning alert annotated on the exact source line. Two details make the alerts render
well:

* **Repo-relative paths** — ``artifactLocation.uri`` must be relative to the repo root, or
  GitHub cannot map the alert to a line. Pass ``root`` (the scanned repo root) so absolute
  scanner paths are relativised.
* **security-severity** — GitHub reads the numeric ``security-severity`` rule property to
  colour the alert (error/warning/note alone does not set it). We map the 0-10
  ``algorithm_risk`` straight through.

Stable ``partialFingerprints`` let code scanning track the same alert across runs (and match
the CI baseline's identity) rather than opening a fresh alert each push.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
from typing import Any

from seqr._severity import severity_for_risk

__all__ = ["build_sarif"]

_SEV_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_HELP_URI = "https://seqrlabs.com/sdk"


def _rel_uri(file_path: str, root: str | None) -> str:
    """Repo-relative POSIX URI for ``file_path`` (best-effort; falls back to as-is)."""
    p = file_path.replace("\\", "/")
    if root:
        try:
            rel = os.path.relpath(file_path, root)
            if not rel.startswith(".."):  # inside the repo
                p = Path(rel).as_posix()
        except ValueError:  # different drive on Windows
            pass
    return PurePosixPath(p).as_posix()


def _fingerprint(uri: str, finding) -> str:
    """Line-independent identity, matching the CI baseline fingerprint inputs."""
    raw = "\n".join([
        uri,
        getattr(finding, "pattern_id", "") or "",
        getattr(finding, "algorithm", "") or "",
        (getattr(finding, "code_snippet", "") or "").strip(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_sarif(findings: list, root: str | None = None) -> dict[str, Any]:
    from seqr import __version__

    # Deduplicate rules
    rules: dict[str, dict] = {}
    for f in findings:
        rid = f.pattern_id
        if rid not in rules:
            sev = severity_for_risk(f.algorithm_risk)
            rules[rid] = {
                "id": rid,
                "name": _to_camel(f.algorithm),
                "shortDescription": {"text": f"{f.algorithm} is quantum-vulnerable"},
                "fullDescription": {
                    "text": (
                        f"{f.algorithm} ({f.algorithm_family}) will be broken by Shor's algorithm "
                        f"on quantum computers. Replace with {f.recommended_replacement}."
                    )
                },
                "helpUri": _HELP_URI,
                "defaultConfiguration": {"level": _SEV_TO_SARIF.get(sev, "warning")},
                "properties": {
                    # GitHub reads this numeric string to set the alert's severity.
                    "security-severity": f"{float(max(0, min(10, f.algorithm_risk))):.1f}",
                    "tags": ["security", "quantum", "pqc", "external/cwe/cwe-327"],
                },
            }

    results = []
    for f in findings:
        sev = severity_for_risk(f.algorithm_risk)
        uri = _rel_uri(f.file_path, root)
        results.append({
            "ruleId": f.pattern_id,
            "level": _SEV_TO_SARIF.get(sev, "warning"),
            "message": {
                "text": (
                    f"{f.algorithm} is quantum-vulnerable. "
                    f"Replace with {f.recommended_replacement}."
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": f.line_number},
                }
            }],
            "partialFingerprints": {"seqrPatternHash/v1": _fingerprint(uri, f)},
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SeQr PQC Scanner",
                    "informationUri": "https://seqrlabs.com",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def _to_camel(s: str) -> str:
    return "".join(w.capitalize() for w in s.replace("-", " ").replace("_", " ").split())
