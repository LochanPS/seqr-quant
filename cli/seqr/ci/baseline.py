"""Baseline of accepted existing findings, so only *new* drift fails the build.

A brand-new gate on a legacy codebase would fail on crypto that predates the policy —
noise that trains teams to ignore it. The baseline records the findings an org has
already accepted (``seqr-baseline.json``); the gate then subtracts them so only crypto a
change *introduces* — genuine new drift — can trip it. Refresh the file with
``seqr ci --update-baseline`` when the accepted set legitimately changes.

A finding is fingerprinted by ``(repo-relative path, pattern, algorithm, code snippet)`` —
deliberately **not** its line number, so reformatting or moving code around does not
silently un-baseline an already-accepted finding.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

BASELINE_FILENAMES = ("seqr-baseline.json",)
BASELINE_SCHEMA_VERSION = 1


def _rel_posix(path: str, root: str | None = None) -> str:
    root = root or os.getcwd()
    try:
        rel = os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        rel = path
    return PurePosixPath(Path(rel).as_posix()).as_posix()


def fingerprint(finding, root: str | None = None) -> str:
    """Stable, line-independent identity for a finding (see module docstring)."""
    path = _rel_posix(getattr(finding, "file_path", ""), root)
    pattern = getattr(finding, "pattern_id", "") or ""
    algorithm = getattr(finding, "algorithm", "") or ""
    snippet = (getattr(finding, "code_snippet", "") or "").strip()
    raw = "\n".join([path, pattern, algorithm, snippet])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class Baseline:
    """Loaded baseline: the accepted fingerprints plus the raw file body."""

    fingerprints: set[str]
    body: dict

    def contains(self, finding, root: str | None = None) -> bool:
        return fingerprint(finding, root) in self.fingerprints

    @classmethod
    def empty(cls) -> "Baseline":
        return cls(set(), {"version": BASELINE_SCHEMA_VERSION, "findings": []})


def find_baseline_file(root: str | os.PathLike[str] | None = None) -> Path | None:
    """Return the first auto-discovered baseline file in ``root`` (cwd default), or None."""
    base = Path(root or os.getcwd())
    for name in BASELINE_FILENAMES:
        p = base / name
        if p.is_file():
            return p
    return None


def load_baseline(path: str | os.PathLike[str]) -> Baseline:
    """Load a baseline file. A missing file yields an empty baseline (fail-open)."""
    p = Path(path)
    if not p.is_file():
        return Baseline.empty()
    body = json.loads(p.read_text(encoding="utf-8"))
    fps = {
        entry["fingerprint"]
        for entry in body.get("findings", [])
        if isinstance(entry, dict) and entry.get("fingerprint")
    }
    return Baseline(fps, body)


def build_baseline(findings: list, root: str | None = None, *, note: str = "accepted existing finding") -> dict:
    """Render a baseline file body recording ``findings`` as accepted.

    Entries are sorted by fingerprint for a stable, reviewable diff, and each carries
    human-readable context (file / algorithm / pattern) alongside the fingerprint.
    """
    seen: dict[str, dict] = {}
    for f in findings:
        fp = fingerprint(f, root)
        if fp in seen:
            continue
        seen[fp] = {
            "fingerprint": fp,
            "file": _rel_posix(getattr(f, "file_path", ""), root),
            "algorithm": getattr(f, "algorithm", ""),
            "pattern_id": getattr(f, "pattern_id", ""),
            "note": note,
        }
    return {
        "version": BASELINE_SCHEMA_VERSION,
        "tool": "seqr ci",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "count": len(seen),
        "findings": [seen[k] for k in sorted(seen)],
    }


def save_baseline(path: str | os.PathLike[str], findings: list, root: str | None = None) -> int:
    """Write a baseline of ``findings`` to ``path``. Returns the accepted-finding count."""
    body = build_baseline(findings, root)
    Path(path).write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return body["count"]


def filter_new(findings: list, baseline: Baseline, root: str | None = None) -> tuple[list, list]:
    """Split ``findings`` into ``(new, baselined)`` against ``baseline``."""
    new: list = []
    baselined: list = []
    for f in findings:
        (baselined if baseline.contains(f, root) else new).append(f)
    return new, baselined


__all__ = [
    "Baseline",
    "BASELINE_FILENAMES",
    "BASELINE_SCHEMA_VERSION",
    "fingerprint",
    "find_baseline_file",
    "load_baseline",
    "build_baseline",
    "save_baseline",
    "filter_new",
]
