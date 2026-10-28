"""Two ways to silence a finding the team has consciously decided to accept.

1. **Inline** — ``# seqr:ignore`` (optionally ``# seqr:ignore[reason]``) on the finding's
   own line, or the line directly above it. Language-agnostic: the marker is matched
   anywhere on the line, so ``//``, ``#`` and ``--`` comment styles all work.

2. **Path** — a ``.seqrignore`` file (gitignore-style globs) excludes whole files or
   directories from the gate, e.g. vendored or generated code.

Both are *suppression*, not deletion: they only affect what the gate considers, never the
underlying scan. An inline reason is captured so a reviewer can see *why* something was
waved through.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SEQRIGNORE_FILENAMES = (".seqrignore",)

# `seqr:ignore` or `seqr:ignore[some reason]`, anywhere on a line, case-insensitive.
_IGNORE_RE = re.compile(r"seqr:ignore(?:\[([^\]]*)\])?", re.IGNORECASE)


@dataclass(frozen=True)
class Suppressed:
    """A finding removed by an inline marker, with the reason if one was given."""

    finding: object
    reason: str  # "" when the marker carried no [reason]


def _line_at(lines: list[str], n: int) -> str:
    """1-indexed line ``n`` from ``lines`` (empty string if out of range)."""
    return lines[n - 1] if 1 <= n <= len(lines) else ""


def _inline_reason(lines: list[str], line_number: int) -> tuple[bool, str] | None:
    """Return ``(True, reason)`` if a marker sits on ``line_number`` or the line above."""
    for n in (line_number, line_number - 1):
        m = _IGNORE_RE.search(_line_at(lines, n))
        if m:
            return True, (m.group(1) or "").strip()
    return None


def apply_inline_suppressions(findings: list) -> tuple[list, list[Suppressed]]:
    """Split ``findings`` into ``(kept, suppressed)`` using inline ``# seqr:ignore``.

    Source files are read once each and cached; an unreadable file suppresses nothing.
    """
    cache: dict[str, list[str]] = {}
    kept: list = []
    suppressed: list[Suppressed] = []

    for f in findings:
        path = getattr(f, "file_path", "")
        if path not in cache:
            try:
                cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, ValueError):
                cache[path] = []
        hit = _inline_reason(cache[path], getattr(f, "line_number", 0))
        if hit is not None:
            suppressed.append(Suppressed(f, hit[1]))
        else:
            kept.append(f)
    return kept, suppressed


# --- .seqrignore (gitignore-style path matching) ----------------------------

def parse_seqrignore(text: str) -> list[str]:
    """Return the non-comment, non-blank patterns from ``.seqrignore`` text."""
    patterns: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def load_seqrignore(root: str | os.PathLike[str] | None = None) -> list[str]:
    """Load patterns from a ``.seqrignore`` in ``root`` (cwd default); [] if absent."""
    base = Path(root or os.getcwd())
    for name in SEQRIGNORE_FILENAMES:
        p = base / name
        if p.is_file():
            return parse_seqrignore(p.read_text(encoding="utf-8"))
    return []


def _matches(rel_posix: str, pattern: str) -> bool:
    """gitignore-ish match of a repo-relative POSIX path against one pattern.

    Supports a leading ``/`` (anchor to root), a trailing ``/`` (directory), and ``*`` /
    ``**`` globs. A bare name (no ``/``) matches that name at any depth.
    """
    anchored = pattern.startswith("/")
    pat = pattern.lstrip("/")
    dir_only = pat.endswith("/")
    pat = pat.rstrip("/")
    if not pat:
        return False

    # `**` is gitignore's "any depth" glob; fnmatch's own `*` already crosses `/`, so
    # collapsing `**` to `*` gives the same recursive reach without a bespoke regex.
    pat = pat.replace("**", "*")
    segments = rel_posix.split("/")

    if dir_only:
        # A directory pattern matches the directory itself and everything under it.
        if anchored or "/" in pat:
            return rel_posix == pat or rel_posix.startswith(pat + "/")
        return pat in segments[:-1]

    if anchored or "/" in pat:
        return fnmatch.fnmatch(rel_posix, pat) or rel_posix.startswith(pat + "/")

    # Bare name: match a file basename or any path segment.
    return any(fnmatch.fnmatch(seg, pat) for seg in segments)


def path_is_ignored(rel_posix: str, patterns: list[str]) -> bool:
    """True if ``rel_posix`` matches any ``.seqrignore`` pattern."""
    return any(_matches(rel_posix, p) for p in patterns)


def apply_path_ignores(
    findings: list, patterns: list[str], root: str | None = None
) -> tuple[list, list]:
    """Split ``findings`` into ``(kept, ignored)`` by ``.seqrignore`` path patterns."""
    if not patterns:
        return list(findings), []
    root = root or os.getcwd()
    kept: list = []
    ignored: list = []
    for f in findings:
        try:
            rel = PurePosixPath(Path(os.path.relpath(getattr(f, "file_path", ""), root)).as_posix()).as_posix()
        except ValueError:
            rel = getattr(f, "file_path", "")
        (ignored if path_is_ignored(rel, patterns) else kept).append(f)
    return kept, ignored


__all__ = [
    "Suppressed",
    "SEQRIGNORE_FILENAMES",
    "apply_inline_suppressions",
    "parse_seqrignore",
    "load_seqrignore",
    "path_is_ignored",
    "apply_path_ignores",
]
