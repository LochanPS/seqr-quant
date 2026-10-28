"""Parse a unified git diff into the set of *added* line numbers per file.

The CI gate flags only crypto that a pull request introduces — findings on lines the
PR added — so pre-existing issues never fail an unrelated build (see the "scan only
new lines" design decision in docs/07_GitHub_App_PRD.md). This module turns a unified
diff into ``{path: {added_line_numbers}}``; the gate then keeps findings whose line is
in that set.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import PurePosixPath

# @@ -old_start,old_len +new_start,new_len @@
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    """Return ``{repo_relative_path: {added_line_numbers}}`` from unified diff text.

    Works at any context level (``--unified=N``): the new-file line counter advances
    on context and added lines and holds on removed lines, so added-line numbers are
    exact. Files deleted in the diff (``+++ /dev/null``) are skipped.
    """
    added: dict[str, set[int]] = {}
    current_file: str | None = None
    new_ln = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            current_file = _strip_diff_path(line[4:].strip())
            continue
        if line.startswith("--- "):
            continue
        m = _HUNK_RE.match(line)
        if m:
            new_ln = int(m.group(1))
            continue
        if current_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.setdefault(current_file, set()).add(new_ln)
            new_ln += 1
        elif line.startswith("-") and not line.startswith("---"):
            # removed line — new-file counter does not advance
            pass
        elif line.startswith("\\"):
            # "\ No newline at end of file" — not a real line
            pass
        else:
            # context line (or blank) — advances the new-file counter
            new_ln += 1

    return added


def _strip_diff_path(path: str) -> str | None:
    """Normalise a diff header path (``b/src/x.py`` → ``src/x.py``); None for /dev/null."""
    if path == "/dev/null":
        return None
    # git uses a/ and b/ prefixes; also tolerate quoted paths.
    path = path.strip('"')
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return PurePosixPath(path).as_posix()


def git_diff(base: str, cwd: str | None = None) -> str:
    """Return the unified diff of the working tree vs ``base`` (e.g. ``origin/main``).

    Uses the merge-base (``base...HEAD`` semantics) so only the PR's own changes show,
    not commits that landed on the base branch since it forked. Raises
    :class:`GitDiffError` if git is unavailable or the ref is unknown.
    """
    try:
        merge_base = subprocess.run(
            ["git", "merge-base", base, "HEAD"],
            cwd=cwd, capture_output=True, text=True,
        )
        left = merge_base.stdout.strip() if merge_base.returncode == 0 else base
        proc = subprocess.run(
            ["git", "diff", "--unified=0", left, "--"],
            cwd=cwd, capture_output=True, text=True,
        )
    except FileNotFoundError as exc:  # git not installed
        raise GitDiffError("git executable not found on PATH.") from exc
    if proc.returncode != 0:
        raise GitDiffError(
            f"git diff against {base!r} failed: {proc.stderr.strip() or 'unknown error'}"
        )
    return proc.stdout


def auto_base(cwd: str | None = None) -> str:
    """Pick a sensible base ref to diff against when the caller gives none.

    Tries common CI base refs in order and returns the first that resolves; falls back
    to ``HEAD~1`` (the previous commit) so a local run still has something to compare.
    """
    candidates = ["origin/main", "origin/master", "main", "master", "HEAD~1"]
    for ref in candidates:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", ref],
                cwd=cwd, capture_output=True, text=True,
            )
        except FileNotFoundError as exc:
            raise GitDiffError("git executable not found on PATH.") from exc
        if proc.returncode == 0 and proc.stdout.strip():
            return ref
    return "HEAD~1"


class GitDiffError(RuntimeError):
    """Raised when a git diff cannot be produced (git missing, unknown ref, etc.)."""
