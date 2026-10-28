"""Turn a GitHub file ``patch`` into the set of line numbers the PR *added*.

The GitHub "list pull request files" API returns a per-file unified-diff fragment in the
``patch`` field (already scoped to that file, no ``+++``/``---`` headers). We only flag
crypto a PR introduces (PRD 07, "scan only new lines"), so this maps each patch to the
new-file line numbers of its added (``+``) lines. Mirrors the CLI's ``parse_unified_diff``
but for a single file's fragment.
"""
from __future__ import annotations

import re

# @@ -old_start,old_len +new_start,new_len @@
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines(patch: str | None) -> set[int]:
    """Return the new-file line numbers added by ``patch`` (empty for None/binary)."""
    if not patch:
        return set()
    added: set[int] = set()
    new_ln = 0
    in_hunk = False
    for line in patch.splitlines():
        m = _HUNK_RE.match(line)
        if m:
            new_ln = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+"):
            added.add(new_ln)
            new_ln += 1
        elif line.startswith("-"):
            # removed line — the new-file counter does not advance
            pass
        elif line.startswith("\\"):
            # "\ No newline at end of file" — not a real line
            pass
        else:
            # context line (or blank) — advances the new-file counter
            new_ln += 1
    return added
