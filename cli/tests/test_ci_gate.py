"""CI-gate filtering, exit-code decision, and Markdown rendering."""
from dataclasses import dataclass

import pytest

from seqr.ci import build_markdown, decide, filter_to_added, normalize_path
from seqr.ci.report import HNDL_DISCLAIMER


@dataclass
class F:
    """Minimal stand-in for a scanner CodeFinding (only the fields the gate reads)."""
    file_path: str
    line_number: int
    algorithm: str = "RSA-2048"
    algorithm_risk: int = 8            # -> "high"
    estimated_effort_hours: float = 3
    hndl_risk: str = ""
    recommended_replacement: str = "ML-KEM-768"


# -- filter_to_added ----------------------------------------------------------

def test_filter_keeps_only_added_lines():
    findings = [F("src/a.py", 10), F("src/a.py", 99), F("src/b.py", 5)]
    added = {"src/a.py": {10, 11}, "src/b.py": {1, 2}}
    kept = filter_to_added(findings, added, root=".")
    assert [(f.file_path, f.line_number) for f in kept] == [("src/a.py", 10)]


def test_filter_empty_diff_keeps_nothing():
    assert filter_to_added([F("a.py", 1)], {}, root=".") == []


def test_filter_basename_fallback_when_paths_differ():
    # Finding path is absolute-ish / differently rooted, diff path is repo-relative.
    findings = [F("/abs/checkout/src/a.py", 10)]
    added = {"src/a.py": {10}}
    kept = filter_to_added(findings, added, root="/abs/checkout")
    assert len(kept) == 1


def test_normalize_path_is_posix_relative():
    assert normalize_path("sub/x.py", root=".") == "sub/x.py"


# -- decide (exit code) -------------------------------------------------------

def test_advisory_by_default_never_fails():
    d = decide([F("a", 1, algorithm_risk=9)], fail_on=None, policy=None)
    assert d.should_fail is False


def test_fail_on_high_trips_on_high_finding():
    d = decide([F("a", 1, algorithm_risk=8)], fail_on="high", policy=None)
    assert d.should_fail is True


def test_fail_on_critical_ignores_high():
    d = decide([F("a", 1, algorithm_risk=8)], fail_on="critical", policy=None)
    assert d.should_fail is False


def test_policy_strict_fails_on_high():
    assert decide([F("a", 1, algorithm_risk=8)], None, "strict").should_fail is True


def test_policy_lax_only_fails_on_critical():
    assert decide([F("a", 1, algorithm_risk=8)], None, "lax").should_fail is False
    assert decide([F("a", 1, algorithm_risk=9)], None, "lax").should_fail is True


def test_combined_flags_fail_if_either_trips():
    # Matches `seqr scan code`: fail_on=critical OR policy=strict(high) — a 'high'
    # finding trips the strict-policy half, so the build fails.
    d = decide([F("a", 1, algorithm_risk=8)], fail_on="critical", policy="strict")
    assert d.should_fail is True


def test_no_findings_never_fails():
    assert decide([], fail_on="low", policy=None).should_fail is False


# -- markdown -----------------------------------------------------------------

def test_markdown_clean_when_no_findings():
    md = build_markdown([])
    assert "No quantum-vulnerable" in md
    assert "SeQr" in md


def test_markdown_lists_findings_and_pqcmap():
    md = build_markdown([F("src/auth.py", 42, algorithm="RSA-SHA256", algorithm_risk=9)])
    assert "src/auth.py" in md and "42" in md
    assert "RSA-SHA256" in md
    assert "pqcmap" in md


def test_markdown_hndl_includes_disclaimer():
    md = build_markdown([F("src/a.py", 1, hndl_risk="HIGH")])
    assert "HNDL" in md
    assert HNDL_DISCLAIMER in md


def test_markdown_never_mentions_cnsa():
    md = build_markdown([F("src/a.py", 1, hndl_risk="HIGH", algorithm_risk=9)])
    assert "CNSA" not in md
