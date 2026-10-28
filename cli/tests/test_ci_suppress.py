"""Inline `# seqr:ignore` suppressions and `.seqrignore` path exclusions."""
from dataclasses import dataclass

from seqr.ci.suppress import (
    apply_inline_suppressions,
    apply_path_ignores,
    parse_seqrignore,
    path_is_ignored,
)


@dataclass
class F:
    file_path: str
    line_number: int
    algorithm: str = "RSA-2048"


# -- inline markers -----------------------------------------------------------

def test_inline_marker_on_same_line(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("import rsa  # seqr:ignore[legacy vendor]\n", encoding="utf-8")
    kept, suppressed = apply_inline_suppressions([F(str(p), 1)])
    assert kept == []
    assert len(suppressed) == 1
    assert suppressed[0].reason == "legacy vendor"


def test_inline_marker_on_line_above(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("# seqr:ignore\nimport rsa\n", encoding="utf-8")
    kept, suppressed = apply_inline_suppressions([F(str(p), 2)])
    assert kept == []
    assert suppressed[0].reason == ""


def test_no_marker_keeps_finding(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("import rsa\n", encoding="utf-8")
    kept, suppressed = apply_inline_suppressions([F(str(p), 1)])
    assert len(kept) == 1 and suppressed == []


def test_unreadable_file_suppresses_nothing():
    kept, suppressed = apply_inline_suppressions([F("does/not/exist.py", 1)])
    assert len(kept) == 1 and suppressed == []


def test_marker_works_with_slash_comment(tmp_path):
    p = tmp_path / "a.js"
    p.write_text("const k = rsa();  // seqr:ignore[known]\n", encoding="utf-8")
    kept, suppressed = apply_inline_suppressions([F(str(p), 1)])
    assert kept == [] and suppressed[0].reason == "known"


# -- .seqrignore --------------------------------------------------------------

def test_parse_skips_comments_and_blanks():
    text = "# a comment\n\nvendor/\n*.min.js\n"
    assert parse_seqrignore(text) == ["vendor/", "*.min.js"]


def test_dir_pattern_matches_subtree():
    pats = ["vendor/"]
    assert path_is_ignored("vendor/lib/x.py", pats)
    assert not path_is_ignored("src/vendor_helper.py", pats)


def test_bare_name_matches_any_depth():
    pats = ["node_modules"]
    assert path_is_ignored("a/b/node_modules/pkg/i.js", pats)


def test_glob_extension():
    pats = ["*.min.js"]
    assert path_is_ignored("static/app.min.js", pats)
    assert not path_is_ignored("static/app.js", pats)


def test_anchored_pattern():
    pats = ["/build/"]
    assert path_is_ignored("build/out.py", pats)
    assert not path_is_ignored("src/build/out.py", pats)


def test_apply_path_ignores_splits(tmp_path):
    findings = [F(str(tmp_path / "vendor" / "x.py"), 1),
                F(str(tmp_path / "src" / "y.py"), 1)]
    kept, ignored = apply_path_ignores(findings, ["vendor/"], root=str(tmp_path))
    assert [f.file_path for f in kept] == [str(tmp_path / "src" / "y.py")]
    assert len(ignored) == 1


def test_empty_patterns_keep_all():
    findings = [F("src/a.py", 1)]
    kept, ignored = apply_path_ignores(findings, [], root=".")
    assert len(kept) == 1 and ignored == []
