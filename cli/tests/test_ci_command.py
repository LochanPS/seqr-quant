"""End-to-end `seqr ci` command tests (via --diff, so no git repo is required)."""
import json

import pytest
from click.testing import CliRunner

from seqr.cli import main


@pytest.fixture
def runner():
    return CliRunner()


VULN = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n'


def _project(tmp_path):
    (tmp_path / "vuln.py").write_text(VULN, encoding="utf-8")
    return tmp_path


def _diff_adding(path, filename, *lines):
    """Write a minimal unified diff marking `lines` (contiguous) as added in filename."""
    hunk_body = "".join("+added\n" for _ in lines)
    text = (
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        f"@@ -1,0 +{lines[0]},{len(lines)} @@\n"
        + hunk_body
    )
    p = path / "changes.diff"
    p.write_text(text, encoding="utf-8")
    return p


def test_gate_flags_added_vulnerability_and_fails_when_asked(runner, tmp_path):
    proj = _project(tmp_path)
    diff = _diff_adding(tmp_path, "vuln.py", 2)  # line 2 = the RS256 call
    result = runner.invoke(
        main, ["ci", str(proj), "--diff", str(diff), "--fail-on", "high"]
    )
    assert result.exit_code == 1
    assert "quantum-vulnerable" in result.output
    assert "vuln.py" in result.output


def test_gate_exit_zero_by_default_even_with_findings(runner, tmp_path):
    proj = _project(tmp_path)
    diff = _diff_adding(tmp_path, "vuln.py", 2)
    result = runner.invoke(main, ["ci", str(proj), "--diff", str(diff)])
    assert result.exit_code == 0  # advisory mode: report, never break the build


def test_gate_ignores_untouched_lines(runner, tmp_path):
    proj = _project(tmp_path)
    # Diff only adds line 1 (the import), not line 2 (the actual finding).
    diff = _diff_adding(tmp_path, "vuln.py", 1)
    result = runner.invoke(
        main, ["ci", str(proj), "--diff", str(diff), "--fail-on", "high"]
    )
    assert result.exit_code == 0
    assert "No quantum-vulnerable" in result.output


def test_all_flag_gates_every_finding(runner, tmp_path):
    proj = _project(tmp_path)
    result = runner.invoke(main, ["ci", str(proj), "--all", "--policy", "strict"])
    assert result.exit_code == 1


def test_json_output_carries_gate_block(runner, tmp_path):
    proj = _project(tmp_path)
    diff = _diff_adding(tmp_path, "vuln.py", 2)
    result = runner.invoke(
        main, ["ci", str(proj), "--diff", str(diff), "--output", "json", "--fail-on", "high"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["gate"]["should_fail"] is True


def test_advisory_when_diff_unavailable_never_fails(runner, tmp_path):
    # tmp_path is not a git repo, so the diff can't be produced. Even with a gate flag
    # the build must not break — the gate degrades to advisory (exit 0).
    proj = _project(tmp_path)
    result = runner.invoke(
        main, ["ci", str(proj), "--base", "does-not-exist", "--policy", "strict"]
    )
    assert result.exit_code == 0


def test_comment_file_written(runner, tmp_path):
    proj = _project(tmp_path)
    diff = _diff_adding(tmp_path, "vuln.py", 2)
    out = tmp_path / "comment.md"
    result = runner.invoke(
        main, ["ci", str(proj), "--diff", str(diff), "--comment-file", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "SeQr PQC Scan Results" in out.read_text(encoding="utf-8")
