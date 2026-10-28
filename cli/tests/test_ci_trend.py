"""Tests for the scheduled trend + fail-budget mode (`seqr ci --snapshot`)."""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass

import pytest
from click.testing import CliRunner

import seqr.cli as cli_mod
from seqr.ci import (
    budget_decision,
    build_snapshot,
    build_trend_json,
    build_trend_markdown,
    diff_snapshots,
    load_snapshots,
    prior_snapshot,
    save_snapshot,
)
from seqr.ci.policy import CryptoPolicy


@dataclass
class FakeFinding:
    file_path: str
    line_number: int
    algorithm: str
    algorithm_family: str
    pattern_id: str = "p1"
    code_snippet: str = ""
    algorithm_risk: int = 8


def _day(y, m, d) -> _dt.datetime:
    return _dt.datetime(y, m, d, 12, 0, tzinfo=_dt.timezone.utc)


# The default policy forbids quantum-vulnerable families (RSA/ECC/…).
RSA = lambda p="a.py", ln=1, alg="RSA-2048": FakeFinding(p, ln, alg, "RSA")
MLKEM = lambda p="b.py", ln=1: FakeFinding(p, ln, "ML-KEM-768", "ML-KEM")


# -- build_snapshot --------------------------------------------------------------

def test_snapshot_records_only_drift():
    policy = CryptoPolicy.default()
    snap = build_snapshot([RSA(), MLKEM()], policy, now=_day(2026, 8, 1))
    assert snap["totals"]["scanned"] == 2
    assert snap["totals"]["drift"] == 1          # only the RSA finding drifts
    assert snap["drift"][0]["algorithm"] == "RSA-2048"
    assert snap["date"] == "2026-08-01"


def test_snapshot_dedupes_fingerprints():
    policy = CryptoPolicy.default()
    # Same file/pattern/algorithm/snippet on two lines → one fingerprint.
    snap = build_snapshot([RSA(ln=1), RSA(ln=9)], policy, now=_day(2026, 8, 1))
    assert snap["totals"]["drift"] == 1


def test_snapshot_severity_counts():
    policy = CryptoPolicy.default()
    hi = FakeFinding("x.py", 1, "RSA-2048", "RSA", pattern_id="hi", algorithm_risk=9)
    md = FakeFinding("y.py", 1, "RSA-1024", "RSA", pattern_id="md", algorithm_risk=5)
    snap = build_snapshot([hi, md], policy, now=_day(2026, 8, 1))
    by = snap["totals"]["by_severity"]
    assert by["critical"] == 1 and by["medium"] == 1


# -- persistence -----------------------------------------------------------------

def test_save_load_roundtrip(tmp_path):
    policy = CryptoPolicy.default()
    snap = build_snapshot([RSA()], policy, now=_day(2026, 8, 1))
    path = save_snapshot(tmp_path, snap)
    assert path.name == "2026-08-01.json"
    loaded = load_snapshots(tmp_path)
    assert len(loaded) == 1 and loaded[0]["date"] == "2026-08-01"


def test_load_skips_garbage(tmp_path):
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "notasnap.json").write_text('{"hello": 1}', encoding="utf-8")
    assert load_snapshots(tmp_path) == []


def test_prior_snapshot_ignores_same_day(tmp_path):
    policy = CryptoPolicy.default()
    older = build_snapshot([RSA()], policy, now=_day(2026, 8, 1))
    today = build_snapshot([RSA()], policy, now=_day(2026, 8, 8))
    save_snapshot(tmp_path, older)
    save_snapshot(tmp_path, today)
    history = load_snapshots(tmp_path)
    # prior for today's snapshot is the 08-01 one, never itself.
    assert prior_snapshot(history, today)["date"] == "2026-08-01"
    # a first snapshot has no prior.
    assert prior_snapshot([older], older) is None


# -- diff ------------------------------------------------------------------------

def test_diff_new_resolved_unchanged():
    policy = CryptoPolicy.default()
    prior = build_snapshot(
        [RSA("keep.py"), RSA("gone.py")], policy, now=_day(2026, 8, 1)
    )
    current = build_snapshot(
        [RSA("keep.py"), RSA("added.py")], policy, now=_day(2026, 8, 8)
    )
    d = diff_snapshots(prior, current)
    assert {r["file"] for r in d.new} == {"added.py"}
    assert {r["file"] for r in d.resolved} == {"gone.py"}
    assert d.unchanged == 1
    assert d.net == 0    # +1 new, -1 resolved


def test_diff_no_prior_is_all_new():
    policy = CryptoPolicy.default()
    current = build_snapshot([RSA("a.py"), RSA("b.py")], policy, now=_day(2026, 8, 8))
    d = diff_snapshots(None, current)
    assert len(d.new) == 2 and not d.resolved and d.net == 2


# -- fail-budget -----------------------------------------------------------------

@pytest.mark.parametrize("new,budget,fail", [
    (0, None, False),   # advisory
    (5, None, False),   # advisory ignores count
    (0, 0, False),      # exactly on a zero budget
    (1, 0, True),       # any regression over a zero budget
    (2, 2, False),      # at budget
    (3, 2, True),       # over budget
])
def test_budget_decision(new, budget, fail):
    assert budget_decision(new, budget).should_fail is fail


# -- reports ---------------------------------------------------------------------

def test_markdown_report_shape():
    policy = CryptoPolicy.default()
    prior = build_snapshot([RSA("gone.py")], policy, now=_day(2026, 8, 1))
    current = build_snapshot([RSA("added.py")], policy, now=_day(2026, 8, 8))
    d = diff_snapshots(prior, current)
    dec = budget_decision(len(d.new), 0)
    md = build_trend_markdown(current, prior, d, dec)
    assert "SeQr PQC Drift Trend" in md
    assert "New drift" in md and "added.py" in md
    assert "Resolved" in md and "gone.py" in md
    assert "Over budget" in md                 # 1 new > budget 0
    assert "harvest" in md.lower() or "HNDL" in md  # HNDL disclaimer present
    assert "CNSA" not in md                     # output-language rule


def test_json_report_shape():
    policy = CryptoPolicy.default()
    current = build_snapshot([RSA()], policy, now=_day(2026, 8, 8))
    d = diff_snapshots(None, current)
    dec = budget_decision(len(d.new), None)
    body = build_trend_json(current, None, d, dec)
    assert body["prior_date"] is None
    assert body["trend"]["net"] == 1
    assert body["budget"]["should_fail"] is False


# -- CLI integration -------------------------------------------------------------

def _write_vuln(tmp_path):
    (tmp_path / "vuln.py").write_text(
        'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n',
        encoding="utf-8",
    )


def test_cli_snapshot_advisory_exit0(tmp_path):
    _write_vuln(tmp_path)
    snap_dir = tmp_path / "snaps"
    res = CliRunner().invoke(
        cli_mod.main,
        ["ci", str(tmp_path), "--snapshot", "--snapshot-dir", str(snap_dir)],
    )
    assert res.exit_code == 0
    assert "Drift Trend" in res.output
    # a dated snapshot file was written
    assert list(snap_dir.glob("*.json"))


def test_cli_snapshot_fail_budget_trips(tmp_path):
    _write_vuln(tmp_path)
    snap_dir = tmp_path / "snaps"
    # First run: no prior → the RS256 drift is "new"; budget 0 → over budget → exit 1.
    res = CliRunner().invoke(
        cli_mod.main,
        ["ci", str(tmp_path), "--snapshot", "--snapshot-dir", str(snap_dir),
         "--fail-budget", "0"],
    )
    assert res.exit_code == 1
    assert "Over budget" in res.output


def test_cli_snapshot_json_output(tmp_path):
    _write_vuln(tmp_path)
    snap_dir = tmp_path / "snaps"
    res = CliRunner().invoke(
        cli_mod.main,
        ["--quiet", "ci", str(tmp_path), "--snapshot", "--snapshot-dir", str(snap_dir),
         "--output", "json"],
    )
    assert res.exit_code == 0
    body = json.loads(res.output)
    assert body["snapshot"]["totals"]["drift"] >= 1
    assert "trend" in body and "budget" in body
