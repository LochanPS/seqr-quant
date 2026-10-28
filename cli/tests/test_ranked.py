"""`seqr scan code --ranked / --context` — context-aware risk ranking (risk v2)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from seqr.cli import main

SAMPLE = Path(__file__).resolve().parents[2] / "ecdat-demo" / "sample-repo"
pytestmark = pytest.mark.skipif(not SAMPLE.exists(), reason="ecdat-demo sample repo not present")


def _run(*args):
    return CliRunner().invoke(main, ["--no-colour", "scan", "code", str(SAMPLE), *args])


def test_ranked_json_is_sorted_and_explained():
    r = _run("--ranked", "--output", "json")
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    scores = [f["score"] for f in data["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert all(f["factors"] and f["top_reason"] for f in data["findings"])
    assert sum(1 for n in data["summary"]["tiers"].values() if n) >= 2  # not one flat bucket


def test_context_file_moves_ranking(tmp_path):
    ctx = tmp_path / "ctx.json"
    ctx.write_text(json.dumps({"rules": [{"match": "payments/*", "exposure": "internet",
                                          "data_sensitivity": "highly_confidential", "shelf_life": "long"}]}))
    r = _run("--context", str(ctx), "--output", "json")   # --context implies --ranked
    assert r.exit_code == 0, r.output
    top = json.loads(r.output)["findings"][0]
    assert top["rel_path"] == "payments/legacy_dh.py"
    assert top["tier"] == "IMMEDIATE" and top["hndl"] is True
    assert "exposure" not in top["inferred"]


def test_bad_context_file_is_a_clean_usage_error(tmp_path):
    ctx = tmp_path / "bad.json"
    ctx.write_text(json.dumps({"rules": [{"match": "*", "exposur": "internal"}]}))
    r = _run("--context", str(ctx))
    assert r.exit_code == 2
    assert "unknown context keys" in r.output


def test_ranked_terminal_has_disclaimer_when_hndl(tmp_path):
    ctx = tmp_path / "ctx.json"
    ctx.write_text(json.dumps({"rules": [{"match": "payments/*", "exposure": "internet", "shelf_life": "long"}]}))
    r = _run("--context", str(ctx))
    assert r.exit_code == 0, r.output
    assert "IMMEDIATE" in r.output
    assert "not indicators of active data interception" in r.output


def test_default_output_unchanged():
    r = _run("--output", "json")
    assert r.exit_code == 0
    assert "score" not in json.loads(r.output).get("findings", [{}])[0]
