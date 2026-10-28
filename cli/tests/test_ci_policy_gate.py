"""End-to-end `seqr ci` policy-aware gating: drift, baseline, suppressions, config."""
import json

import pytest
from click.testing import CliRunner

from seqr.cli import main

VULN = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n'


@pytest.fixture
def runner():
    return CliRunner()


def _project(tmp_path):
    (tmp_path / "vuln.py").write_text(VULN, encoding="utf-8")
    return tmp_path


# -- policy-drift gating ------------------------------------------------------

def test_fail_on_drift_fails_on_new_vulnerable_crypto(runner, tmp_path):
    proj = _project(tmp_path)
    r = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on-drift"])
    assert r.exit_code == 1
    assert "drift" in r.output.lower()


def test_no_gate_flags_stays_advisory(runner, tmp_path):
    proj = _project(tmp_path)
    r = runner.invoke(main, ["ci", str(proj), "--all"])
    assert r.exit_code == 0


def test_custom_policy_tolerates_family(runner, tmp_path):
    # A policy that forbids only ECC leaves the RSA/JWT finding as non-drift.
    proj = _project(tmp_path)
    (tmp_path / "seqr-policy.json").write_text(
        json.dumps({"name": "ecc-only", "rules": [
            {"key": "no_ecc", "type": "family_not_in", "forbidden": ["ECC"],
             "severity": "urgent", "target": "ML-KEM"}]}),
        encoding="utf-8",
    )
    r = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on-drift"])
    assert r.exit_code == 0  # RSA finding does not drift under this policy


# -- baseline -----------------------------------------------------------------

def test_baseline_accepts_existing_so_drift_passes(runner, tmp_path):
    proj = _project(tmp_path)
    # Record the current finding as accepted.
    r0 = runner.invoke(main, ["ci", str(proj), "--update-baseline"])
    assert r0.exit_code == 0
    assert (tmp_path / "seqr-baseline.json").exists()
    # Now the same finding is baselined → drift gate no longer trips.
    r1 = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on-drift"])
    assert r1.exit_code == 0
    assert "accepted via baseline" in r1.output


def test_new_finding_after_baseline_still_fails(runner, tmp_path):
    proj = _project(tmp_path)
    runner.invoke(main, ["ci", str(proj), "--update-baseline"])
    # Add a *different* vulnerable file — not in the baseline.
    (tmp_path / "more.py").write_text(
        'from cryptography.hazmat.primitives.asymmetric import rsa\n'
        'k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n',
        encoding="utf-8",
    )
    r = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on-drift"])
    assert r.exit_code == 1


def test_no_baseline_flag_ignores_baseline(runner, tmp_path):
    proj = _project(tmp_path)
    runner.invoke(main, ["ci", str(proj), "--update-baseline"])
    r = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on-drift", "--no-baseline"])
    assert r.exit_code == 1  # baseline ignored → finding is "new" again


# -- inline suppression -------------------------------------------------------

def test_inline_ignore_suppresses_finding(runner, tmp_path):
    (tmp_path / "vuln.py").write_text(
        'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")  # seqr:ignore[legacy]\n',
        encoding="utf-8",
    )
    r = runner.invoke(main, ["ci", str(tmp_path), "--all", "--fail-on-drift"])
    assert r.exit_code == 0
    assert "suppressed inline" in r.output


# -- .seqrignore --------------------------------------------------------------

def test_seqrignore_excludes_path(runner, tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "old.py").write_text(VULN, encoding="utf-8")
    (tmp_path / ".seqrignore").write_text("vendor/\n", encoding="utf-8")
    r = runner.invoke(main, ["ci", str(tmp_path), "--all", "--fail-on-drift"])
    assert r.exit_code == 0


# -- seqr-ci.yml config -------------------------------------------------------

def test_config_supplies_fail_on_drift_default(runner, tmp_path):
    proj = _project(tmp_path)
    (tmp_path / "seqr-ci.yml").write_text("fail_on_drift: true\n", encoding="utf-8")
    r = runner.invoke(main, ["ci", str(proj), "--all"])
    assert r.exit_code == 1  # config armed the drift gate without a CLI flag


def test_cli_flag_overrides_config(runner, tmp_path):
    proj = _project(tmp_path)
    (tmp_path / "seqr-ci.yml").write_text("fail_on_drift: true\n", encoding="utf-8")
    r = runner.invoke(main, ["ci", str(proj), "--all", "--no-fail-on-drift"])
    assert r.exit_code == 0  # explicit flag beats config


# -- json output carries policy metadata --------------------------------------

def test_json_output_has_policy_block(runner, tmp_path):
    proj = _project(tmp_path)
    r = runner.invoke(main, ["ci", str(proj), "--all", "--output", "json"])
    payload = json.loads(r.output)
    assert "drift_count" in payload["gate"]
    assert payload["gate"]["drift_count"] >= 1
    assert "policy" in payload["gate"]


# -- severity path still intact -----------------------------------------------

def test_existing_fail_on_still_works(runner, tmp_path):
    proj = _project(tmp_path)
    r = runner.invoke(main, ["ci", str(proj), "--all", "--fail-on", "high"])
    assert r.exit_code == 1
