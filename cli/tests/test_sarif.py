"""SARIF 2.1.0 shape for GitHub code-scanning upload."""
import os
from dataclasses import dataclass

import pytest
from click.testing import CliRunner

from seqr.cli import main
from seqr.output.sarif import build_sarif


@dataclass
class F:
    pattern_id: str = "py.jwt.rs256"
    file_path: str = "/repo/src/auth.py"
    line_number: int = 42
    code_snippet: str = 'jwt.encode(p, k, algorithm="RS256")'
    algorithm: str = "RSA-SHA256"
    algorithm_family: str = "RSA"
    quantum_status: str = "vulnerable"
    algorithm_risk: int = 9
    confidence: str = "high"
    recommended_replacement: str = "ML-DSA-65"
    estimated_effort_hours: int = 3
    hndl_risk: bool = True


def test_top_level_shape():
    s = build_sarif([F()])
    assert s["version"] == "2.1.0"
    assert s["$schema"].endswith("sarif-2.1.0-rtm.5.json")
    assert len(s["runs"]) == 1
    driver = s["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SeQr PQC Scanner"
    assert driver["rules"]


def test_paths_relativised_to_repo_root():
    s = build_sarif([F(file_path="/repo/src/auth.py")], root="/repo")
    uri = s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/auth.py"  # repo-relative, POSIX


def test_windows_backslashes_normalised():
    s = build_sarif([F(file_path=r"C:\repo\src\auth.py")], root=r"C:\repo")
    uri = s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/auth.py"


def test_security_severity_property_present():
    rule = build_sarif([F(algorithm_risk=9)])["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.0"
    assert rule["helpUri"].startswith("https://")


def test_level_mapping():
    s = build_sarif([F(algorithm_risk=9), F(pattern_id="p.med", algorithm_risk=5)])
    levels = {r["ruleId"]: r["level"] for r in s["runs"][0]["results"]}
    assert levels["py.jwt.rs256"] == "error"
    assert levels["p.med"] == "warning"


def test_region_start_line():
    r = build_sarif([F(line_number=42)])["runs"][0]["results"][0]
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_partial_fingerprint_is_line_independent():
    a = build_sarif([F(line_number=42)], root="/repo")["runs"][0]["results"][0]
    b = build_sarif([F(line_number=200)], root="/repo")["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]


def test_rules_deduplicated():
    s = build_sarif([F(), F(line_number=99)])  # same pattern_id
    assert len(s["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(s["runs"][0]["results"]) == 2


# -- CLI wiring ---------------------------------------------------------------

VULN = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n'


def test_validates_against_official_sarif_schema():
    """Full schema validation — skipped when jsonschema or network is unavailable."""
    jsonschema = pytest.importorskip("jsonschema")
    import json
    import urllib.request

    url = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
           "sarif-2.1/schema/sarif-schema-2.1.0.json")
    try:
        schema = json.loads(urllib.request.urlopen(url, timeout=20).read().decode())
    except Exception:  # offline CI — the online uploader is the real validator
        pytest.skip("SARIF schema unreachable (offline)")
    doc = build_sarif([F(), F(pattern_id="p2", algorithm_risk=5, line_number=7)], root="/repo")
    jsonschema.validate(doc, schema)


def test_ci_sarif_file_written(tmp_path):
    (tmp_path / "vuln.py").write_text(VULN, encoding="utf-8")
    out = tmp_path / "out.sarif"
    r = CliRunner().invoke(
        main, ["ci", str(tmp_path), "--all", "--sarif-file", str(out)]
    )
    assert r.exit_code == 0
    import json
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    # path relativised to the scanned root
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "vuln.py"
