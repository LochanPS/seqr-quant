"""
Tests for engines/cbom.py — CBOMEngine, CryptoComponent, CBOMSummary.
"""

import json
import io
import csv

import pytest

from engines.cbom import CBOMEngine, CryptoComponent, CBOMSummary
from engines.risk import score_component


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

def _make_network_result(
    domain="example.com",
    port=443,
    reachable=True,
    tls_version="TLS_1_2",
    algorithm="RSA",
    key_size=2048,
    kex_algorithm="ECDHE",
):
    """Build a minimal DomainScanResult-like object for CBOM testing."""
    from unittest.mock import MagicMock
    from engines.classifier import AlgorithmClassification

    result = MagicMock()
    result.domain = domain
    result.port = port
    result.reachable = reachable
    result.tls_version = tls_version
    result.key_exchange_algorithm = kex_algorithm

    # TLS classification
    tls_cls = AlgorithmClassification("vulnerable", 4, "TLS", False, "TLS 1.2")
    result.classifications = [tls_cls]

    # Certificate
    cert = MagicMock()
    cert.algorithm = algorithm
    cert.key_size = key_size
    from datetime import date
    cert.expiry_date = date(2025, 12, 31)
    cert.issuer = "CN=Let's Encrypt R3"
    cert.subject = f"CN={domain}"
    cert.serial = 123456789
    cert.san = [domain, f"www.{domain}"]
    cert.is_expired = False
    cert.days_until_expiry = 180
    result.cert = cert

    return result


def _make_code_finding(
    pattern_id="PY-RSA-001",
    file_path="src/auth/jwt.py",
    line_number=42,
    algorithm="RSA",
    family="RSA",
    risk=8,
    quantum_status="vulnerable",
    confidence="high",
    hndl=True,
):
    from scanner.code import CodeFinding
    return CodeFinding(
        pattern_id=pattern_id,
        file_path=file_path,
        line_number=line_number,
        code_snippet="key = rsa.generate_private_key(65537, 2048)",
        algorithm=algorithm,
        algorithm_family=family,
        quantum_status=quantum_status,
        algorithm_risk=risk,
        confidence=confidence,
        recommended_replacement="ML-DSA-65 (FIPS 204)",
        estimated_effort_hours=8,
        hndl_risk=hndl,
        library_name="cryptography.hazmat.primitives.asymmetric.rsa",
    )


# ---------------------------------------------------------------------------
# CBOMEngine.aggregate
# ---------------------------------------------------------------------------

class TestAggregate:
    def test_empty_input_returns_empty_list(self):
        engine = CBOMEngine()
        assert engine.aggregate() == []

    def test_network_result_produces_components(self):
        engine = CBOMEngine()
        result = _make_network_result()
        components = engine.aggregate(network_results=[result])
        assert len(components) > 0

    def test_network_result_has_correct_location_type(self):
        engine = CBOMEngine()
        result = _make_network_result()
        components = engine.aggregate(network_results=[result])
        location_types = {c.location_type for c in components}
        assert "tls_cert" in location_types

    def test_unreachable_host_skipped(self):
        engine = CBOMEngine()
        result = _make_network_result(reachable=False)
        components = engine.aggregate(network_results=[result])
        assert components == []

    def test_code_finding_produces_code_component(self):
        engine = CBOMEngine()
        finding = _make_code_finding()
        components = engine.aggregate(code_findings=[finding])
        assert len(components) == 1
        assert components[0].location_type == "code"

    def test_code_component_preserves_file_path(self):
        engine = CBOMEngine()
        finding = _make_code_finding(file_path="src/crypto/keys.py", line_number=17)
        components = engine.aggregate(code_findings=[finding])
        assert components[0].location_file == "src/crypto/keys.py"
        assert components[0].location_line == 17

    def test_code_component_location_detail_format(self):
        engine = CBOMEngine()
        finding = _make_code_finding(file_path="auth.py", line_number=5)
        components = engine.aggregate(code_findings=[finding])
        assert "auth.py:5" in components[0].location_detail

    def test_mixed_network_and_code_findings(self):
        engine = CBOMEngine()
        net = _make_network_result()
        code = _make_code_finding()
        components = engine.aggregate(network_results=[net], code_findings=[code])
        types = {c.location_type for c in components}
        assert "tls_cert" in types
        assert "code" in types

    def test_deduplication_same_location_same_algo(self):
        engine = CBOMEngine()
        f1 = _make_code_finding(file_path="auth.py", line_number=10, algorithm="RSA")
        f2 = _make_code_finding(file_path="auth.py", line_number=10, algorithm="RSA")
        components = engine.aggregate(code_findings=[f1, f2])
        # Should deduplicate to 1
        assert len(components) == 1

    def test_data_sensitivity_propagated(self):
        engine = CBOMEngine()
        finding = _make_code_finding()
        components = engine.aggregate(code_findings=[finding], org_data_sensitivity="highly_confidential")
        assert components[0].data_sensitivity == "highly_confidential"

    def test_components_have_uuids(self):
        import re
        uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        engine = CBOMEngine()
        finding = _make_code_finding()
        components = engine.aggregate(code_findings=[finding])
        assert uuid_re.match(components[0].id)

    def test_final_risk_score_computed(self):
        engine = CBOMEngine()
        finding = _make_code_finding(risk=8)
        components = engine.aggregate(code_findings=[finding], org_data_sensitivity="confidential")
        # algorithm_risk=8, ds_score=8 → 8*8/10 = 6.4
        assert components[0].final_risk_score == pytest.approx(6.4, abs=0.1)

    def test_migration_priority_set(self):
        engine = CBOMEngine()
        finding = _make_code_finding(risk=8)
        components = engine.aggregate(code_findings=[finding], org_data_sensitivity="highly_confidential")
        assert components[0].migration_priority in ("critical", "high", "medium", "low")

    def test_recommended_algorithm_populated(self):
        engine = CBOMEngine()
        finding = _make_code_finding(algorithm="RSA")
        components = engine.aggregate(code_findings=[finding])
        assert len(components[0].recommended_algorithm) > 0


# ---------------------------------------------------------------------------
# CBOMEngine.summarise
# ---------------------------------------------------------------------------

class TestSummarise:
    def _components(self, n_vuln=3, n_safe=2):
        engine = CBOMEngine()
        findings = [
            _make_code_finding(
                pattern_id=f"PY-RSA-{i}",
                file_path=f"file{i}.py",
                line_number=i + 1,
            )
            for i in range(n_vuln)
        ]
        safe_findings = [
            _make_code_finding(
                pattern_id=f"PQC-{i}",
                file_path=f"safe{i}.py",
                line_number=1,
                algorithm="ML-KEM-768",
                family="ML-KEM",
                risk=0,
                quantum_status="safe",
                hndl=False,
            )
            for i in range(n_safe)
        ]
        return engine.aggregate(code_findings=findings + safe_findings)

    def test_returns_cbom_summary(self):
        engine = CBOMEngine()
        comps = self._components()
        summary = engine.summarise(comps)
        assert isinstance(summary, CBOMSummary)

    def test_total_components_count(self):
        engine = CBOMEngine()
        comps = self._components(n_vuln=3, n_safe=2)
        summary = engine.summarise(comps)
        assert summary.total_components == len(comps)

    def test_vulnerable_count(self):
        engine = CBOMEngine()
        comps = self._components(n_vuln=3, n_safe=2)
        summary = engine.summarise(comps)
        assert summary.vulnerable_count == 3

    def test_safe_count(self):
        engine = CBOMEngine()
        comps = self._components(n_vuln=0, n_safe=4)
        summary = engine.summarise(comps)
        assert summary.safe_count == 4

    def test_org_risk_score_in_range(self):
        engine = CBOMEngine()
        comps = self._components()
        summary = engine.summarise(comps)
        assert 0 <= summary.org_risk_score <= 100

    def test_by_algorithm_family_populated(self):
        engine = CBOMEngine()
        comps = self._components(n_vuln=2, n_safe=1)
        summary = engine.summarise(comps)
        assert "RSA" in summary.by_algorithm_family

    def test_by_quantum_status_populated(self):
        engine = CBOMEngine()
        comps = self._components(n_vuln=2, n_safe=1)
        summary = engine.summarise(comps)
        assert "vulnerable" in summary.by_quantum_status

    def test_compliance_frameworks_present(self):
        engine = CBOMEngine()
        comps = self._components()
        summary = engine.summarise(comps)
        assert "nist_800_131a" in summary.compliance
        assert "pci_dss_12_3_3" in summary.compliance
        assert "dst_2026" in summary.compliance

    def test_empty_components_summarise(self):
        engine = CBOMEngine()
        summary = engine.summarise([])
        assert summary.total_components == 0
        assert summary.org_risk_score == 0


# ---------------------------------------------------------------------------
# CBOMEngine.export_json
# ---------------------------------------------------------------------------

class TestExportJson:
    def _comps(self):
        engine = CBOMEngine()
        return engine.aggregate(code_findings=[_make_code_finding()])

    def test_returns_valid_json(self):
        engine = CBOMEngine()
        comps = self._comps()
        output = engine.export_json(comps)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_json_has_components_key(self):
        engine = CBOMEngine()
        output = engine.export_json(self._comps())
        data = json.loads(output)
        assert "components" in data

    def test_json_component_count_matches(self):
        engine = CBOMEngine()
        comps = self._comps()
        output = engine.export_json(comps)
        data = json.loads(output)
        assert data["component_count"] == len(comps)

    def test_json_schema_version_present(self):
        engine = CBOMEngine()
        output = engine.export_json(self._comps())
        data = json.loads(output)
        assert "schema_version" in data

    def test_json_empty_components(self):
        engine = CBOMEngine()
        output = engine.export_json([])
        data = json.loads(output)
        assert data["component_count"] == 0
        assert data["components"] == []


# ---------------------------------------------------------------------------
# CBOMEngine.export_csv
# ---------------------------------------------------------------------------

class TestExportCsv:
    def test_returns_csv_string(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_csv(comps)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_csv_has_header(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_csv(comps)
        reader = csv.DictReader(io.StringIO(output))
        assert "algorithm" in reader.fieldnames
        assert "final_risk_score" in reader.fieldnames

    def test_csv_row_count(self):
        engine = CBOMEngine()
        findings = [_make_code_finding(file_path=f"f{i}.py", line_number=i + 1) for i in range(3)]
        comps = engine.aggregate(code_findings=findings)
        output = engine.export_csv(comps)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == len(comps)

    def test_csv_empty_returns_empty_string(self):
        engine = CBOMEngine()
        assert engine.export_csv([]) == ""


# ---------------------------------------------------------------------------
# CBOMEngine.export_cyclonedx
# ---------------------------------------------------------------------------

class TestExportCycloneDX:
    def test_returns_dict(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_cyclonedx(comps)
        assert isinstance(output, dict)

    def test_cyclonedx_bom_format(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_cyclonedx(comps)
        assert output["bomFormat"] == "CycloneDX"
        # 1.6 is the spec version that introduced cryptographic-asset / cryptoProperties.
        assert output["specVersion"] == "1.6"

    def test_cyclonedx_has_components(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_cyclonedx(comps)
        assert "components" in output
        assert len(output["components"]) == len(comps)

    def test_cyclonedx_component_has_crypto_properties(self):
        engine = CBOMEngine()
        comps = engine.aggregate(code_findings=[_make_code_finding()])
        output = engine.export_cyclonedx(comps)
        comp = output["components"][0]
        assert "cryptoProperties" in comp

    def test_cyclonedx_empty(self):
        engine = CBOMEngine()
        output = engine.export_cyclonedx([])
        assert output["components"] == []


# ---------------------------------------------------------------------------
# CryptoComponent dataclass
# ---------------------------------------------------------------------------

class TestCryptoComponent:
    def test_from_code_has_location_line(self):
        engine = CBOMEngine()
        finding = _make_code_finding(line_number=99)
        comps = engine.aggregate(code_findings=[finding])
        assert comps[0].location_line == 99

    def test_from_network_has_no_location_line(self):
        engine = CBOMEngine()
        net = _make_network_result()
        comps = engine.aggregate(network_results=[net])
        for c in comps:
            if c.location_type == "tls_cert":
                assert c.location_line is None
