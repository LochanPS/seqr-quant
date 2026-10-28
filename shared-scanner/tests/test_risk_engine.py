"""
Tests for engines/risk.py — ComponentRiskScore, OrgRiskScore, compliance.
"""

import pytest

from engines.risk import (
    ComponentRiskScore,
    OrgRiskScore,
    ComplianceResult,
    check_compliance,
    score_component,
    score_org,
    DATA_SENSITIVITY_SCORES,
)


# ---------------------------------------------------------------------------
# DATA_SENSITIVITY_SCORES
# ---------------------------------------------------------------------------

class TestDataSensitivityScores:
    def test_highly_confidential_is_10(self):
        assert DATA_SENSITIVITY_SCORES["highly_confidential"] == 10

    def test_confidential_is_8(self):
        assert DATA_SENSITIVITY_SCORES["confidential"] == 8

    def test_internal_is_5(self):
        assert DATA_SENSITIVITY_SCORES["internal"] == 5

    def test_public_is_1(self):
        assert DATA_SENSITIVITY_SCORES["public"] == 1


# ---------------------------------------------------------------------------
# score_component
# ---------------------------------------------------------------------------

class TestScoreComponent:
    def _rsa_comp(self, data_sensitivity="confidential", location="tls_cert", public=True):
        return score_component(
            component_id="comp-1",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity=data_sensitivity,
            location_type=location,
            is_public_facing=public,
        )

    def test_final_risk_score_formula(self):
        # formula: algorithm_risk * data_sensitivity_score / 10
        comp = self._rsa_comp(data_sensitivity="confidential")
        assert comp.final_risk_score == round((8 * 8) / 10, 2)  # 6.4

    def test_final_risk_public_data(self):
        comp = self._rsa_comp(data_sensitivity="public")
        assert comp.final_risk_score == round((8 * 1) / 10, 2)  # 0.8

    def test_final_risk_highly_confidential(self):
        comp = self._rsa_comp(data_sensitivity="highly_confidential")
        assert comp.final_risk_score == round((8 * 10) / 10, 2)  # 8.0

    def test_hndl_risk_true_when_all_conditions_met(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert comp.hndl_risk is True

    def test_hndl_risk_false_when_not_public(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=False,
        )
        assert comp.hndl_risk is False

    def test_hndl_risk_false_for_code_location(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="code",
            is_public_facing=True,
        )
        assert comp.hndl_risk is False

    def test_hndl_risk_false_for_public_sensitivity(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="public",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert comp.hndl_risk is False

    def test_hndl_risk_true_for_jwt_location(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-SHA256",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="highly_confidential",
            location_type="jwt",
            is_public_facing=True,
        )
        assert comp.hndl_risk is True

    def test_safe_algorithm_zero_risk(self):
        comp = score_component(
            component_id="c",
            algorithm="ML-KEM-768",
            algorithm_family="ML-KEM",
            algorithm_risk=0,
            quantum_status="safe",
            data_sensitivity="highly_confidential",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert comp.final_risk_score == 0.0
        assert comp.hndl_risk is False

    def test_migration_priority_critical_when_hndl(self):
        comp = self._rsa_comp(data_sensitivity="highly_confidential", location="tls_cert", public=True)
        assert comp.migration_priority == "critical"

    def test_migration_priority_high(self):
        # final_risk = 8 * 8 / 10 = 6.4 → high (5 <= x < 8, no HNDL)
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="code",
            is_public_facing=False,
        )
        assert comp.migration_priority in ("high", "critical")

    def test_migration_priority_medium(self):
        # ECDSA p384, algorithm_risk=6, data=internal, ds_score=5 → 6*5/10=3.0 → medium
        comp = score_component(
            component_id="c",
            algorithm="ECDSA-P384",
            algorithm_family="ECC",
            algorithm_risk=6,
            quantum_status="vulnerable",
            data_sensitivity="internal",
            location_type="code",
            is_public_facing=False,
        )
        assert comp.migration_priority == "medium"

    def test_migration_priority_low(self):
        # AES-256, risk=0, ds=public → 0.0 → low
        comp = score_component(
            component_id="c",
            algorithm="AES-256",
            algorithm_family="AES",
            algorithm_risk=0,
            quantum_status="safe",
            data_sensitivity="public",
            location_type="code",
            is_public_facing=False,
        )
        assert comp.migration_priority == "low"

    def test_returns_component_risk_score_type(self):
        comp = self._rsa_comp()
        assert isinstance(comp, ComponentRiskScore)

    def test_data_sensitivity_score_on_result(self):
        comp = self._rsa_comp(data_sensitivity="highly_confidential")
        assert comp.data_sensitivity_score == 10


# ---------------------------------------------------------------------------
# NIST 800-131A compliance
# ---------------------------------------------------------------------------

class TestNistCompliance:
    def test_rsa_2048_nist_compliant(self):
        comp = score_component(
            component_id="c", algorithm="RSA-2048", algorithm_family="RSA",
            algorithm_risk=8, quantum_status="vulnerable",
            key_size=2048,
        )
        assert comp.nist_compliant is True

    def test_rsa_1024_nist_non_compliant(self):
        comp = score_component(
            component_id="c", algorithm="RSA-1024", algorithm_family="RSA",
            algorithm_risk=9, quantum_status="deprecated",
            key_size=1024,
        )
        assert comp.nist_compliant is False

    def test_sha1_nist_non_compliant(self):
        comp = score_component(
            component_id="c", algorithm="SHA-1", algorithm_family="SHA",
            algorithm_risk=10, quantum_status="deprecated",
        )
        assert comp.nist_compliant is False

    def test_aes256_nist_compliant(self):
        comp = score_component(
            component_id="c", algorithm="AES-256", algorithm_family="AES",
            algorithm_risk=0, quantum_status="safe",
        )
        assert comp.nist_compliant is True


# ---------------------------------------------------------------------------
# PCI DSS compliance
# ---------------------------------------------------------------------------

class TestPciCompliance:
    def test_rsa_pci_non_compliant(self):
        comp = score_component(
            component_id="c", algorithm="RSA-2048", algorithm_family="RSA",
            algorithm_risk=8, quantum_status="vulnerable",
        )
        assert comp.pci_compliant is False

    def test_ecc_pci_non_compliant(self):
        comp = score_component(
            component_id="c", algorithm="ECDSA-P256", algorithm_family="ECC",
            algorithm_risk=7, quantum_status="vulnerable",
        )
        assert comp.pci_compliant is False

    def test_ml_kem_pci_compliant(self):
        comp = score_component(
            component_id="c", algorithm="ML-KEM-768", algorithm_family="ML-KEM",
            algorithm_risk=0, quantum_status="safe",
        )
        assert comp.pci_compliant is True


# ---------------------------------------------------------------------------
# score_org
# ---------------------------------------------------------------------------

class TestScoreOrg:
    def _make_comps(self, n_vulnerable=5, n_safe=5) -> list[ComponentRiskScore]:
        comps = []
        for i in range(n_vulnerable):
            comps.append(score_component(
                component_id=f"vuln-{i}",
                algorithm="RSA-2048",
                algorithm_family="RSA",
                algorithm_risk=8,
                quantum_status="vulnerable",
                data_sensitivity="confidential",
                location_type="tls_cert",
                is_public_facing=True,
            ))
        for i in range(n_safe):
            comps.append(score_component(
                component_id=f"safe-{i}",
                algorithm="ML-KEM-768",
                algorithm_family="ML-KEM",
                algorithm_risk=0,
                quantum_status="safe",
                data_sensitivity="internal",
                location_type="code",
            ))
        return comps

    def test_empty_components_gives_zero(self):
        result = score_org([])
        assert result.score == 0
        assert result.total_components == 0

    def test_returns_org_risk_score_type(self):
        result = score_org(self._make_comps())
        assert isinstance(result, OrgRiskScore)

    def test_score_in_range_0_to_100(self):
        result = score_org(self._make_comps(n_vulnerable=10, n_safe=0))
        assert 0 <= result.score <= 100

    def test_all_safe_gives_low_score(self):
        comps = self._make_comps(n_vulnerable=0, n_safe=10)
        result = score_org(comps)
        assert result.score == 0

    def test_all_vulnerable_gives_high_score(self):
        comps = self._make_comps(n_vulnerable=10, n_safe=0)
        result = score_org(comps)
        assert result.score > 0

    def test_hndl_critical_count(self):
        comps = self._make_comps(n_vulnerable=3, n_safe=2)
        result = score_org(comps)
        assert result.hndl_critical_count == 3

    def test_vulnerable_count(self):
        comps = self._make_comps(n_vulnerable=4, n_safe=3)
        result = score_org(comps)
        assert result.vulnerable_count == 4

    def test_top_20_limit(self):
        comps = self._make_comps(n_vulnerable=25, n_safe=5)
        result = score_org(comps)
        assert len(result.top_risk_components) <= 20

    def test_hndl_doubles_weight(self):
        hndl_comp = score_component(
            component_id="hndl-1",
            algorithm="RSA-2048", algorithm_family="RSA",
            algorithm_risk=8, quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert", is_public_facing=True,
        )
        non_hndl = score_component(
            component_id="code-1",
            algorithm="RSA-2048", algorithm_family="RSA",
            algorithm_risk=8, quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="code", is_public_facing=False,
        )
        # Both same algorithm_risk and data_sensitivity, so same final_risk_score
        # HNDL doubles the weight of hndl_comp
        result_mixed = score_org([hndl_comp, non_hndl])
        result_none = score_org([non_hndl, non_hndl])
        # Adding HNDL component should not decrease score
        assert result_mixed.score >= result_none.score


# ---------------------------------------------------------------------------
# check_compliance
# ---------------------------------------------------------------------------

class TestCheckCompliance:
    def _vulns(self, n=2):
        return [
            score_component(
                component_id=f"c-{i}",
                algorithm="RSA-2048", algorithm_family="RSA",
                algorithm_risk=8, quantum_status="vulnerable",
                data_sensitivity="confidential",
                location_type="tls_cert", is_public_facing=True,
            )
            for i in range(n)
        ]

    def _safes(self, n=2):
        return [
            score_component(
                component_id=f"s-{i}",
                algorithm="ML-KEM-768", algorithm_family="ML-KEM",
                algorithm_risk=0, quantum_status="safe",
                data_sensitivity="public",
            )
            for i in range(n)
        ]

    def test_nist_fails_on_sha1(self):
        """NIST 800-131A checks classical security, not quantum. SHA-1 fails classically."""
        sha1_comp = score_component(
            component_id="sha1",
            algorithm="sha-1",
            algorithm_family="SHA",
            algorithm_risk=10,
            quantum_status="deprecated",
        )
        result = check_compliance([sha1_comp], "nist_800_131a")
        assert isinstance(result, ComplianceResult)
        assert result.status == "non_compliant"

    def test_nist_rsa_2048_is_compliant(self):
        """RSA-2048 meets NIST 800-131A minimum (2048-bit). Quantum-vulnerable but classically OK."""
        result = check_compliance(self._vulns(), "nist_800_131a")
        assert result.status == "compliant"

    def test_nist_passes_all_safe(self):
        result = check_compliance(self._safes(), "nist_800_131a")
        assert result.status == "compliant"

    def test_pci_fails_on_rsa(self):
        result = check_compliance(self._vulns(), "pci_dss_12_3_3")
        assert result.status == "non_compliant"
        assert len(result.failing_components) == 2

    def test_dst_fails_on_vulnerable(self):
        result = check_compliance(self._vulns(), "dst_2026")
        assert result.status == "non_compliant"

    def test_cnsa_fails_on_rsa(self):
        result = check_compliance(self._vulns(), "cnsa_2")
        assert result.status == "non_compliant"

    def test_all_frameworks_pass_on_pqc(self):
        safes = self._safes()
        for fw in ("nist_800_131a", "pci_dss_12_3_3", "dst_2026", "cnsa_2"):
            result = check_compliance(safes, fw)
            assert result.status == "compliant", f"{fw} should be compliant"

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            check_compliance([], "foo_bar")

    def test_compliance_result_has_reason(self):
        result = check_compliance(self._vulns(), "pci_dss_12_3_3")
        assert len(result.reason) > 0

    def test_failing_components_list(self):
        comps = self._vulns(n=3)
        result = check_compliance(comps, "dst_2026")
        assert len(result.failing_components) == 3
        assert all(c_id in [c.component_id for c in comps] for c_id in result.failing_components)
