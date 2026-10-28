"""
Tests for the four v1.1 improvements:
  1. Data shelf-life scoring (engines/risk.py)
  2. Hybrid deployment detection (scanner/network.py)
  3. Client-side readiness (scanner/network.py)
  4. Threat timeline categorisation (engines/cbom.py)
"""

import pytest

from engines.risk import (
    DATA_SHELF_LIFE_MULTIPLIERS,
    score_component,
    ComponentRiskScore,
)
from engines.cbom import (
    CBOMEngine,
    CryptoComponent,
    THREAT_TIMELINE_IMMEDIATE,
    THREAT_TIMELINE_URGENT,
    THREAT_TIMELINE_PLANNED,
    THREAT_TIMELINE_ROADMAP,
    _classify_threat_timeline,
)
from scanner.network import (
    DomainScanResult,
    PQC_CLIENT_SUPPORT,
    _detect_hybrid_status,
    _build_client_readiness,
)


# ===========================================================================
# Improvement 1 — Data Shelf-Life Scoring
# ===========================================================================

class TestShelfLifeConstants:
    def test_ephemeral_multiplier(self):
        assert DATA_SHELF_LIFE_MULTIPLIERS["ephemeral"] == pytest.approx(0.2)

    def test_short_multiplier(self):
        assert DATA_SHELF_LIFE_MULTIPLIERS["short"] == pytest.approx(0.5)

    def test_medium_multiplier(self):
        assert DATA_SHELF_LIFE_MULTIPLIERS["medium"] == pytest.approx(1.0)

    def test_long_multiplier(self):
        assert DATA_SHELF_LIFE_MULTIPLIERS["long"] == pytest.approx(1.5)

    def test_permanent_multiplier(self):
        assert DATA_SHELF_LIFE_MULTIPLIERS["permanent"] == pytest.approx(2.0)


class TestShelfLifeScore:
    def test_ephemeral_lowers_score(self):
        ephemeral = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="ephemeral",
        )
        medium = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="medium",
        )
        assert ephemeral.final_risk_score < medium.final_risk_score

    def test_permanent_raises_score(self):
        permanent = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="permanent",
        )
        medium = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="medium",
        )
        assert permanent.final_risk_score > medium.final_risk_score

    def test_score_capped_at_10(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="highly_confidential",  # ds=10
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="permanent",  # multiplier=2.0 → 8*10*2/10=16 → capped at 10
        )
        assert comp.final_risk_score == pytest.approx(10.0)

    def test_ephemeral_formula(self):
        # 8 * 8 * 0.2 / 10 = 1.28
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            data_shelf_life="ephemeral",
        )
        assert comp.final_risk_score == pytest.approx(1.28, abs=0.01)

    def test_long_formula(self):
        # 8 * 8 * 1.5 / 10 = 9.6
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            data_shelf_life="long",
        )
        assert comp.final_risk_score == pytest.approx(9.6, abs=0.01)

    def test_shelf_life_stored_on_result(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_shelf_life="short",
        )
        assert comp.data_shelf_life == "short"

    def test_recommended_next_step_populated(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
        )
        assert isinstance(comp.recommended_next_step, str)
        assert len(comp.recommended_next_step) > 0

    def test_safe_algorithm_next_step(self):
        comp = score_component(
            component_id="c",
            algorithm="ML-KEM-768",
            algorithm_family="ML-KEM",
            algorithm_risk=0,
            quantum_status="safe",
        )
        assert "No action" in comp.recommended_next_step or "safe" in comp.recommended_next_step.lower()


class TestHNDLShelfLife:
    """HNDL risk must be False for ephemeral/short shelf-life data."""

    def test_otp_ephemeral_no_hndl(self):
        # OTP: ephemeral shelf-life — quantum attacker can't use it in time
        comp = score_component(
            component_id="otp",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="jwt",
            is_public_facing=True,
            data_shelf_life="ephemeral",
        )
        assert comp.hndl_risk is False

    def test_short_shelf_no_hndl(self):
        comp = score_component(
            component_id="api-token",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="short",
        )
        assert comp.hndl_risk is False

    def test_health_records_permanent_hndl(self):
        # EHR encrypted with RSA — data must stay private for decades
        comp = score_component(
            component_id="ehr-key",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="highly_confidential",
            location_type="kms_key",
            is_public_facing=True,
            data_shelf_life="permanent",
        )
        assert comp.hndl_risk is True

    def test_medium_shelf_life_keeps_hndl(self):
        comp = score_component(
            component_id="tls-cert",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
            data_shelf_life="medium",
        )
        assert comp.hndl_risk is True

    def test_hndl_recommended_next_step_urgent(self):
        comp = score_component(
            component_id="c",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="highly_confidential",
            location_type="kms_key",
            is_public_facing=True,
            data_shelf_life="permanent",
        )
        assert comp.hndl_risk is True
        assert "HNDL" in comp.recommended_next_step or "Immediate" in comp.recommended_next_step


# ===========================================================================
# Improvement 2 — Hybrid Deployment Detection
# ===========================================================================

class TestDetectHybridStatus:
    def test_no_pqc_ciphers_returns_none(self):
        ciphers = [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_AES_256_GCM_SHA384",
        ]
        assert _detect_hybrid_status(ciphers) == "none"

    def test_x25519kyber_returns_hybrid(self):
        ciphers = [
            "TLS_X25519Kyber768Draft00_AES_256_GCM_SHA384",
            "TLS_AES_256_GCM_SHA384",
        ]
        assert _detect_hybrid_status(ciphers) == "hybrid"

    def test_mlkem_only_returns_full_pqc(self):
        ciphers = ["TLS_MLKEM768_AES_256_GCM_SHA384"]
        assert _detect_hybrid_status(ciphers) == "full_pqc"

    def test_kyber_only_returns_full_pqc(self):
        ciphers = ["TLS_KYBER768_AES_256_GCM_SHA384"]
        assert _detect_hybrid_status(ciphers) == "full_pqc"

    def test_empty_list_returns_none(self):
        assert _detect_hybrid_status([]) == "none"

    def test_domain_scan_result_has_hybrid_status_field(self):
        r = DomainScanResult(domain="example.com", port=443, reachable=True)
        assert hasattr(r, "hybrid_status")
        assert r.hybrid_status == "none"

    def test_domain_scan_result_has_recommended_next_step(self):
        r = DomainScanResult(domain="example.com", port=443, reachable=True)
        assert hasattr(r, "recommended_next_step")

    def test_domain_scan_result_has_client_readiness(self):
        r = DomainScanResult(domain="example.com", port=443, reachable=True)
        assert hasattr(r, "client_readiness")


# ===========================================================================
# Improvement 3 — Client-Side Readiness
# ===========================================================================

class TestPQCClientSupport:
    def test_x25519kyber_entry_exists(self):
        assert "X25519Kyber768" in PQC_CLIENT_SUPPORT

    def test_mlkem_entry_exists(self):
        assert "ML-KEM-768" in PQC_CLIENT_SUPPORT

    def test_x25519kyber_has_chrome_field(self):
        entry = PQC_CLIENT_SUPPORT["X25519Kyber768"]
        assert "chrome" in entry

    def test_x25519kyber_has_market_share(self):
        entry = PQC_CLIENT_SUPPORT["X25519Kyber768"]
        assert "market_share_supported" in entry
        assert 0.0 <= entry["market_share_supported"] <= 1.0


class TestBuildClientReadiness:
    def test_hybrid_returns_x25519kyber_data(self):
        data = _build_client_readiness("hybrid")
        assert data is not None
        assert "chrome" in data

    def test_full_pqc_returns_mlkem_data(self):
        data = _build_client_readiness("full_pqc")
        assert data is not None
        assert "chrome" in data

    def test_none_returns_none(self):
        assert _build_client_readiness("none") is None

    def test_hybrid_market_share_above_zero(self):
        data = _build_client_readiness("hybrid")
        assert data["market_share_supported"] > 0.0

    def test_full_pqc_market_share_is_zero(self):
        data = _build_client_readiness("full_pqc")
        assert data["market_share_supported"] == 0.0


# ===========================================================================
# Improvement 4 — Threat Timeline Categorisation
# ===========================================================================

class TestThreatTimelineConstants:
    def test_immediate_value(self):
        assert THREAT_TIMELINE_IMMEDIATE == "immediate"

    def test_urgent_value(self):
        assert THREAT_TIMELINE_URGENT == "urgent"

    def test_planned_value(self):
        assert THREAT_TIMELINE_PLANNED == "planned"

    def test_roadmap_value(self):
        assert THREAT_TIMELINE_ROADMAP == "roadmap"


class TestClassifyThreatTimeline:
    def test_deprecated_is_immediate(self):
        timeline = _classify_threat_timeline(
            quantum_status="deprecated",
            algorithm_risk=10,
            hndl_risk=False,
            migration_priority="critical",
        )
        assert timeline == "immediate"

    def test_hndl_risk_is_immediate(self):
        timeline = _classify_threat_timeline(
            quantum_status="vulnerable",
            algorithm_risk=8,
            hndl_risk=True,
            migration_priority="critical",
        )
        assert timeline == "immediate"

    def test_high_risk_vulnerable_is_urgent(self):
        timeline = _classify_threat_timeline(
            quantum_status="vulnerable",
            algorithm_risk=8,
            hndl_risk=False,
            migration_priority="high",
        )
        assert timeline == "urgent"

    def test_critical_priority_vulnerable_is_urgent(self):
        timeline = _classify_threat_timeline(
            quantum_status="vulnerable",
            algorithm_risk=6,
            hndl_risk=False,
            migration_priority="critical",
        )
        assert timeline == "urgent"

    def test_medium_risk_vulnerable_is_planned(self):
        timeline = _classify_threat_timeline(
            quantum_status="vulnerable",
            algorithm_risk=4,
            hndl_risk=False,
            migration_priority="medium",
        )
        assert timeline == "planned"

    def test_safe_is_roadmap(self):
        timeline = _classify_threat_timeline(
            quantum_status="safe",
            algorithm_risk=0,
            hndl_risk=False,
            migration_priority="low",
        )
        assert timeline == "roadmap"

    def test_tls10_is_immediate(self):
        # TLS 1.0 is deprecated → immediate
        timeline = _classify_threat_timeline(
            quantum_status="deprecated",
            algorithm_risk=9,
            hndl_risk=False,
            migration_priority="critical",
        )
        assert timeline == "immediate"

    def test_mlkem_is_roadmap(self):
        timeline = _classify_threat_timeline(
            quantum_status="safe",
            algorithm_risk=0,
            hndl_risk=False,
            migration_priority="low",
        )
        assert timeline == "roadmap"


class TestCryptoComponentTimeline:
    def _make_finding(self, algorithm="RSA", family="RSA", risk=8,
                      quantum_status="vulnerable", hndl=True):
        from scanner.code import CodeFinding
        return CodeFinding(
            pattern_id="PY-RSA-001",
            file_path="src/auth.py",
            line_number=10,
            code_snippet="rsa.generate_private_key(65537, 2048)",
            algorithm=algorithm,
            algorithm_family=family,
            quantum_status=quantum_status,
            algorithm_risk=risk,
            confidence="high",
            recommended_replacement="ML-DSA-65 (FIPS 204)",
            estimated_effort_hours=8,
            hndl_risk=hndl,
            library_name="cryptography",
        )

    def test_code_component_has_threat_timeline(self):
        engine = CBOMEngine()
        finding = self._make_finding()
        comps = engine.aggregate(code_findings=[finding])
        assert hasattr(comps[0], "threat_timeline")
        assert comps[0].threat_timeline != ""

    def test_hndl_component_timeline_is_immediate(self):
        engine = CBOMEngine()
        finding = self._make_finding(hndl=True, quantum_status="vulnerable")
        # code location won't trigger HNDL in risk engine but hndl_risk from finding is passed
        # directly in _from_code_finding; timeline uses finding.hndl_risk
        comps = engine.aggregate(code_findings=[finding])
        assert comps[0].threat_timeline == "immediate"

    def test_safe_component_timeline_is_roadmap(self):
        engine = CBOMEngine()
        finding = self._make_finding(
            algorithm="ML-KEM-768",
            family="ML-KEM",
            risk=0,
            quantum_status="safe",
            hndl=False,
        )
        comps = engine.aggregate(code_findings=[finding])
        assert comps[0].threat_timeline == "roadmap"

    def test_vulnerable_high_risk_timeline_is_urgent(self):
        engine = CBOMEngine()
        finding = self._make_finding(
            algorithm="RSA-2048",
            family="RSA",
            risk=8,
            quantum_status="vulnerable",
            hndl=False,
        )
        comps = engine.aggregate(
            code_findings=[finding],
            org_data_sensitivity="highly_confidential",
        )
        # algorithm_risk=8 ≥ 7 → urgent
        assert comps[0].threat_timeline in ("urgent", "immediate")
