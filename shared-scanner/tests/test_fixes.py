"""
Tests for the five shared-scanner fixes:
  Fix 1: HNDL must always be labeled "Estimated"
  Fix 2: Rename risk score to PQC Migration Priority (cap at 7.0 for PLANNED)
  Fix 3: Crypto Agility Score
  Fix 4: Deployment Readiness Level
  Fix 5: Compliance framework list — India-first, no CNSA
"""

from __future__ import annotations

import pytest

from engines.classifier import classify_algorithm
from scanner.network import (
    DomainScanResult,
    _compute_crypto_agility,
    _compute_deployment_level,
    _compute_estimated_hndl_exposure,
    _compute_hndl_inference_basis,
    _compute_pqc_migration_priority,
    _compute_threat_timeline,
)


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------

def make_domain_result(
    domain: str = "example.com",
    hndl_risk_inferred: bool = False,
    threat_timeline: str = "",
    cert_algorithm: str = "RSA-2048",
    data_shelf_life: str = "medium",
    tls_version: str = "TLS_1_3",
    key_exchange: str = "X25519",
    hybrid_status: str = "none",
    cdn_detected: bool = False,
    cert_expired: bool = False,
    final_algorithm_risk: int | None = None,
    quantum_status: str = "vulnerable",
    deprecated: bool = False,
    cert_algorithm_label: str = "",
) -> DomainScanResult:
    """Build a synthetic DomainScanResult with all fix-related fields populated."""
    result = DomainScanResult(domain=domain, port=443, reachable=True)
    result.tls_version = tls_version
    result.key_exchange_algorithm = key_exchange
    result.hybrid_status = hybrid_status
    result.cdn_detected = cdn_detected
    result.cert_expired = cert_expired
    result.data_shelf_life = data_shelf_life
    result.quantum_status = quantum_status
    result.cert_algorithm = cert_algorithm_label or ""

    # deprecated flag: set by TLS version or explicit override
    result.deprecated = deprecated or tls_version in ("TLS_1_0", "TLS_1_1", "SSL_2_0", "SSL_3_0")

    # final_algorithm_risk: from cert algo if not provided
    if final_algorithm_risk is not None:
        result.final_algorithm_risk = final_algorithm_risk
    elif cert_algorithm:
        cls = classify_algorithm(cert_algorithm)
        result.final_algorithm_risk = cls.algorithm_risk if cls else 0

    # HNDL risk: explicit flag or from kex + shelf life
    result.hndl_risk = hndl_risk_inferred or (
        key_exchange == "RSA" and data_shelf_life in ("long", "permanent")
    )

    # threat_timeline: explicit override or computed
    result.threat_timeline = threat_timeline if threat_timeline else _compute_threat_timeline(result)

    # Compute all fix fields
    result.estimated_hndl_exposure = _compute_estimated_hndl_exposure(result)
    result.hndl_inference_basis = _compute_hndl_inference_basis(domain)
    result.pqc_migration_priority = _compute_pqc_migration_priority(result)
    result.crypto_agility_score, result.crypto_agility_breakdown = _compute_crypto_agility(result)
    result.deployment_level, result.deployment_level_name = _compute_deployment_level(result)

    return result


# ===========================================================================
# Fix 1 — Estimated HNDL exposure
# ===========================================================================

class TestEstimatedHndlExposure:
    def test_hndl_is_labeled_estimated(self):
        result = make_domain_result(hndl_risk_inferred=True)
        assert hasattr(result, "estimated_hndl_exposure")
        assert hasattr(result, "hndl_inference_basis")
        assert (
            "inference" in result.hndl_inference_basis.lower()
            or "assumed" in result.hndl_inference_basis.lower()
        )

    def test_estimated_exposure_high_when_hndl_risk(self):
        result = make_domain_result(hndl_risk_inferred=True)
        assert result.estimated_hndl_exposure == "high"

    def test_estimated_exposure_medium_vulnerable_medium_shelf(self):
        result = make_domain_result(
            quantum_status="vulnerable",
            data_shelf_life="medium",
            hndl_risk_inferred=False,
        )
        assert result.estimated_hndl_exposure == "medium"

    def test_estimated_exposure_low_vulnerable_ephemeral(self):
        result = make_domain_result(
            quantum_status="vulnerable",
            data_shelf_life="ephemeral",
            hndl_risk_inferred=False,
        )
        assert result.estimated_hndl_exposure == "low"

    def test_estimated_exposure_none_for_safe_algorithm(self):
        result = make_domain_result(
            quantum_status="safe",
            hndl_risk_inferred=False,
        )
        assert result.estimated_hndl_exposure == "none"

    def test_financial_domain_basis_says_assumed(self):
        result = make_domain_result(domain="payments.bank.in")
        assert "assumed" in result.hndl_inference_basis.lower()
        assert "financial" in result.hndl_inference_basis.lower()

    def test_health_domain_basis_says_assumed(self):
        result = make_domain_result(domain="ehr.hospital.com")
        assert "assumed" in result.hndl_inference_basis.lower()
        assert "health" in result.hndl_inference_basis.lower()

    def test_auth_domain_basis_says_ephemeral(self):
        result = make_domain_result(domain="auth.company.com")
        assert "assumed" in result.hndl_inference_basis.lower()
        assert "ephemeral" in result.hndl_inference_basis.lower()

    def test_generic_domain_basis_says_inference(self):
        result = make_domain_result(domain="example.com")
        assert "inference" in result.hndl_inference_basis.lower()

    def test_hndl_inference_basis_field_exists_on_domain_scan_result(self):
        fields = DomainScanResult.__dataclass_fields__
        assert "hndl_inference_basis" in fields

    def test_estimated_hndl_exposure_field_exists_on_domain_scan_result(self):
        fields = DomainScanResult.__dataclass_fields__
        assert "estimated_hndl_exposure" in fields

    def test_default_estimated_hndl_exposure_is_none(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.estimated_hndl_exposure == "none"

    def test_default_hndl_inference_basis_is_empty(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.hndl_inference_basis == ""


# ===========================================================================
# Fix 2 — PQC Migration Priority (PLANNED capped at 7.0)
# ===========================================================================

class TestPqcMigrationPriority:
    def test_planned_timeline_caps_priority_at_7(self):
        result = make_domain_result(
            threat_timeline="PLANNED",
            cert_algorithm="RSA-2048",
            data_shelf_life="long",
        )
        assert result.pqc_migration_priority <= 7.0

    def test_planned_timeline_rsa2048_risk8_gives_7(self):
        # RSA-2048 algorithm_risk=8 → capped to 7.0 for PLANNED
        result = make_domain_result(
            threat_timeline="PLANNED",
            cert_algorithm="RSA-2048",
        )
        assert result.pqc_migration_priority == 7.0

    def test_immediate_timeline_not_capped(self):
        # algorithm_risk=9 (TLS 1.0), IMMEDIATE → no cap
        result = make_domain_result(
            tls_version="TLS_1_0",
            final_algorithm_risk=9,
        )
        # threat_timeline will be IMMEDIATE → no cap at 7.0
        assert result.threat_timeline == "IMMEDIATE"
        assert result.pqc_migration_priority == 9.0

    def test_urgent_timeline_not_capped(self):
        result = make_domain_result(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="long",
            final_algorithm_risk=8,
        )
        assert result.threat_timeline == "URGENT"
        assert result.pqc_migration_priority == 8.0

    def test_roadmap_timeline_low_priority(self):
        result = make_domain_result(
            tls_version="TLS_1_3",
            quantum_status="safe",
            hybrid_status="hybrid",
            final_algorithm_risk=0,
        )
        assert result.pqc_migration_priority == 0.0

    def test_pqc_migration_priority_field_exists(self):
        fields = DomainScanResult.__dataclass_fields__
        assert "pqc_migration_priority" in fields

    def test_pqc_migration_priority_default_is_zero(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.pqc_migration_priority == 0.0

    def test_planned_risk_5_stays_5(self):
        # risk < 7 → no effect from cap
        result = make_domain_result(
            threat_timeline="PLANNED",
            final_algorithm_risk=5,
        )
        assert result.pqc_migration_priority == 5.0

    def test_planned_risk_10_caps_at_7(self):
        result = make_domain_result(
            threat_timeline="PLANNED",
            final_algorithm_risk=10,
        )
        assert result.pqc_migration_priority == 7.0


# ===========================================================================
# Fix 3 — Crypto Agility Score
# ===========================================================================

class TestCryptoAgilityScore:
    def test_crypto_agility_tls13_x25519_no_pqc(self):
        # TLS1.3(2) + X25519(2) + cert not expired(1) + no deprecated(0.5) - CDN(1) = 4.5
        result = make_domain_result(
            tls_version="TLS_1_3",
            key_exchange="X25519",
            hybrid_status="none",
            cdn_detected=True,
            cert_expired=False,
        )
        assert 4.0 <= result.crypto_agility_score <= 5.0

    def test_tls10_gets_legacy_penalty(self):
        result = make_domain_result(tls_version="TLS_1_0", cdn_detected=False, cert_expired=False)
        # +0 (not TLS1.3) + forward_secrecy depends on kex + -2 (legacy) + ...
        # score should be lower than a TLS 1.3 result
        tls13_result = make_domain_result(tls_version="TLS_1_3", cdn_detected=False, cert_expired=False)
        assert result.crypto_agility_score < tls13_result.crypto_agility_score

    def test_expired_cert_lowers_score(self):
        valid = make_domain_result(tls_version="TLS_1_3", cert_expired=False)
        expired = make_domain_result(tls_version="TLS_1_3", cert_expired=True)
        assert expired.crypto_agility_score < valid.crypto_agility_score

    def test_hybrid_pqc_adds_2_points(self):
        no_pqc = make_domain_result(tls_version="TLS_1_3", hybrid_status="none", cdn_detected=False)
        hybrid = make_domain_result(tls_version="TLS_1_3", hybrid_status="hybrid", cdn_detected=False)
        assert hybrid.crypto_agility_score - no_pqc.crypto_agility_score == pytest.approx(2.0)

    def test_cdn_penalty_lowers_score(self):
        no_cdn = make_domain_result(tls_version="TLS_1_3", cdn_detected=False)
        cdn = make_domain_result(tls_version="TLS_1_3", cdn_detected=True)
        assert no_cdn.crypto_agility_score - cdn.crypto_agility_score == pytest.approx(1.0)

    def test_score_clamped_to_0_10(self):
        # Worst possible
        result = make_domain_result(
            tls_version="TLS_1_0", cert_expired=True, cdn_detected=True,
            hybrid_status="none", key_exchange="RSA",
        )
        assert 0.0 <= result.crypto_agility_score <= 10.0

    def test_max_score_not_exceeded(self):
        # Best possible configuration
        result = make_domain_result(
            tls_version="TLS_1_3",
            key_exchange="X25519",
            hybrid_status="hybrid",
            cert_expired=False,
            cdn_detected=False,
            cert_algorithm_label="ML-DSA-65",
        )
        assert result.crypto_agility_score <= 10.0

    def test_breakdown_dict_has_expected_keys(self):
        result = make_domain_result()
        bd = result.crypto_agility_breakdown
        for key in ("tls_1_3", "forward_secrecy", "cert_valid", "no_deprecated",
                    "hybrid_pqc", "full_pqc_cert", "cdn_penalty"):
            assert key in bd, f"Missing key: {key}"

    def test_crypto_agility_score_field_exists(self):
        fields = DomainScanResult.__dataclass_fields__
        assert "crypto_agility_score" in fields
        assert "crypto_agility_breakdown" in fields

    def test_perfect_tls13_x25519_no_cdn_score(self):
        # TLS1.3(2) + X25519(2) + valid(1) + no deprecated(0.5) = 5.5
        result = make_domain_result(
            tls_version="TLS_1_3", key_exchange="X25519",
            hybrid_status="none", cdn_detected=False, cert_expired=False,
        )
        assert result.crypto_agility_score == pytest.approx(5.5)


# ===========================================================================
# Fix 4 — Deployment Readiness Level
# ===========================================================================

class TestDeploymentLevel:
    def test_tls10_is_level0(self):
        result = make_domain_result(tls_version="TLS_1_0")
        assert result.deployment_level == 0

    def test_tls11_is_level0(self):
        result = make_domain_result(tls_version="TLS_1_1")
        assert result.deployment_level == 0

    def test_expired_cert_is_level0(self):
        result = make_domain_result(tls_version="TLS_1_3", cert_expired=True)
        assert result.deployment_level == 0

    def test_deprecated_flag_is_level0(self):
        result = make_domain_result(tls_version="TLS_1_2", deprecated=True)
        assert result.deployment_level == 0

    def test_tls13_no_pqc_is_level1(self):
        result = make_domain_result(tls_version="TLS_1_3", hybrid_status="none")
        assert result.deployment_level == 1

    def test_tls12_no_pqc_is_level1(self):
        result = make_domain_result(tls_version="TLS_1_2", hybrid_status="none")
        assert result.deployment_level == 1

    def test_hybrid_pqc_is_level3(self):
        result = make_domain_result(hybrid_status="hybrid")
        assert result.deployment_level == 3

    def test_hybrid_name_is_hybrid_deployed(self):
        result = make_domain_result(hybrid_status="hybrid")
        assert result.deployment_level_name == "Hybrid Deployed"

    def test_full_pqc_mldsa_cert_is_level4(self):
        result = make_domain_result(
            hybrid_status="full_pqc",
            cert_algorithm_label="ML-DSA-65",
        )
        assert result.deployment_level == 4

    def test_full_pqc_no_mldsa_cert_is_level1(self):
        # full_pqc hybrid_status but cert is RSA → stays at 1
        result = make_domain_result(
            hybrid_status="full_pqc",
            cert_algorithm_label="RSA-2048",
        )
        assert result.deployment_level == 1

    def test_level0_name_is_legacy(self):
        result = make_domain_result(tls_version="TLS_1_0")
        assert result.deployment_level_name == "Legacy"

    def test_level1_name_is_modern_classical(self):
        result = make_domain_result(tls_version="TLS_1_3", hybrid_status="none")
        assert result.deployment_level_name == "Modern Classical"

    def test_deployment_level_fields_exist(self):
        fields = DomainScanResult.__dataclass_fields__
        assert "deployment_level" in fields
        assert "deployment_level_name" in fields


# ===========================================================================
# Fix 5 — India-first compliance frameworks, no CNSA
# ===========================================================================

class TestComplianceFrameworks:
    def test_cnsa_not_in_default_frameworks(self):
        from seqr_scanner.engines.compliance import DEFAULT_FRAMEWORKS
        framework_names = [f.name for f in DEFAULT_FRAMEWORKS]
        assert "CNSA" not in " ".join(framework_names)
        assert "DST" in " ".join(framework_names)

    def test_dst_task_force_2026_in_defaults(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        names = [f.name for f in DEFAULT_FRAMEWORKS]
        assert "DST_TASK_FORCE_2026" in names

    def test_rbi_it_framework_in_defaults(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        names = [f.name for f in DEFAULT_FRAMEWORKS]
        assert "RBI_IT_FRAMEWORK" in names

    def test_cert_in_in_defaults(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        names = [f.name for f in DEFAULT_FRAMEWORKS]
        assert "CERT_IN" in names

    def test_pci_dss_in_defaults(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        names = [f.name for f in DEFAULT_FRAMEWORKS]
        assert "PCI_DSS_4X" in names

    def test_rbi_status_is_monitor(self):
        from engines.compliance import RBI_IT_FRAMEWORK, check_framework
        result = check_framework(RBI_IT_FRAMEWORK)
        assert result.status == "MONITOR"

    def test_cert_in_status_is_monitor(self):
        from engines.compliance import CERT_IN, check_framework
        result = check_framework(CERT_IN)
        assert result.status == "MONITOR"

    def test_rbi_note_says_no_mandatory_pqc(self):
        from engines.compliance import RBI_IT_FRAMEWORK
        assert "No mandatory PQC" in RBI_IT_FRAMEWORK.note

    def test_cert_in_note_says_no_mandatory_pqc(self):
        from engines.compliance import CERT_IN
        assert "No mandatory PQC" in CERT_IN.note or "no PQC advisory" in CERT_IN.note.lower()

    def test_dst_is_recommendatory(self):
        # Corrected 2026-06: the DST report is a Task Force RECOMMENDATION, not a
        # statute. Enforcement rests with sectoral regulators (RBI/SEBI/DoT).
        from engines.compliance import DST_TASK_FORCE_2026
        assert DST_TASK_FORCE_2026.mandatory is False
        assert DST_TASK_FORCE_2026.enforcement == "recommendatory"

    def test_rbi_is_not_mandatory(self):
        from engines.compliance import RBI_IT_FRAMEWORK
        assert RBI_IT_FRAMEWORK.mandatory is False

    def test_framework_has_name_attribute(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        for fw in DEFAULT_FRAMEWORKS:
            assert hasattr(fw, "name")
            assert isinstance(fw.name, str)

    def test_dst_applies_to_india(self):
        from engines.compliance import DST_TASK_FORCE_2026
        assert DST_TASK_FORCE_2026.applies_to == "india"

    def test_seqr_scanner_engines_compliance_importable(self):
        from seqr_scanner.engines.compliance import DEFAULT_FRAMEWORKS
        assert len(DEFAULT_FRAMEWORKS) >= 4

    def test_no_cnsa_anywhere_in_names(self):
        from engines.compliance import DEFAULT_FRAMEWORKS
        for fw in DEFAULT_FRAMEWORKS:
            assert "CNSA" not in fw.name
            assert "CNSA" not in fw.display_name
