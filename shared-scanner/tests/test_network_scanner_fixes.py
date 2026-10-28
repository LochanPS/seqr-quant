"""
Tests for the four v1.2 fixes to scanner/network.py:
  Fix 1: Rewritten _compute_threat_timeline (IMMEDIATE/URGENT/PLANNED/ROADMAP)
  Fix 2: scan_confidence + scan_confidence_note per domain
  Fix 3: rate_limit_seconds + scan_domains_with_checkpoint + User-Agent
  Fix 4: scan_outcome categorisation; errors always produce results
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

from engines.classifier import classify_algorithm
from scanner.network import (
    DomainScanResult,
    NetworkScanner,
    _categorize_scan_error,
    _cidr_cdn,
    _compute_scan_confidence,
    _compute_threat_timeline,
    _detect_cdn,
    _is_cloud_ip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_component(
    tls_version: str = "TLS_1_3",
    cert_algorithm: Optional[str] = "ECDSA-P256",
    key_exchange: str = "X25519",
    data_shelf_life: str = "medium",
    cert_expired: bool = False,
    deprecated: bool = False,
    final_algorithm_risk: Optional[int] = None,
    quantum_status: str = "vulnerable",
    hybrid_status: str = "none",
) -> DomainScanResult:
    """Build a synthetic DomainScanResult and compute threat_timeline."""
    result = DomainScanResult(domain="test.example.com", port=443, reachable=True)
    result.tls_version = tls_version
    result.data_shelf_life = data_shelf_life
    result.cert_expired = cert_expired
    result.deprecated = deprecated
    result.key_exchange_algorithm = key_exchange
    result.hybrid_status = hybrid_status
    result.quantum_status = quantum_status
    if final_algorithm_risk is not None:
        result.final_algorithm_risk = final_algorithm_risk
    elif cert_algorithm:
        cls = classify_algorithm(cert_algorithm)
        result.final_algorithm_risk = cls.algorithm_risk if cls else 0
    result.threat_timeline = _compute_threat_timeline(result)
    return result


def make_domain_result(
    cdn_detected: bool = False,
    scan_duration_ms: int = 1500,
    ip_address_scanned: Optional[str] = "203.0.113.1",
    domain: str = "example.com",
) -> DomainScanResult:
    """Build a DomainScanResult and compute scan_confidence."""
    result = DomainScanResult(domain=domain, port=443, reachable=True)
    result.cdn_detected = cdn_detected
    result.scan_duration_ms = scan_duration_ms
    result.ip_address_scanned = ip_address_scanned
    conf, note = _compute_scan_confidence(
        cdn_detected=cdn_detected,
        scan_duration_ms=scan_duration_ms,
        ip_address_scanned=ip_address_scanned,
    )
    result.scan_confidence = conf
    result.scan_confidence_note = note
    return result


def make_timeout_result(domain: str = "example.com") -> DomainScanResult:
    import datetime
    result = DomainScanResult(domain=domain, port=443, reachable=False)
    result.scan_outcome = "timeout"
    result.scan_timestamp = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    return result


def make_error_result(
    domain: str = "example.com",
    outcome: str = "dns_failure",
) -> DomainScanResult:
    import datetime
    result = DomainScanResult(domain=domain, port=443, reachable=False)
    result.scan_outcome = outcome
    result.scan_timestamp = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    return result


def _make_scan_result_mock(
    domain: str,
    tls_version: str = "TLS_1_3",
    cert_algo: str = "ec",
    cipher_name: str = "TLS_AES_256_GCM_SHA384",
    ephemeral_key=None,
    supported_curves=None,
) -> MagicMock:
    import datetime
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from sslyze.plugins.scan_commands import ScanCommand

    result = MagicMock()
    result.server_location.hostname = domain
    result.server_location.ip_address = "203.0.113.1"
    result.connectivity_error_trace = None

    scan_result = MagicMock()
    result.scan_result = scan_result

    if ephemeral_key is None:
        ek = MagicMock(spec=[])
        ek.type_name = "ECDH"
        ek.curve_name = "X25519"
        ek.size = 253
        ephemeral_key = ek

    cs = MagicMock()
    cs.cipher_suite.name = cipher_name
    cs.ephemeral_key = ephemeral_key

    for cmd in ScanCommand:
        cr = MagicMock()
        cr.result = MagicMock()
        cr.result.accepted_cipher_suites = []
        cr.result.supported_curves = []
        setattr(scan_result, cmd.value, cr)

    version_to_attr = {
        "TLS_1_3": ScanCommand.TLS_1_3_CIPHER_SUITES.value,
        "TLS_1_2": ScanCommand.TLS_1_2_CIPHER_SUITES.value,
        "TLS_1_1": ScanCommand.TLS_1_1_CIPHER_SUITES.value,
        "TLS_1_0": ScanCommand.TLS_1_0_CIPHER_SUITES.value,
    }
    attr = version_to_attr.get(tls_version)
    if attr:
        cr = MagicMock()
        cr.result.accepted_cipher_suites = [cs]
        setattr(scan_result, attr, cr)

    ec_r = MagicMock()
    curves = supported_curves or ["X25519", "secp256r1"]
    ec_r.result.supported_curves = [MagicMock(name=n) for n in curves]
    for c_mock, name in zip(ec_r.result.supported_curves, curves):
        c_mock.name = name
    setattr(scan_result, ScanCommand.ELLIPTIC_CURVES.value, ec_r)

    if "rsa" in cert_algo.lower():
        ks = int("".join(c for c in cert_algo if c.isdigit()) or "2048")
        pk = rsa.generate_private_key(65537, ks, default_backend()).public_key()
    else:
        pk = ec.generate_private_key(ec.SECP256R1(), default_backend()).public_key()

    leaf = MagicMock()
    leaf.public_key.return_value = pk
    leaf.serial_number = 1
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    leaf.not_valid_after_utc = now + datetime.timedelta(days=365)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    leaf.issuer = name
    leaf.subject = name
    leaf.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound(
        "no san", x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    cert_cr = MagicMock()
    cert_cr.result.certificate_deployments = [MagicMock(received_certificate_chain=[leaf])]
    setattr(scan_result, ScanCommand.CERTIFICATE_INFO.value, cert_cr)

    return result


# ===========================================================================
# Fix 1 — Threat Timeline Rewrite
# ===========================================================================

class TestThreatTimelineImmediate:
    """Spec tests + coverage for IMMEDIATE condition."""

    def test_tls10_is_immediate(self):
        component = make_component(tls_version="TLS_1_0")
        assert component.threat_timeline == "IMMEDIATE"

    def test_tls11_is_immediate(self):
        component = make_component(tls_version="TLS_1_1")
        assert component.threat_timeline == "IMMEDIATE"

    def test_expired_cert_is_immediate(self):
        component = make_component(cert_expired=True)
        assert component.threat_timeline == "IMMEDIATE"

    def test_algorithm_risk_10_is_immediate(self):
        component = make_component(final_algorithm_risk=10)
        assert component.threat_timeline == "IMMEDIATE"

    def test_deprecated_flag_is_immediate(self):
        component = make_component(deprecated=True, tls_version="TLS_1_2")
        assert component.threat_timeline == "IMMEDIATE"

    def test_immediate_overrides_urgent_conditions(self):
        # Even with RSA kex + long shelf life, IMMEDIATE wins when cert is expired
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="long",
            cert_expired=True,
        )
        assert component.threat_timeline == "IMMEDIATE"

    def test_tls12_no_expiry_not_immediate(self):
        component = make_component(tls_version="TLS_1_2", cert_expired=False, deprecated=False)
        assert component.threat_timeline != "IMMEDIATE"


class TestThreatTimelineUrgent:
    """Spec tests + coverage for URGENT condition."""

    def test_rsa_static_kex_long_data_is_urgent(self):
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="long",
        )
        assert component.threat_timeline == "URGENT"

    def test_rsa_static_kex_permanent_data_is_urgent(self):
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="permanent",
        )
        assert component.threat_timeline == "URGENT"

    def test_rsa_cert_tls13_is_planned_not_urgent(self):
        # RSA cert on TLS 1.3 with X25519 kex is NOT urgent — only static RSA kex is urgent
        component = make_component(
            tls_version="TLS_1_3",
            cert_algorithm="RSA-2048",
            key_exchange="X25519",
            data_shelf_life="short",
        )
        assert component.threat_timeline == "PLANNED"

    def test_x25519_long_shelf_life_is_planned_not_urgent(self):
        # X25519 is NOT static RSA kex — no HNDL risk regardless of shelf life
        component = make_component(
            tls_version="TLS_1_3",
            key_exchange="X25519",
            data_shelf_life="long",
        )
        assert component.threat_timeline == "PLANNED"

    def test_ecdhe_long_shelf_life_is_planned_not_urgent(self):
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="ECDHE",
            data_shelf_life="long",
        )
        assert component.threat_timeline == "PLANNED"

    def test_rsa_kex_short_shelf_life_is_planned(self):
        # RSA kex is URGENT only with long/permanent shelf life
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="short",
        )
        assert component.threat_timeline == "PLANNED"

    def test_rsa_kex_medium_shelf_life_is_planned(self):
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="medium",
        )
        assert component.threat_timeline == "PLANNED"

    def test_rsa_kex_ephemeral_shelf_life_is_planned(self):
        component = make_component(
            tls_version="TLS_1_2",
            key_exchange="RSA",
            data_shelf_life="ephemeral",
        )
        assert component.threat_timeline == "PLANNED"


class TestThreatTimelinePlanned:
    """Spec tests + coverage for PLANNED (default) condition."""

    def test_tls13_ecdsa_x25519_is_planned(self):
        component = make_component(
            tls_version="TLS_1_3",
            cert_algorithm="ECDSA-P256",
            key_exchange="X25519",
            data_shelf_life="short",
        )
        assert component.threat_timeline == "PLANNED"

    def test_tls12_ecdhe_vulnerable_is_planned(self):
        component = make_component(
            tls_version="TLS_1_2",
            cert_algorithm="ECDSA-P256",
            key_exchange="ECDHE",
            data_shelf_life="medium",
        )
        assert component.threat_timeline == "PLANNED"

    def test_vulnerable_quantum_status_defaults_planned(self):
        component = make_component(
            tls_version="TLS_1_3",
            quantum_status="vulnerable",
        )
        assert component.threat_timeline == "PLANNED"


class TestThreatTimelineRoadmap:
    """Coverage for ROADMAP condition."""

    def test_hybrid_status_hybrid_is_roadmap(self):
        component = make_component(
            tls_version="TLS_1_3",
            hybrid_status="hybrid",
            quantum_status="hybrid",
        )
        assert component.threat_timeline == "ROADMAP"

    def test_hybrid_status_full_pqc_is_roadmap(self):
        component = make_component(
            tls_version="TLS_1_3",
            hybrid_status="full_pqc",
            quantum_status="safe",
        )
        assert component.threat_timeline == "ROADMAP"

    def test_quantum_status_safe_is_roadmap(self):
        component = make_component(
            tls_version="TLS_1_3",
            quantum_status="safe",
            hybrid_status="none",
        )
        assert component.threat_timeline == "ROADMAP"


# ===========================================================================
# Fix 2 — Scan Confidence
# ===========================================================================

class TestScanConfidence:
    """Spec tests + coverage for scan_confidence field."""

    def test_cdn_domain_is_low_confidence(self):
        result = make_domain_result(cdn_detected=True)
        assert result.scan_confidence == "low"

    def test_slow_scan_is_low_confidence(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=30000)
        assert result.scan_confidence == "low"

    def test_direct_scan_is_high_confidence(self):
        result = make_domain_result(
            cdn_detected=False,
            scan_duration_ms=1500,
            ip_address_scanned="203.0.113.1",
        )
        assert result.scan_confidence == "high"

    def test_cdn_note_is_set(self):
        result = make_domain_result(cdn_detected=True)
        assert "CDN" in result.scan_confidence_note

    def test_slow_scan_note_is_set(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=30000)
        assert "WAF" in result.scan_confidence_note or "Slow" in result.scan_confidence_note

    def test_high_confidence_note_mentions_direct(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=500, ip_address_scanned="10.0.0.1")
        assert "Direct" in result.scan_confidence_note or result.scan_confidence == "high"

    def test_cloud_aws_ip_is_medium_confidence(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=200, ip_address_scanned="52.100.200.1")
        assert result.scan_confidence == "medium"

    def test_cloud_gcp_ip_is_medium_confidence(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=200, ip_address_scanned="34.50.100.1")
        assert result.scan_confidence == "medium"

    def test_cloud_azure_ip_is_medium_confidence(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=200, ip_address_scanned="13.100.200.1")
        assert result.scan_confidence == "medium"

    def test_cloud_ip_note_mentions_cloud(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=200, ip_address_scanned="54.200.100.1")
        assert "cloud" in result.scan_confidence_note.lower()

    def test_cdn_overrides_fast_scan(self):
        # CDN takes priority even if scan is fast
        result = make_domain_result(cdn_detected=True, scan_duration_ms=100)
        assert result.scan_confidence == "low"

    def test_slow_threshold_exactly_25000_is_not_low(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=25000)
        assert result.scan_confidence != "low"

    def test_slow_threshold_25001_is_low(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=25001)
        assert result.scan_confidence == "low"

    def test_no_ip_non_cdn_is_high(self):
        result = make_domain_result(cdn_detected=False, scan_duration_ms=500, ip_address_scanned=None)
        assert result.scan_confidence == "high"


class TestIsCloudIP:
    def test_aws_52_range(self):
        assert _is_cloud_ip("52.0.0.1") is True

    def test_aws_54_range(self):
        assert _is_cloud_ip("54.200.100.1") is True

    def test_aws_3_range(self):
        assert _is_cloud_ip("3.100.200.1") is True

    def test_gcp_34_range(self):
        assert _is_cloud_ip("34.0.0.1") is True

    def test_gcp_35_range(self):
        assert _is_cloud_ip("35.50.100.1") is True

    def test_azure_13_range(self):
        assert _is_cloud_ip("13.100.200.1") is True

    def test_azure_40_range(self):
        assert _is_cloud_ip("40.200.100.1") is True

    def test_non_cloud_documentation_range(self):
        assert _is_cloud_ip("203.0.113.1") is False

    def test_non_cloud_private_range(self):
        assert _is_cloud_ip("10.0.0.1") is False

    def test_non_cloud_loopback(self):
        assert _is_cloud_ip("127.0.0.1") is False

    def test_invalid_ip_returns_false(self):
        assert _is_cloud_ip("not-an-ip") is False

    def test_empty_string_returns_false(self):
        assert _is_cloud_ip("") is False


# ===========================================================================
# Fix 4 — Scan Outcome Categorisation
# ===========================================================================

class TestScanOutcome:
    """Spec tests + coverage for scan_outcome field."""

    def test_timeout_produces_scan_outcome_field(self):
        result = make_timeout_result(domain="example.com")
        assert result.scan_outcome == "timeout"
        assert result.reachable is False
        assert result.scan_timestamp is not None
        assert result.domain == "example.com"

    def test_dns_failure_produces_scan_outcome_field(self):
        result = make_error_result(domain="example.com", outcome="dns_failure")
        assert result.scan_outcome == "dns_failure"
        assert result.reachable is False

    def test_success_is_default_scan_outcome(self):
        result = DomainScanResult(domain="example.com", port=443, reachable=True)
        assert result.scan_outcome == "success"

    def test_connection_refused_outcome_value(self):
        result = make_error_result(outcome="connection_refused")
        assert result.scan_outcome == "connection_refused"

    def test_ssl_error_outcome_value(self):
        result = make_error_result(outcome="ssl_error")
        assert result.scan_outcome == "ssl_error"

    def test_unknown_error_outcome_value(self):
        result = make_error_result(outcome="unknown_error")
        assert result.scan_outcome == "unknown_error"

    def test_cdn_blocked_outcome_value(self):
        result = make_error_result(outcome="cdn_blocked")
        assert result.scan_outcome == "cdn_blocked"


class TestCategorizeScanError:
    def test_dns_failure_hostname_resolution(self):
        assert _categorize_scan_error("ServerHostnameCouldNotBeResolved") == "dns_failure"

    def test_dns_failure_name_resolution(self):
        assert _categorize_scan_error("Name resolution failed") == "dns_failure"

    def test_timeout_message(self):
        assert _categorize_scan_error("Connection timed out after 10s") == "timeout"

    def test_timeout_keyword(self):
        assert _categorize_scan_error("Server timeout") == "timeout"

    def test_connection_refused(self):
        assert _categorize_scan_error("Connection refused") == "connection_refused"

    def test_connection_reset(self):
        assert _categorize_scan_error("Connection reset by peer") == "connection_refused"

    def test_ssl_error(self):
        assert _categorize_scan_error("SSL handshake failed") == "ssl_error"

    def test_tls_error(self):
        assert _categorize_scan_error("TLS protocol error") == "ssl_error"

    def test_unknown_error(self):
        assert _categorize_scan_error("Something unexpected happened") == "unknown_error"

    def test_none_is_unknown(self):
        assert _categorize_scan_error(None) == "unknown_error"

    def test_empty_is_unknown(self):
        assert _categorize_scan_error("") == "unknown_error"


# ===========================================================================
# Fix 3 — Rate Limiting + scan_domains_with_checkpoint
# ===========================================================================

class TestRateLimiting:
    def test_scanner_has_rate_limit_seconds(self):
        scanner = NetworkScanner()
        assert hasattr(scanner, "rate_limit_seconds")

    def test_default_rate_limit_is_0_5(self):
        scanner = NetworkScanner()
        assert scanner.rate_limit_seconds == 0.5

    def test_custom_rate_limit_stored(self):
        scanner = NetworkScanner(rate_limit_seconds=2.0)
        assert scanner.rate_limit_seconds == 2.0

    def test_rate_limit_zero_stored(self):
        scanner = NetworkScanner(rate_limit_seconds=0.0)
        assert scanner.rate_limit_seconds == 0.0

    def test_scan_domains_with_checkpoint_method_exists(self):
        scanner = NetworkScanner()
        assert hasattr(scanner, "scan_domains_with_checkpoint")
        assert callable(scanner.scan_domains_with_checkpoint)

    @patch("scanner.network.time.sleep")
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_rate_limit_sleep_called_between_two_domains(
        self, MockScanner, MockLocation, mock_sleep
    ):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        scanner = NetworkScanner(timeout=5, rate_limit_seconds=0.3)
        scanner.scan_domains(["d1.com", "d2.com"])

        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_once_with(0.3)

    @patch("scanner.network.time.sleep")
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_no_sleep_for_single_domain(
        self, MockScanner, MockLocation, mock_sleep
    ):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        NetworkScanner(timeout=5, rate_limit_seconds=0.5).scan_domains(["d1.com"])
        mock_sleep.assert_not_called()

    @patch("scanner.network.time.sleep")
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_rate_limit_zero_no_sleep(
        self, MockScanner, MockLocation, mock_sleep
    ):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        NetworkScanner(timeout=5, rate_limit_seconds=0.0).scan_domains(["d1.com", "d2.com"])
        mock_sleep.assert_not_called()

    @patch("scanner.network.time.sleep")
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_three_domains_sleep_twice(
        self, MockScanner, MockLocation, mock_sleep
    ):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        NetworkScanner(timeout=5, rate_limit_seconds=0.5).scan_domains(["a.com", "b.com", "c.com"])
        assert mock_sleep.call_count == 2


class TestScanDomainsWithCheckpoint:
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_checkpoint_callback_called_for_each_domain(
        self, MockScanner, MockLocation
    ):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        received = []
        scanner = NetworkScanner(timeout=5, rate_limit_seconds=0)
        results = scanner.scan_domains_with_checkpoint(
            ["d1.com"],
            checkpoint_callback=received.append,
        )
        assert len(received) == 1
        assert len(results) == 1
        assert received[0] is results[0]

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_checkpoint_empty_list_returns_empty(self, MockScanner, MockLocation):
        scanner = NetworkScanner(timeout=5, rate_limit_seconds=0)
        results = scanner.scan_domains_with_checkpoint([])
        assert results == []

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_checkpoint_no_callback_is_ok(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("d1.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        scanner = NetworkScanner(timeout=5, rate_limit_seconds=0)
        results = scanner.scan_domains_with_checkpoint(["d1.com"])
        assert len(results) == 1

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_checkpoint_failed_domain_included(self, MockScanner, MockLocation):
        failed = MagicMock()
        failed.server_location.hostname = "dead.example.com"
        failed.scan_result = None
        failed.connectivity_error_trace = "Connection timed out after 30s"

        MockScanner.return_value.get_results.return_value = [failed]
        MockScanner.return_value.queue_scans.return_value = None

        received = []
        scanner = NetworkScanner(timeout=5, rate_limit_seconds=0)
        results = scanner.scan_domains_with_checkpoint(
            ["dead.example.com"],
            checkpoint_callback=received.append,
        )
        assert len(results) == 1
        assert results[0].reachable is False
        assert results[0].scan_outcome == "timeout"
        assert results[0].scan_timestamp is not None
        assert results[0].domain == "dead.example.com"
        assert len(received) == 1


# ===========================================================================
# Fix 4 — Scanner sets scan_outcome via _scan_single_domain
# ===========================================================================

class TestScannerSetsNewFields:
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_successful_scan_sets_scan_timestamp(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("example.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("example.com")
        assert result.scan_timestamp is not None
        assert "T" in result.scan_timestamp  # ISO format contains "T"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_successful_scan_sets_scan_duration_ms(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("example.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("example.com")
        assert isinstance(result.scan_duration_ms, int)
        assert result.scan_duration_ms >= 0

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_successful_scan_outcome_is_success(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("example.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("example.com")
        assert result.scan_outcome == "success"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_successful_scan_sets_scan_confidence(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("example.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("example.com")
        assert result.scan_confidence in ("high", "medium", "low")

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_connectivity_error_sets_scan_timestamp(self, MockScanner, MockLocation):
        failed = MagicMock()
        failed.server_location.hostname = "unreachable.com"
        failed.scan_result = None
        failed.connectivity_error_trace = "Connection timed out"

        MockScanner.return_value.get_results.return_value = [failed]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("unreachable.com")
        assert result.reachable is False
        assert result.scan_timestamp is not None
        assert result.scan_outcome == "timeout"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_connectivity_refused_sets_outcome(self, MockScanner, MockLocation):
        failed = MagicMock()
        failed.server_location.hostname = "closed.com"
        failed.scan_result = None
        failed.connectivity_error_trace = "Connection refused"

        MockScanner.return_value.get_results.return_value = [failed]
        MockScanner.return_value.queue_scans.return_value = None

        result = NetworkScanner(timeout=5, rate_limit_seconds=0).scan_domain("closed.com")
        assert result.scan_outcome == "connection_refused"
        assert result.reachable is False


# ===========================================================================
# New field existence / default checks
# ===========================================================================

class TestNewFieldDefaults:
    def test_scan_duration_ms_default_zero(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.scan_duration_ms == 0

    def test_scan_timestamp_default_none(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.scan_timestamp is None

    def test_ip_address_scanned_default_none(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.ip_address_scanned is None

    def test_cdn_detected_default_false(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.cdn_detected is False

    def test_scan_confidence_default_high(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.scan_confidence == "high"

    def test_scan_confidence_note_default_empty(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.scan_confidence_note == ""

    def test_scan_outcome_default_success(self):
        r = DomainScanResult(domain="x.com", port=443, reachable=True)
        assert r.scan_outcome == "success"

    def test_all_seven_new_fields_present(self):
        fields = DomainScanResult.__dataclass_fields__
        for f in (
            "scan_duration_ms",
            "scan_timestamp",
            "ip_address_scanned",
            "cdn_detected",
            "scan_confidence",
            "scan_confidence_note",
            "scan_outcome",
        ):
            assert f in fields, f"Missing field: {f}"


# ===========================================================================
# seqr_scanner re-export
# ===========================================================================

class TestSeqrScannerReExport:
    def test_domain_scan_result_importable_from_seqr_scanner(self):
        from seqr_scanner import DomainScanResult as DSR
        assert DSR is DomainScanResult

    def test_network_scanner_importable_from_seqr_scanner(self):
        from seqr_scanner import NetworkScanner as NS
        assert NS is NetworkScanner

    def test_all_required_fields_on_seqr_scanner_domain_scan_result(self):
        from seqr_scanner import DomainScanResult as DSR
        fields = DSR.__dataclass_fields__
        for f in ("scan_confidence", "scan_confidence_note", "scan_outcome",
                  "scan_timestamp", "scan_duration_ms", "cdn_detected", "ip_address_scanned"):
            assert f in fields


# ===========================================================================
# CDN CIDR range detection bug fixes
# Bug: 185.199.110.153 (GitHub Pages/Fastly) and 162.159.152.4, 172.66.0.145
#      (Cloudflare) were not detected because PTR records didn't match patterns.
# Fix: CIDR-based detection using published IP ranges.
# ===========================================================================

class TestCidrCdn:
    def test_github_pages_fastly_range_185_199_110(self):
        # 185.199.108.0/22 is GitHub Pages (Fastly-fronted)
        # universe.razorpay.com was returning cdn_detected=False for this IP
        assert _cidr_cdn("185.199.110.153") == "Fastly"

    def test_github_pages_fastly_range_185_199_108(self):
        assert _cidr_cdn("185.199.108.1") == "Fastly"

    def test_github_pages_fastly_range_185_199_111(self):
        # All four /24 blocks in 185.199.108.0/22
        assert _cidr_cdn("185.199.111.255") == "Fastly"

    def test_cloudflare_162_159_range(self):
        # 162.158.0.0/15 is Cloudflare — engineering.razorpay.com was at 162.159.152.4
        assert _cidr_cdn("162.159.152.4") == "Cloudflare"

    def test_cloudflare_172_66_range(self):
        # 172.64.0.0/13 is Cloudflare — knowledgebase.razorpay.com was at 172.66.0.145
        assert _cidr_cdn("172.66.0.145") == "Cloudflare"

    def test_cloudflare_104_16_range(self):
        assert _cidr_cdn("104.16.0.1") == "Cloudflare"

    def test_cloudflare_104_24_range(self):
        assert _cidr_cdn("104.24.0.1") == "Cloudflare"

    def test_fastly_151_101_range(self):
        # 151.101.0.0/16 is Fastly
        assert _cidr_cdn("151.101.100.200") == "Fastly"

    def test_fastly_199_232_range(self):
        assert _cidr_cdn("199.232.0.1") == "Fastly"

    def test_non_cdn_ip_returns_empty(self):
        # Documentation range — not a CDN
        assert _cidr_cdn("203.0.113.1") == ""

    def test_private_ip_returns_empty(self):
        assert _cidr_cdn("10.0.0.1") == ""

    def test_aws_ip_returns_empty(self):
        # AWS is cloud, not CDN — CIDR ranges should not include AWS
        assert _cidr_cdn("52.0.0.1") == ""

    def test_invalid_ip_returns_empty(self):
        assert _cidr_cdn("not-an-ip") == ""

    def test_empty_string_returns_empty(self):
        assert _cidr_cdn("") == ""
