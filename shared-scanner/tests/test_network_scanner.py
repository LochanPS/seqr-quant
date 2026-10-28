"""
Tests for scanner/network.py.

Unit tests use synthetic sslyze-like mocks that match the REAL sslyze 6.0 object
structure (verified against google.com and badssl.com on 2026-06-13).

Key structural facts about sslyze 6.0:
  - accepted_cipher_suites[i].cipher_suite.name  → cipher name string
  - accepted_cipher_suites[i].ephemeral_key       → EcDhEphemeralKeyInfo or None
    .type_name  = "ECDH" | "DH"
    .curve_name = "X25519" | "secp256r1" | ...
    .size       = key size in bits
  - TLS 1.3 cipher names (TLS_AES_*, TLS_CHACHA20_*) NEVER encode key exchange
  - ELLIPTIC_CURVES.result.supported_curves[i].name = curve group name string
    X25519Kyber768 hybrid appears HERE, not in cipher names

Run unit tests only (no network):
    pytest tests/test_network_scanner.py -m "not integration"

Run integration tests (requires internet):
    pytest tests/test_network_scanner.py -m integration
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from scanner.network import (
    DomainScanResult,
    NetworkScanner,
    _check_pqc_in_ciphers,
    _check_pqc_in_curves,
    _detect_hybrid_status,
    _extract_key_exchange_from_cipher_name,
    _key_exchange_from_ephemeral_key,
    _parse_certificate,
    infer_shelf_life,
)
from engines.classifier import classify_algorithm

FIXTURES = Path(__file__).parent / "fixtures" / "sslyze"


# ---------------------------------------------------------------------------
# Helpers: real crypto objects for certificate tests
# ---------------------------------------------------------------------------

def _make_mock_rsa_cert(key_size: int = 2048, expired: bool = False) -> MagicMock:
    """Mock x509.Certificate with a real RSA public key (so isinstance checks work)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    cert = MagicMock()
    cert.public_key.return_value = private_key.public_key()
    cert.serial_number = 0xDEADBEEF

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if expired:
        cert.not_valid_after_utc = now - datetime.timedelta(days=1)
    else:
        cert.not_valid_after_utc = now + datetime.timedelta(days=365)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert.issuer = name
    cert.subject = name
    cert.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound(
        "No SAN", x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    return cert


def _make_mock_ec_cert(curve_name: str = "secp256r1", expired: bool = False) -> MagicMock:
    """Mock x509.Certificate with a real EC public key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    curve_map = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    private_key = ec.generate_private_key(curve_map.get(curve_name, ec.SECP256R1()), default_backend())
    cert = MagicMock()
    cert.public_key.return_value = private_key.public_key()
    cert.serial_number = 0xCAFEBABE

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if expired:
        cert.not_valid_after_utc = now - datetime.timedelta(days=1)
    else:
        cert.not_valid_after_utc = now + datetime.timedelta(days=180)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.com")])
    cert.issuer = name
    cert.subject = name
    cert.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound(
        "No SAN", x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    return cert


# ---------------------------------------------------------------------------
# Helpers: sslyze ephemeral key and curve mocks matching real structure
# ---------------------------------------------------------------------------

def _make_ephemeral_key(
    type_name: str = "ECDH",
    curve_name: str = "X25519",
    size: int = 253,
) -> MagicMock:
    """
    Return a mock matching sslyze's EcDhEphemeralKeyInfo / DhEphemeralKeyInfo.

    Real structure (verified against google.com 2026-06-13):
      ephemeral_key.type_name  = "ECDH"
      ephemeral_key.curve_name = "X25519"
      ephemeral_key.size       = 253
    """
    ek = MagicMock(spec=[])  # spec=[] → only explicitly set attrs exist
    ek.type_name = type_name
    ek.curve_name = curve_name
    ek.size = size
    return ek


def _make_curve(name: str) -> MagicMock:
    """Return a mock matching sslyze's NamedGroup object (has .name attribute)."""
    c = MagicMock(spec=[])
    c.name = name
    return c


def _make_scan_result_mock(
    domain: str,
    tls_version: str = "TLS_1_2",
    cert_algo: str = "rsa-2048",
    cipher_name: str = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ephemeral_key: Optional[MagicMock] = None,
    supported_curves: Optional[list[str]] = None,
) -> MagicMock:
    """
    Build a mock sslyze ServerScanResult matching the real sslyze 6.0 structure.

    ephemeral_key: if None, auto-derived from cipher_name / tls_version.
    supported_curves: curve group names for ELLIPTIC_CURVES result.
                      Defaults to ["X25519", "secp256r1"].
    """
    from sslyze.plugins.scan_commands import ScanCommand

    result = MagicMock()
    result.server_location.hostname = domain
    result.connectivity_error_trace = None

    scan_result = MagicMock()
    result.scan_result = scan_result

    # --- Derive ephemeral key if not provided ---
    if ephemeral_key is None:
        name_upper = cipher_name.upper()
        if tls_version == "TLS_1_3":
            ephemeral_key = _make_ephemeral_key("ECDH", "X25519", 253)
        elif "ECDHE" in name_upper or "ECDH_" in name_upper:
            ephemeral_key = _make_ephemeral_key("ECDH", "secp256r1", 256)
        elif "DHE" in name_upper:
            ephemeral_key = _make_ephemeral_key("DH", "", 2048)
        else:
            ephemeral_key = None  # RSA static key exchange — no ephemeral key

    cipher_suite_mock = MagicMock()
    cipher_suite_mock.cipher_suite.name = cipher_name
    cipher_suite_mock.ephemeral_key = ephemeral_key

    # --- Default: all TLS versions have no accepted suites ---
    for cmd in ScanCommand:
        cmd_result = MagicMock()
        cmd_result.result = MagicMock()
        cmd_result.result.accepted_cipher_suites = []
        cmd_result.result.supported_curves = []
        setattr(scan_result, cmd.value, cmd_result)

    # --- Set requested TLS version to have the one cipher ---
    version_to_attr = {
        "TLS_1_3": ScanCommand.TLS_1_3_CIPHER_SUITES.value,
        "TLS_1_2": ScanCommand.TLS_1_2_CIPHER_SUITES.value,
        "TLS_1_1": ScanCommand.TLS_1_1_CIPHER_SUITES.value,
        "TLS_1_0": ScanCommand.TLS_1_0_CIPHER_SUITES.value,
        "SSL_3_0": ScanCommand.SSL_3_0_CIPHER_SUITES.value,
        "SSL_2_0": ScanCommand.SSL_2_0_CIPHER_SUITES.value,
    }
    attr = version_to_attr.get(tls_version)
    if attr:
        cmd_result = MagicMock()
        cmd_result.result.accepted_cipher_suites = [cipher_suite_mock]
        setattr(scan_result, attr, cmd_result)

    # --- ELLIPTIC_CURVES result ---
    ec_result_mock = MagicMock()
    curves = supported_curves if supported_curves is not None else ["X25519", "secp256r1"]
    ec_result_mock.result.supported_curves = [_make_curve(n) for n in curves]
    setattr(scan_result, ScanCommand.ELLIPTIC_CURVES.value, ec_result_mock)

    # --- Certificate ---
    if "rsa" in cert_algo.lower():
        key_size = int("".join(c for c in cert_algo if c.isdigit()) or "2048")
        leaf_cert = _make_mock_rsa_cert(key_size=key_size)
    else:
        leaf_cert = _make_mock_ec_cert("secp256r1")

    cert_deployment = MagicMock()
    cert_deployment.received_certificate_chain = [leaf_cert]
    cert_result = MagicMock()
    cert_result.result.certificate_deployments = [cert_deployment]
    setattr(scan_result, ScanCommand.CERTIFICATE_INFO.value, cert_result)

    return result


# ---------------------------------------------------------------------------
# Unit tests — certificate parsing
# ---------------------------------------------------------------------------

class TestParseCertificate:
    def test_rsa_2048_cert(self):
        info = _parse_certificate(_make_mock_rsa_cert(key_size=2048))
        assert info.algorithm == "RSA"
        assert info.key_size == 2048
        assert info.is_expired is False
        assert info.days_until_expiry > 0

    def test_rsa_4096_cert(self):
        info = _parse_certificate(_make_mock_rsa_cert(key_size=4096))
        assert info.key_size == 4096

    def test_ecdsa_p256_cert(self):
        info = _parse_certificate(_make_mock_ec_cert("secp256r1"))
        assert info.algorithm == "ECDSA-P256"

    def test_ecdsa_p384_cert(self):
        info = _parse_certificate(_make_mock_ec_cert("secp384r1"))
        assert info.algorithm == "ECDSA-P384"

    def test_expired_cert_detection(self):
        info = _parse_certificate(_make_mock_rsa_cert(expired=True))
        assert info.is_expired is True
        assert info.days_until_expiry < 0


# ---------------------------------------------------------------------------
# Unit tests — ephemeral key extraction (core TLS 1.3 key exchange logic)
# ---------------------------------------------------------------------------

class TestKeyExchangeFromEphemeralKey:
    """
    Tests _key_exchange_from_ephemeral_key against real sslyze ephemeral key shapes.
    This is the primary key exchange source — cipher name parsing is only a fallback.
    """

    def test_x25519_ecdh_ephemeral_key(self):
        # Google.com TLS 1.3 uses this exact structure
        ek = _make_ephemeral_key("ECDH", "X25519", 253)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_CHACHA20_POLY1305_SHA256") == "X25519"

    def test_secp256r1_ecdh_ephemeral_key(self):
        ek = _make_ephemeral_key("ECDH", "secp256r1", 256)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") == "ECDHE"

    def test_secp384r1_ecdh_ephemeral_key(self):
        ek = _make_ephemeral_key("ECDH", "secp384r1", 384)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == "ECDHE"

    def test_x448_ecdh_ephemeral_key(self):
        ek = _make_ephemeral_key("ECDH", "X448", 448)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_AES_256_GCM_SHA384") == "X448"

    def test_dh_ephemeral_key_2048(self):
        ek = _make_ephemeral_key("DH", "", 2048)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384") == "DHE"

    def test_dh_ephemeral_key_1024_weak(self):
        ek = _make_ephemeral_key("DH", "", 1024)
        assert _key_exchange_from_ephemeral_key(ek, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA") == "DHE-1024"

    def test_none_ephemeral_key_is_rsa(self):
        # No ephemeral key = static RSA key exchange
        assert _key_exchange_from_ephemeral_key(None, "TLS_RSA_WITH_AES_256_CBC_SHA") == "RSA"


# ---------------------------------------------------------------------------
# Unit tests — cipher name fallback (legacy TLS 1.2 / no ephemeral key info)
# ---------------------------------------------------------------------------

class TestExtractKeyExchangeFromCipherName:
    def test_ecdhe_rsa_cipher(self):
        assert _extract_key_exchange_from_cipher_name(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        ) == "ECDHE"

    def test_dhe_rsa_cipher(self):
        assert _extract_key_exchange_from_cipher_name(
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        ) == "DHE"

    def test_rsa_key_exchange(self):
        assert _extract_key_exchange_from_cipher_name(
            "TLS_RSA_WITH_AES_256_CBC_SHA"
        ) == "RSA"

    def test_tls13_aes_returns_hkdf_sentinel(self):
        # TLS 1.3 cipher names never encode kex; caller must use ephemeral_key
        assert _extract_key_exchange_from_cipher_name("TLS_AES_256_GCM_SHA384") == "TLS1.3-HKDF"

    def test_tls13_chacha_returns_hkdf_sentinel(self):
        assert _extract_key_exchange_from_cipher_name("TLS_CHACHA20_POLY1305_SHA256") == "TLS1.3-HKDF"


# ---------------------------------------------------------------------------
# Unit tests — PQC detection (cipher names — legacy path)
# ---------------------------------------------------------------------------

class TestPQCCipherCheck:
    def test_no_pqc_in_standard_ciphers(self):
        ciphers = [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]
        hybrid, pqc_only = _check_pqc_in_ciphers(ciphers)
        assert hybrid is False
        assert pqc_only is False

    def test_hybrid_kyber_in_cipher_name(self):
        # Hypothetical cipher name containing KYBER (not real TLS 1.3 but tests the path)
        hybrid, pqc_only = _check_pqc_in_ciphers(["TLS_X25519Kyber768Draft00_AES_256_GCM_SHA384"])
        assert hybrid is True

    def test_pure_kyber_in_cipher_name(self):
        hybrid, pqc_only = _check_pqc_in_ciphers(["TLS_KYBER768_AES_256_GCM_SHA384"])
        assert pqc_only is True

    def test_empty_cipher_list(self):
        hybrid, pqc_only = _check_pqc_in_ciphers([])
        assert hybrid is False
        assert pqc_only is False


# ---------------------------------------------------------------------------
# Unit tests — PQC detection (elliptic curve names — real production path)
# ---------------------------------------------------------------------------

class TestPQCCurveCheck:
    """
    Real TLS 1.3 servers advertising X25519Kyber768 show it in ELLIPTIC_CURVES
    supported_curves, NOT in cipher suite names. These tests validate the primary
    PQC detection path.
    """

    def test_x25519kyber768_in_curves_is_hybrid(self):
        hybrid, pqc_only = _check_pqc_in_curves(["X25519Kyber768", "X25519", "secp256r1"])
        assert hybrid is True
        assert pqc_only is False

    def test_x25519mlkem768_in_curves_is_hybrid(self):
        hybrid, pqc_only = _check_pqc_in_curves(["X25519MLKEM768", "X25519"])
        assert hybrid is True

    def test_kyber_only_curve_is_pqc_only(self):
        hybrid, pqc_only = _check_pqc_in_curves(["Kyber768"])
        assert pqc_only is True
        assert hybrid is False

    def test_standard_curves_no_pqc(self):
        hybrid, pqc_only = _check_pqc_in_curves(["X25519", "secp256r1", "secp384r1"])
        assert hybrid is False
        assert pqc_only is False

    def test_empty_curves_no_pqc(self):
        hybrid, pqc_only = _check_pqc_in_curves([])
        assert hybrid is False
        assert pqc_only is False


class TestDetectHybridStatus:
    def test_no_pqc_ciphers_or_curves(self):
        assert _detect_hybrid_status(["TLS_AES_256_GCM_SHA384"], ["X25519", "secp256r1"]) == "none"

    def test_hybrid_from_curve_names(self):
        assert _detect_hybrid_status(
            ["TLS_AES_256_GCM_SHA384"],
            ["X25519Kyber768", "X25519"],
        ) == "hybrid"

    def test_hybrid_from_cipher_names(self):
        assert _detect_hybrid_status(
            ["TLS_X25519Kyber768_AES_256_GCM_SHA384"],
            [],
        ) == "hybrid"

    def test_full_pqc_from_curve_names(self):
        assert _detect_hybrid_status([], ["Kyber768"]) == "full_pqc"

    def test_curves_none_defaults_safely(self):
        assert _detect_hybrid_status(["TLS_AES_256_GCM_SHA384"]) == "none"


# ---------------------------------------------------------------------------
# Unit tests — NetworkScanner end-to-end (mocked sslyze)
# ---------------------------------------------------------------------------

class TestNetworkScannerProcessing:
    def _scanner(self) -> NetworkScanner:
        return NetworkScanner(timeout=5)

    def test_empty_domain_list_returns_empty(self):
        assert self._scanner().scan_domains([]) == []

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_rsa_tls12_domain_is_vulnerable(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock(
            domain="vulnerable.example.com",
            tls_version="TLS_1_2",
            cert_algo="rsa-2048",
            cipher_name="TLS_RSA_WITH_AES_256_CBC_SHA",
            ephemeral_key=None,  # RSA static kex → no ephemeral
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["vulnerable.example.com"])
        r = results[0]

        assert r.reachable is True
        assert r.tls_version == "TLS_1_2"
        assert r.cert is not None
        assert r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm == "RSA"
        assert r.cert_algorithm_classification.quantum_status == "vulnerable"
        assert r.cert_algorithm_classification.algorithm_risk == 8

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_tls13_key_exchange_from_ephemeral_key_not_cipher_name(self, MockScanner, MockLocation):
        """TLS 1.3: key_exchange_algorithm must come from ephemeral_key, not cipher name."""
        ek = _make_ephemeral_key("ECDH", "X25519", 253)
        mock = _make_scan_result_mock(
            domain="tls13.example.com",
            tls_version="TLS_1_3",
            cert_algo="ec",
            cipher_name="TLS_CHACHA20_POLY1305_SHA256",  # no kex info in name
            ephemeral_key=ek,
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["tls13.example.com"])
        r = results[0]

        # Must use ephemeral_key.curve_name, NOT parse "TLS1.3-HKDF" from cipher name
        assert r.key_exchange_algorithm == "X25519"
        assert r.tls_version == "TLS_1_3"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_pqc_hybrid_detected_from_elliptic_curves(self, MockScanner, MockLocation):
        """
        X25519Kyber768 is detected from ELLIPTIC_CURVES.supported_curves,
        not from cipher suite names (which never contain 'KYBER' in real TLS).
        """
        mock = _make_scan_result_mock(
            domain="modern.example.com",
            tls_version="TLS_1_3",
            cert_algo="ec",
            cipher_name="TLS_AES_256_GCM_SHA384",
            ephemeral_key=_make_ephemeral_key("ECDH", "X25519Kyber768", 1120),
            supported_curves=["X25519Kyber768", "X25519", "secp256r1"],
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["modern.example.com"])
        r = results[0]

        assert r.pqc_hybrid_offered is True
        assert r.hybrid_status == "hybrid"
        assert r.final_algorithm_risk <= 2  # hybrid lowers effective risk

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_no_pqc_when_standard_curves_only(self, MockScanner, MockLocation):
        """Standard curves (X25519, secp256r1) — no PQC detected."""
        mock = _make_scan_result_mock(
            domain="standard.example.com",
            tls_version="TLS_1_3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            supported_curves=["X25519", "secp256r1"],
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["standard.example.com"])
        r = results[0]

        assert r.pqc_hybrid_offered is False
        assert r.hybrid_status == "none"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_tls10_domain_is_deprecated(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock(
            domain="old.example.com",
            tls_version="TLS_1_0",
            cipher_name="TLS_RSA_WITH_AES_128_CBC_SHA",
            ephemeral_key=None,
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["old.example.com"])
        r = results[0]

        assert r.tls_version == "TLS_1_0"
        assert r.tls_version_classification.quantum_status == "deprecated"
        assert r.tls_version_classification.algorithm_risk == 9

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_hndl_risk_false_for_short_shelf_life_domain(self, MockScanner, MockLocation):
        """ECDHE is quantum-vulnerable but HNDL requires long/permanent shelf life.
        api.example.com → infer_shelf_life → 'short' → hndl_risk=False."""
        mock = _make_scan_result_mock(
            domain="api.example.com",
            tls_version="TLS_1_2",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ephemeral_key=_make_ephemeral_key("ECDH", "secp256r1", 256),
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["api.example.com"])
        r = results[0]

        # kex correctly identified
        assert r.key_exchange_algorithm == "ECDHE"
        # HNDL=False because data_shelf_life="short" (not long/permanent)
        assert r.hndl_risk is False
        assert r.data_shelf_life == "short"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_hndl_risk_true_for_long_shelf_life_ecdhe(self, MockScanner, MockLocation):
        """ECDHE + long shelf life domain → hndl_risk=True."""
        mock = _make_scan_result_mock(
            domain="health.records.hospital.com",
            tls_version="TLS_1_2",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ephemeral_key=_make_ephemeral_key("ECDH", "secp256r1", 256),
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["health.records.hospital.com"])
        r = results[0]

        assert r.key_exchange_algorithm == "ECDHE"
        # health.records → infer_shelf_life → "long" → HNDL=True
        assert r.hndl_risk is True
        assert r.data_shelf_life == "long"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_x25519_kex_correctly_identified(self, MockScanner, MockLocation):
        """X25519 key exchange is correctly extracted from ephemeral_key."""
        mock = _make_scan_result_mock(
            domain="tls13.example.com",
            tls_version="TLS_1_3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            ephemeral_key=_make_ephemeral_key("ECDH", "X25519", 253),
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["tls13.example.com"])
        r = results[0]

        assert r.key_exchange_algorithm == "X25519"
        # medium shelf life → HNDL=False
        assert r.hndl_risk is False

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_x25519_hndl_true_for_health_domain(self, MockScanner, MockLocation):
        """X25519 + health domain (long shelf life) → hndl_risk=True."""
        mock = _make_scan_result_mock(
            domain="health.api.hospital.com",
            tls_version="TLS_1_3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            ephemeral_key=_make_ephemeral_key("ECDH", "X25519", 253),
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["health.api.hospital.com"])
        r = results[0]

        assert r.key_exchange_algorithm == "X25519"
        assert r.hndl_risk is True
        assert r.data_shelf_life == "long"

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_recommendations_populated_for_vulnerable_rsa(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock(
            domain="test.example.com",
            tls_version="TLS_1_2",
            cert_algo="rsa-2048",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["test.example.com"])
        r = results[0]

        assert r.recommended_algorithm_cert is not None
        assert "ML-DSA" in r.recommended_algorithm_cert or "ML-KEM" in r.recommended_algorithm_cert

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_connection_failure_returns_unreachable(self, MockScanner, MockLocation):
        failed = MagicMock()
        failed.server_location.hostname = "unreachable.example.com"
        failed.scan_result = None
        failed.connectivity_error_trace = "Connection refused"

        MockScanner.return_value.get_results.return_value = [failed]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["unreachable.example.com"])
        r = results[0]

        assert r.reachable is False
        assert r.error_message is not None

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_final_risk_max_of_cert_kex_and_tls_version(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock(
            domain="risk.example.com",
            tls_version="TLS_1_0",  # deprecated → risk=9
            cert_algo="rsa-2048",   # RSA → risk=8
            cipher_name="TLS_RSA_WITH_AES_128_CBC_SHA",
            ephemeral_key=None,     # RSA key exchange → risk=8
        )
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        results = self._scanner().scan_domains(["risk.example.com"])
        r = results[0]

        # TLS 1.0 risk=9 dominates
        assert r.final_algorithm_risk == 9

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_scan_domain_single_convenience_method(self, MockScanner, MockLocation):
        mock = _make_scan_result_mock("single.example.com")
        MockScanner.return_value.get_results.return_value = [mock]
        MockScanner.return_value.queue_scans.return_value = None

        r = self._scanner().scan_domain("single.example.com")

        assert isinstance(r, DomainScanResult)
        assert r.domain == "single.example.com"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_unreachable_domain_reachable_false(self, MockScanner, MockLocation):
        failed = MagicMock()
        failed.server_location.hostname = "no-such-host.invalid"
        failed.scan_result = None
        failed.connectivity_error_trace = "Name resolution failed"

        MockScanner.return_value.get_results.return_value = [failed]
        MockScanner.return_value.queue_scans.return_value = None

        results = NetworkScanner(timeout=5).scan_domains(["no-such-host.invalid"])
        assert results[0].reachable is False
        assert results[0].error_message is not None

    @patch("scanner.network.ServerNetworkLocation")
    @patch("scanner.network.Scanner")
    def test_timeout_returns_reachable_false(self, MockScanner, MockLocation):
        timed_out = MagicMock()
        timed_out.server_location.hostname = "slow.example.com"
        timed_out.scan_result = None
        timed_out.connectivity_error_trace = "Connection timed out after 10s"

        MockScanner.return_value.get_results.return_value = [timed_out]
        MockScanner.return_value.queue_scans.return_value = None

        results = NetworkScanner(timeout=5).scan_domains(["slow.example.com"])
        assert results[0].reachable is False


# ---------------------------------------------------------------------------
# Algorithm classification via score_component
# ---------------------------------------------------------------------------

class TestAlgorithmClassificationViaScoreComponent:
    def test_rsa_2048_is_vulnerable(self):
        from engines.risk import score_component
        result = score_component(
            component_id="test-rsa",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="internal",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert result.quantum_status == "vulnerable"
        assert result.algorithm_risk == 8

    def test_ml_kem_768_is_safe(self):
        from engines.risk import score_component
        result = score_component(
            component_id="test-mlkem",
            algorithm="ML-KEM-768",
            algorithm_family="ML-KEM",
            algorithm_risk=0,
            quantum_status="safe",
            data_sensitivity="internal",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert result.quantum_status == "safe"
        assert result.algorithm_risk == 0

    def test_tls_1_0_is_deprecated(self):
        from engines.risk import score_component
        result = score_component(
            component_id="test-tls10",
            algorithm="TLS_1_0",
            algorithm_family="TLS",
            algorithm_risk=9,
            quantum_status="deprecated",
            data_sensitivity="internal",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert result.quantum_status == "deprecated"
        assert result.algorithm_risk == 9

    def test_hndl_risk_true_rsa_key_in_tls_cert_confidential(self):
        from engines.risk import score_component
        result = score_component(
            component_id="test-hndl-true",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="tls_cert",
            is_public_facing=True,
        )
        assert result.hndl_risk is True

    def test_hndl_risk_false_rsa_in_code_not_tls(self):
        from engines.risk import score_component
        result = score_component(
            component_id="test-hndl-false",
            algorithm="RSA-2048",
            algorithm_family="RSA",
            algorithm_risk=8,
            quantum_status="vulnerable",
            data_sensitivity="confidential",
            location_type="code",
            is_public_facing=True,
        )
        assert result.hndl_risk is False


# ---------------------------------------------------------------------------
# Domain normalization
# ---------------------------------------------------------------------------

class TestNormalizeDomain:
    def test_strips_https_prefix(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("https://example.com") == "example.com"

    def test_strips_http_prefix(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("http://example.com") == "example.com"

    def test_strips_path(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("https://example.com/api/v1") == "example.com"

    def test_strips_query(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("example.com?foo=bar") == "example.com"

    def test_plain_domain_unchanged(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("api.example.com") == "api.example.com"

    def test_strips_whitespace(self):
        from scanner.network import _normalize_domain
        assert _normalize_domain("  example.com  ") == "example.com"


# ---------------------------------------------------------------------------
# infer_shelf_life
# ---------------------------------------------------------------------------

class TestInferShelfLife:
    def test_auth_domain_is_ephemeral(self):
        assert infer_shelf_life("auth.api.company.com") == "ephemeral"

    def test_login_domain_is_ephemeral(self):
        assert infer_shelf_life("login.example.com") == "ephemeral"

    def test_token_domain_is_ephemeral(self):
        assert infer_shelf_life("token.service.com") == "ephemeral"

    def test_payment_domain_is_long(self):
        assert infer_shelf_life("payment.razorpay.com") == "long"

    def test_billing_domain_is_long(self):
        assert infer_shelf_life("billing.stripe.com") == "long"

    def test_fintech_domain_is_long(self):
        assert infer_shelf_life("api.fintech.com") == "long"

    def test_banking_domain_is_long(self):
        assert infer_shelf_life("api.banking.hdfc.com") == "long"

    def test_health_domain_is_long(self):
        assert infer_shelf_life("health.records.hospital.com") == "long"

    def test_generic_api_is_short(self):
        assert infer_shelf_life("api.example.com") == "short"

    def test_example_com_is_short(self):
        assert infer_shelf_life("example.com") == "short"


# ---------------------------------------------------------------------------
# Integration tests — real domains, verified against fixture JSON
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestNetworkScannerIntegration:
    """
    Hit real TLS endpoints. Results validated against fixture files in
    tests/fixtures/sslyze/. Run with:
        pytest tests/test_network_scanner.py -m integration
    """

    def _load_fixture(self, filename: str) -> dict:
        return json.loads((FIXTURES / filename).read_text())

    def _run(self, domain: str) -> DomainScanResult:
        return NetworkScanner(timeout=15, per_domain_timeout=45).scan_domain(domain)

    def test_rsa2048_badssl(self):
        fx = self._load_fixture("rsa2048_badssl_com.json")
        ex = fx["expected"]
        r = self._run(fx["domain"])

        assert r.reachable is True
        assert r.cert is not None
        assert r.cert.algorithm == ex["cert_algorithm"]
        assert r.cert.key_size == ex["cert_key_size"]
        assert r.cert_expired == ex["cert_expired"]
        assert r.key_exchange_algorithm == ex["key_exchange_algorithm"]
        assert r.tls_version == ex["tls_version"]
        assert r.hybrid_status == ex["hybrid_status"]
        assert r.pqc_hybrid_offered == ex["pqc_hybrid_offered"]
        assert r.hndl_risk == ex["hndl_risk"]
        assert r.final_algorithm_risk == ex["final_algorithm_risk"]
        assert r.quantum_status == ex["quantum_status"]
        assert "TLS_1_0" in r.supported_tls_versions  # legacy TLS still accepted

    def test_ecc256_badssl(self):
        fx = self._load_fixture("ecc256_badssl_com.json")
        ex = fx["expected"]
        r = self._run(fx["domain"])

        assert r.reachable is True
        assert r.cert.algorithm == ex["cert_algorithm"]
        assert r.cert.key_size == ex["cert_key_size"]
        assert r.cert_expired is False
        assert r.key_exchange_algorithm == ex["key_exchange_algorithm"]
        assert r.hybrid_status == ex["hybrid_status"]
        assert r.pqc_hybrid_offered == ex["pqc_hybrid_offered"]
        assert r.hndl_risk == ex["hndl_risk"]
        assert r.final_algorithm_risk == ex["final_algorithm_risk"]

    def test_expired_badssl(self):
        fx = self._load_fixture("expired_badssl_com.json")
        ex = fx["expected"]
        r = self._run(fx["domain"])

        assert r.reachable is True
        assert r.cert_expired is True  # core assertion — must detect expired cert
        assert r.cert.algorithm == ex["cert_algorithm"]
        assert r.threat_timeline == ex["threat_timeline"]

    def test_tls10_badssl_supports_legacy_tls(self):
        fx = self._load_fixture("tls10_badssl_com.json")
        ex = fx["expected"]
        r = self._run(fx["domain"])

        assert r.reachable is True
        assert r.cert.algorithm == ex["cert_algorithm"]
        assert r.hndl_risk == ex["hndl_risk"]
        # Server supports TLS 1.0 even if it also supports higher versions
        assert "TLS_1_0" in r.supported_tls_versions

    def test_unreachable_domain_returns_gracefully(self):
        r = NetworkScanner(timeout=5, per_domain_timeout=10).scan_domain(
            "this-domain-absolutely-does-not-exist-xyzzy.invalid", port=443
        )
        assert r.reachable is False
        assert r.error_message is not None

    def test_scan_multiple_domains_all_return(self):
        scanner = NetworkScanner(timeout=15, per_domain_timeout=45, max_workers=3)
        domains = ["rsa2048.badssl.com", "ecc256.badssl.com"]
        results = scanner.scan_domains(domains)

        assert len(results) == 2
        domain_set = {r.domain for r in results}
        assert domain_set == set(domains)
        assert all(r.reachable for r in results)
