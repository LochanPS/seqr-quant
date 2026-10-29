"""Tests for active PQC detection probe (scanner/pqc_probe.py).

All subprocess calls are mocked — no real network or openssl invocation.
"""
import subprocess
import types
from unittest.mock import patch

from scanner.pqc_probe import PqcProbeResult, probe_active_pqc


def _cp(stdout="", stderr=""):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)


_WIRE = PqcProbeResult(True, True, True, "X25519MLKEM768", "wire")


def test_no_openssl_falls_back_to_wire_probe():
    with (
        patch("scanner.pqc_probe.shutil.which", return_value=None),
        patch("scanner.wire_probe.probe_wire_pqc", return_value=_WIRE) as wire,
    ):
        r = probe_active_pqc("example.com", alpn="h2")
    assert r is _WIRE
    wire.assert_called_once_with("example.com", 443, timeout=10.0, alpn="h2")


def test_no_openssl_starttls_stays_unavailable():
    with (
        patch("scanner.pqc_probe.shutil.which", return_value=None),
        patch("scanner.wire_probe.probe_wire_pqc") as wire,
    ):
        r = probe_active_pqc("mail.example.com", 25, starttls="smtp")
    assert r.available is False and r.probed is False and r.supported is False
    wire.assert_not_called()


def test_old_openssl_falls_back_to_wire_probe():
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", return_value=_cp(stdout="OpenSSL 3.0.13 30 Jan 2024")),
        patch("scanner.wire_probe.probe_wire_pqc", return_value=_WIRE),
    ):
        r = probe_active_pqc("example.com")
    assert r is _WIRE


def test_detects_hybrid_pqc_group():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="CONNECTED\nNegotiated TLS1.3 group: X25519MLKEM768\n")
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=[version, sclient]),
    ):
        r = probe_active_pqc("pq.example.com")
    assert r.available is True
    assert r.probed is True
    assert r.supported is True
    assert r.negotiated_group == "X25519MLKEM768"


def test_classical_only_server_not_supported():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="CONNECTED\nNegotiated TLS1.3 group: X25519\n")
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=[version, sclient]),
    ):
        r = probe_active_pqc("classical.example.com")
    assert r.available is True
    assert r.probed is True
    assert r.supported is False
    assert r.negotiated_group == "X25519"


def test_no_group_line_means_handshake_failed():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="CONNECTED\n", stderr="errno=104 connection reset\n")
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=[version, sclient]),
    ):
        r = probe_active_pqc("broken.example.com")
    assert r.available is True
    assert r.probed is True
    assert r.supported is False
    assert r.negotiated_group == ""


def test_timeout_is_handled():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch(
            "scanner.pqc_probe.subprocess.run",
            side_effect=[version, subprocess.TimeoutExpired(cmd="openssl", timeout=10)],
        ),
    ):
        r = probe_active_pqc("slow.example.com")
    assert r.available is True
    assert r.probed is False
    assert r.supported is False


def test_secp256r1_mlkem_also_detected():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="Negotiated TLS1.3 group: SecP256r1MLKEM768\n")
    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=[version, sclient]),
    ):
        r = probe_active_pqc("aws.example.com")
    assert r.supported is True
    assert r.negotiated_group == "SecP256r1MLKEM768"


def test_starttls_adds_flag_to_command():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="Negotiated TLS1.3 group: X25519MLKEM768\n")
    captured = {}

    def _run(cmd, *a, **k):
        if "s_client" in cmd:
            captured["cmd"] = cmd
            return sclient
        return version

    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=_run),
    ):
        r = probe_active_pqc("smtp.example.com", 587, starttls="smtp")
    assert r.supported is True
    assert "-starttls" in captured["cmd"]
    assert "smtp" in captured["cmd"]


def test_no_starttls_flag_when_none():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="Negotiated TLS1.3 group: X25519\n")
    captured = {}

    def _run(cmd, *a, **k):
        if "s_client" in cmd:
            captured["cmd"] = cmd
            return sclient
        return version

    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=_run),
    ):
        probe_active_pqc("example.com")
    assert "-starttls" not in captured["cmd"]


def test_alpn_adds_flag_to_command():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="Negotiated TLS1.3 group: X25519MLKEM768\n")
    captured = {}

    def _run(cmd, *a, **k):
        if "s_client" in cmd:
            captured["cmd"] = cmd
            return sclient
        return version

    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=_run),
    ):
        r = probe_active_pqc("grpc.example.com", 443, alpn="h2")
    assert r.supported is True
    assert "-alpn" in captured["cmd"]
    assert "h2" in captured["cmd"]


def test_no_alpn_flag_when_none():
    version = _cp(stdout="OpenSSL 3.5.6 1 Jul 2025")
    sclient = _cp(stdout="Negotiated TLS1.3 group: X25519\n")
    captured = {}

    def _run(cmd, *a, **k):
        if "s_client" in cmd:
            captured["cmd"] = cmd
            return sclient
        return version

    with (
        patch("scanner.pqc_probe.shutil.which", return_value="/usr/bin/openssl"),
        patch("scanner.pqc_probe.subprocess.run", side_effect=_run),
    ):
        probe_active_pqc("example.com")
    assert "-alpn" not in captured["cmd"]


def test_wrapped_protocol_map():
    from scanner.network import _WRAPPED_PROTOCOLS
    assert _WRAPPED_PROTOCOLS["smtp"][1] == 587
    assert _WRAPPED_PROTOCOLS["imap"][1] == 143
    assert _WRAPPED_PROTOCOLS["pop3"][1] == 110
    assert _WRAPPED_PROTOCOLS["postgres"][1] == 5432
    # openssl -starttls names present
    assert _WRAPPED_PROTOCOLS["smtp"][2] == "smtp"


def test_direct_tls_protocol_map():
    from scanner.network import _DIRECT_TLS_PROTOCOLS
    assert _DIRECT_TLS_PROTOCOLS["mongodb"][0] == 27017
    assert _DIRECT_TLS_PROTOCOLS["amqp"][0] == 5671
    assert _DIRECT_TLS_PROTOCOLS["grpc"] == (443, "h2")
