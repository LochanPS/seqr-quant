"""Tests for direct-TLS service scanning: MongoDB, AMQP (RabbitMQ), gRPC-over-TLS.

These services speak TLS immediately on connect (no STARTTLS upgrade), so they reuse
the same direct-TLS analysis path as "https" — only the default port differs (and gRPC
offers an h2 ALPN in the active probe). See scanner.network._DIRECT_TLS_PROTOCOLS.

Unit tests mock sslyze (no network). Integration tests either hit a real public gRPC/TLS
endpoint or spin a throwaway self-signed TLS server on the service's default port; run with:
    pytest tests/test_direct_tls_protocols.py -m integration
"""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

from scanner.network import NetworkScanner, _DIRECT_TLS_PROTOCOLS, _STARTTLS_UPGRADE_PROTOCOLS

# Reuse the sslyze ServerScanResult mock builder from the main scanner test module.
from tests.test_network_scanner import _make_scan_result_mock


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestDirectTlsRegistry:
    def test_default_ports(self):
        assert _DIRECT_TLS_PROTOCOLS["mongodb"][0] == 27017
        assert _DIRECT_TLS_PROTOCOLS["amqp"][0] == 5671
        assert _DIRECT_TLS_PROTOCOLS["grpc"][0] == 443

    def test_only_grpc_offers_alpn_h2(self):
        assert _DIRECT_TLS_PROTOCOLS["grpc"][1] == "h2"
        assert _DIRECT_TLS_PROTOCOLS["mongodb"][1] is None
        assert _DIRECT_TLS_PROTOCOLS["amqp"][1] is None

    def test_mysql_not_direct_tls(self):
        # MySQL is NOT direct-TLS — its TLS is a mid-handshake upgrade sslyze cannot drive.
        # It lives in the STARTTLS-upgrade registry instead, handled by scanner.mysql_probe.
        assert "mysql" not in _DIRECT_TLS_PROTOCOLS
        assert _STARTTLS_UPGRADE_PROTOCOLS["mysql"] == (3306, "mysql")


# ---------------------------------------------------------------------------
# Unit — mocked sslyze end-to-end, one per protocol
# ---------------------------------------------------------------------------

class TestDirectTlsMocked:
    def _scan(self, protocol: str):
        mock = _make_scan_result_mock(
            domain="svc.example.com",
            tls_version="TLS_1_3",
            cert_algo="rsa-2048",
            cipher_name="TLS_AES_256_GCM_SHA384",
        )
        with (
            patch("scanner.network.Scanner") as MockScanner,
            patch("scanner.network.ServerNetworkLocation"),
        ):
            MockScanner.return_value.get_results.return_value = [mock]
            MockScanner.return_value.queue_scans.return_value = None
            return NetworkScanner(timeout=5).scan_domain("svc.example.com", protocol=protocol)

    def test_mongodb_defaults_to_27017_and_extracts_cert(self):
        r = self._scan("mongodb")
        assert r.port == 27017
        assert r.reachable is True
        assert r.tls_version == "TLS_1_3"
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm == "X25519"

    def test_amqp_defaults_to_5671_and_extracts_cert(self):
        r = self._scan("amqp")
        assert r.port == 5671
        assert r.reachable is True
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm == "X25519"

    def test_grpc_defaults_to_443_and_extracts_cert(self):
        r = self._scan("grpc")
        assert r.port == 443
        assert r.reachable is True
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm == "X25519"

    def test_explicit_port_overrides_default(self):
        # A non-default port passed by the caller must win over the registry default.
        mock = _make_scan_result_mock(domain="svc.example.com", tls_version="TLS_1_3")
        with (
            patch("scanner.network.Scanner") as MockScanner,
            patch("scanner.network.ServerNetworkLocation"),
        ):
            MockScanner.return_value.get_results.return_value = [mock]
            MockScanner.return_value.queue_scans.return_value = None
            r = NetworkScanner(timeout=5).scan_domain(
                "svc.example.com", port=28017, protocol="mongodb"
            )
        assert r.port == 28017


# ---------------------------------------------------------------------------
# Integration — real handshakes
# ---------------------------------------------------------------------------

def _self_signed_cert() -> tuple[str, str]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    d = tempfile.mkdtemp()
    cp = os.path.join(d, "c.pem")
    kp = os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cp, kp


class _LocalTlsServer:
    """A throwaway TLS server that accepts a handshake and closes — enough for
    sslyze to fetch the cert and negotiate a group. Direct TLS (no STARTTLS)."""

    def __init__(self, port: int, certfile: str, keyfile: str):
        self.port = port
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(20)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                tls.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    def __enter__(self):
        self._thread.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            self._sock.close()
        except Exception:
            pass


@pytest.mark.integration
class TestDirectTlsIntegration:
    def test_grpc_over_tls_public_endpoint(self):
        # grpcb.in serves gRPC-over-TLS on 443 (public test server).
        r = NetworkScanner(timeout=15).scan_domain("grpcb.in", protocol="grpc")
        if not r.reachable:
            pytest.skip(f"grpcb.in unreachable: {r.error_message}")
        assert r.port == 443
        assert r.tls_version in ("TLS_1_2", "TLS_1_3")
        assert r.cert is not None and r.cert.algorithm

    def test_mongodb_direct_tls_local_server(self):
        cp, kp = _self_signed_cert()
        with _LocalTlsServer(27017, cp, kp):
            r = NetworkScanner(timeout=10).scan_domain("localhost", protocol="mongodb")
        assert r.reachable is True
        assert r.port == 27017            # default MongoDB TLS port picked automatically
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm  # a group was negotiated

    def test_amqp_direct_tls_local_server(self):
        cp, kp = _self_signed_cert()
        with _LocalTlsServer(5671, cp, kp):
            r = NetworkScanner(timeout=10).scan_domain("localhost", protocol="amqp")
        assert r.reachable is True
        assert r.port == 5671             # default AMQPS port picked automatically
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.key_exchange_algorithm


# ===========================================================================
# MySQL — STARTTLS-style mid-handshake TLS upgrade (scanner.mysql_probe)
# ===========================================================================

def _rsa_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "db.example.com")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestMysqlProbeUnit:
    """Unit-test the MySQL protocol framing directly (no network)."""

    def test_parse_initial_handshake_reads_capabilities(self):
        from scanner.mysql_probe import _parse_initial_handshake, CLIENT_SSL

        payload = bytearray(b"\x0a")            # protocol v10
        payload += b"8.0.34\x00"                # server version
        payload += (7).to_bytes(4, "little")    # thread id
        payload += bytes(8)                     # auth-plugin-data-1
        payload += b"\x00"                      # filler
        payload += (CLIENT_SSL & 0xFFFF).to_bytes(2, "little")  # cap lower (has SSL bit)
        payload += bytes([45])                  # charset
        payload += (2).to_bytes(2, "little")    # status
        payload += (0).to_bytes(2, "little")    # cap upper
        payload += bytes(13)
        caps, ver, err = _parse_initial_handshake(bytes(payload))
        assert err == ""
        assert ver == "8.0.34"
        assert caps & CLIENT_SSL

    def test_parse_initial_handshake_rejects_err_packet(self):
        from scanner.mysql_probe import _parse_initial_handshake

        # 0xFF marks an ERR packet (e.g. host not allowed to connect).
        caps, ver, err = _parse_initial_handshake(b"\xff\x69\x04Host blocked")
        assert caps == 0 and "mysql error" in err

    def test_parse_initial_handshake_rejects_wrong_version(self):
        from scanner.mysql_probe import _parse_initial_handshake

        caps, ver, err = _parse_initial_handshake(b"\x09rest")
        assert caps == 0 and "protocol version" in err

    def test_ssl_request_packet_shape(self):
        from scanner.mysql_probe import _ssl_request_packet, CLIENT_SSL

        pkt = _ssl_request_packet(1)
        length = int.from_bytes(pkt[:3], "little")
        assert length == 32 and pkt[3] == 1        # 32-byte body, sequence id echoed
        flags = int.from_bytes(pkt[4:8], "little")
        assert flags & CLIENT_SSL                  # SSL flag set → triggers the upgrade
        assert len(pkt) == 36                       # 4-byte header + 32-byte body


class _FakeMysqlTlsServer:
    """A throwaway MySQL server: sends a v10 handshake advertising CLIENT_SSL, reads the
    client's SSLRequest, then completes a real TLS handshake — enough to exercise the whole
    mysql_probe path end-to-end. Set ssl_capable=False to model a MySQL with TLS disabled."""

    CLIENT_SSL = 0x0800
    CLIENT_PROTOCOL_41 = 0x0200

    def __init__(self, port, certfile, keyfile, ssl_capable=True):
        self.port = port
        self.ssl_capable = ssl_capable
        self._certfile, self._keyfile = certfile, keyfile
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(5)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _handshake(self):
        caps = self.CLIENT_PROTOCOL_41 | (self.CLIENT_SSL if self.ssl_capable else 0)
        p = bytearray(b"\x0a")
        p += b"8.0.34-fake\x00"
        p += (1).to_bytes(4, "little")
        p += bytes(8) + b"\x00"
        p += (caps & 0xFFFF).to_bytes(2, "little")
        p += bytes([45]) + (2).to_bytes(2, "little")
        p += ((caps >> 16) & 0xFFFF).to_bytes(2, "little")
        p += bytes(13)
        return bytes(p)

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            try:
                pl = self._handshake()
                conn.sendall(len(pl).to_bytes(3, "little") + b"\x00" + pl)  # seq 0
                hdr = conn.recv(4)
                if hdr:
                    conn.recv(int.from_bytes(hdr[:3], "little"))  # drain SSLRequest
                if self.ssl_capable:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self._certfile, self._keyfile)
                    try:
                        tls = ctx.wrap_socket(conn, server_side=True)
                        tls.close()
                    except Exception:
                        conn.close()
                else:
                    conn.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    def __enter__(self):
        self._thread.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            self._sock.close()
        except Exception:
            pass


class TestMysqlMocked:
    def test_scan_builds_result_from_probe(self):
        from scanner.mysql_probe import MysqlTlsProbeResult

        fake = MysqlTlsProbeResult(
            reachable=True, outcome="success", ssl_supported=True,
            tls_version="TLS_1_3", cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange=None, leaf_cert_der=_rsa_cert_der(),
            server_version="8.0.34", ip="10.0.0.5",
        )
        with patch("scanner.mysql_probe.probe_mysql_tls", return_value=fake):
            r = NetworkScanner(timeout=5, active_pqc=False).scan_domain("db.example.com", protocol="mysql")
        assert r.reachable is True
        assert r.port == 3306                        # default MySQL port picked automatically
        assert r.scan_outcome == "success"
        assert r.tls_version == "TLS_1_3"
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.cert_algorithm == "RSA-2048"
        assert r.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert r.classifications                     # CBOM-shaped output populated
        assert r.deployment_level_name               # context computed

    def test_scan_reports_ssl_disabled(self):
        from scanner.mysql_probe import MysqlTlsProbeResult

        fake = MysqlTlsProbeResult(
            reachable=True, outcome="ssl_not_supported", ssl_supported=False,
            server_version="5.7", error="server does not advertise CLIENT_SSL",
        )
        with patch("scanner.mysql_probe.probe_mysql_tls", return_value=fake):
            r = NetworkScanner(timeout=5).scan_domain("db.example.com", protocol="mysql")
        assert r.reachable is True
        assert r.scan_outcome == "ssl_not_supported"
        assert r.cert is None

    def test_explicit_port_overrides_default(self):
        from scanner.mysql_probe import MysqlTlsProbeResult

        fake = MysqlTlsProbeResult(reachable=True, outcome="success", tls_version="TLS_1_2",
                                   leaf_cert_der=_rsa_cert_der())
        with patch("scanner.mysql_probe.probe_mysql_tls", return_value=fake):
            r = NetworkScanner(timeout=5, active_pqc=False).scan_domain(
                "db.example.com", port=13306, protocol="mysql"
            )
        assert r.port == 13306


@pytest.mark.integration
class TestMysqlIntegration:
    def test_mysql_tls_upgrade_local_server(self):
        cp, kp = _self_signed_cert()
        with _FakeMysqlTlsServer(13306, cp, kp):
            r = NetworkScanner(timeout=10, active_pqc=False).scan_domain(
                "localhost", port=13306, protocol="mysql"
            )
        assert r.reachable is True
        assert r.scan_outcome == "success"
        assert r.tls_version in ("TLS_1_2", "TLS_1_3")
        assert r.cert is not None and r.cert.algorithm == "RSA"
        assert r.cipher_suite

    def test_mysql_ssl_disabled_server(self):
        cp, kp = _self_signed_cert()
        with _FakeMysqlTlsServer(13307, cp, kp, ssl_capable=False):
            r = NetworkScanner(timeout=10).scan_domain(
                "localhost", port=13307, protocol="mysql"
            )
        assert r.reachable is True
        assert r.scan_outcome == "ssl_not_supported"
