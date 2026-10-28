"""MySQL-over-TLS probe — drives the MySQL protocol's mid-handshake TLS upgrade.

MySQL is **not** a direct-TLS service (unlike MongoDB/AMQP/gRPC) and it has no line-based
STARTTLS command sslyze can drive. Instead the client:

1. reads the server's initial Handshake packet (protocol v10) and checks the ``CLIENT_SSL``
   capability bit,
2. replies with an ``SSLRequest`` packet (a 32-byte truncated HandshakeResponse41 with the
   ``CLIENT_SSL`` flag set and **no** credentials),
3. then begins the TLS handshake on the very same socket.

Reference: MySQL client/server protocol, "Connection Phase" / "Protocol::SSLRequest".
This module completes exactly that sequence, then reads the negotiated TLS version, cipher
and the server certificate — the same crypto inventory the sslyze path produces for other
protocols. It authenticates *nothing*: the handshake carries no username/password, so it
never logs in. Active PQC group detection is left to :func:`scanner.pqc_probe.probe_active_pqc`
with ``starttls="mysql"`` (OpenSSL ``s_client -starttls mysql`` drives the same upgrade).

Fail-safe: every failure maps to a scan outcome; the probe never raises into the scan flow.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Optional

# MySQL capability flags (subset we need).
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_SECURE_CONNECTION = 0x00008000

_CHARSET_UTF8MB4 = 45
_MAX_PACKET = 0xFFFFFF

_TLS_VERSION_LABELS = {
    "TLSv1.3": "TLS_1_3",
    "TLSv1.2": "TLS_1_2",
    "TLSv1.1": "TLS_1_1",
    "TLSv1": "TLS_1_0",
    "TLSv1.0": "TLS_1_0",
    "SSLv3": "SSL_3_0",
}


@dataclass
class MysqlTlsProbeResult:
    reachable: bool
    outcome: str                       # success | ssl_not_supported | mysql_error | not_mysql |
                                       # timeout | connection_refused | ssl_error | dns_failure | unknown_error
    ssl_supported: bool = False        # server advertised CLIENT_SSL
    tls_version: Optional[str] = None  # scanner label, e.g. "TLS_1_3"
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None # best-effort (TLS 1.2 name heuristic; None for 1.3)
    leaf_cert_der: Optional[bytes] = None
    server_version: str = ""           # MySQL server version banner
    ip: Optional[str] = None
    error: Optional[str] = None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-packet")
        buf += chunk
    return buf


def _read_packet(sock: socket.socket) -> tuple[int, bytes]:
    """Read one MySQL protocol packet → (sequence_id, payload)."""
    header = _recv_exact(sock, 4)
    length = int.from_bytes(header[:3], "little")
    seq = header[3]
    payload = _recv_exact(sock, length) if length else b""
    return seq, payload


def _parse_initial_handshake(payload: bytes) -> tuple[int, str, str]:
    """Return (capability_flags, server_version, error) from a v10 Handshake payload.

    ``error`` is non-empty if the packet is not a usable v10 handshake (ERR packet, or an
    unsupported protocol version) — the caller turns that into a scan outcome.
    """
    if not payload:
        return 0, "", "empty handshake"
    if payload[0] == 0xFF:  # ERR packet — server refused the connection outright
        msg = payload[3:].decode("utf-8", "replace") if len(payload) > 3 else "server error"
        return 0, "", f"mysql error: {msg}"
    if payload[0] != 0x0A:  # only protocol version 10 is supported
        return 0, "", f"unsupported MySQL protocol version {payload[0]}"

    i = 1
    end = payload.find(b"\x00", i)
    if end == -1:
        return 0, "", "malformed handshake (server version)"
    server_version = payload[i:end].decode("utf-8", "replace")
    i = end + 1
    # thread_id(4) + auth_plugin_data_part_1(8) + filler(1)
    i += 4 + 8 + 1
    if i + 2 > len(payload):
        return 0, server_version, "malformed handshake (capabilities)"
    cap_lower = int.from_bytes(payload[i:i + 2], "little")
    i += 2
    cap_upper = 0
    # character_set(1) + status_flags(2) then capability_flags_upper(2)
    if i + 1 + 2 + 2 <= len(payload):
        i += 1 + 2  # skip charset + status flags
        cap_upper = int.from_bytes(payload[i:i + 2], "little")
    capabilities = cap_lower | (cap_upper << 16)
    return capabilities, server_version, ""


def _ssl_request_packet(seq: int) -> bytes:
    """Build the 32-byte SSLRequest (truncated HandshakeResponse41, no credentials)."""
    flags = CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD
    body = (
        flags.to_bytes(4, "little")
        + _MAX_PACKET.to_bytes(4, "little")
        + bytes([_CHARSET_UTF8MB4])
        + b"\x00" * 23
    )
    header = len(body).to_bytes(3, "little") + bytes([seq])
    return header + body


def _key_exchange_from_cipher(tls_version: str, cipher_name: str) -> Optional[str]:
    """Best-effort KEX for TLS 1.2 from the cipher name; None for 1.3 (group not exposed)."""
    if tls_version == "TLS_1_3":
        return None
    name = (cipher_name or "").upper()
    if "ECDHE" in name:
        return "ECDHE"
    if "DHE" in name:
        return "DHE"
    if name.startswith("AES") or "RSA" in name:
        return "RSA"
    return None


def probe_mysql_tls(host: str, port: int = 3306, timeout: float = 10.0) -> MysqlTlsProbeResult:
    """Complete the MySQL TLS upgrade against ``host:port`` and read the TLS crypto.

    Never raises — returns a :class:`MysqlTlsProbeResult` describing what happened.
    """
    ip = None
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        if infos:
            ip = infos[0][4][0]
    except socket.gaierror as exc:
        return MysqlTlsProbeResult(reachable=False, outcome="dns_failure", error=str(exc))

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((host, port))
    except socket.timeout:
        raw.close()
        return MysqlTlsProbeResult(reachable=False, outcome="timeout", ip=ip, error="connect timed out")
    except ConnectionRefusedError:
        raw.close()
        return MysqlTlsProbeResult(reachable=False, outcome="connection_refused", ip=ip)
    except OSError as exc:
        raw.close()
        return MysqlTlsProbeResult(reachable=False, outcome="unknown_error", ip=ip, error=str(exc))

    try:
        seq, payload = _read_packet(raw)
        capabilities, server_version, err = _parse_initial_handshake(payload)
        if err:
            outcome = "mysql_error" if "mysql error" in err else "not_mysql"
            return MysqlTlsProbeResult(
                reachable=True, outcome=outcome, ip=ip, server_version=server_version, error=err
            )
        if not capabilities & CLIENT_SSL:
            return MysqlTlsProbeResult(
                reachable=True, outcome="ssl_not_supported", ip=ip, ssl_supported=False,
                server_version=server_version,
                error="server does not advertise CLIENT_SSL (TLS disabled on this MySQL)",
            )

        # Send SSLRequest (sequence id = server's + 1), then upgrade to TLS on the socket.
        raw.sendall(_ssl_request_packet(seq + 1))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # inventory, not trust validation — we read what's served
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLError as exc:
            return MysqlTlsProbeResult(
                reachable=True, outcome="ssl_error", ip=ip, ssl_supported=True,
                server_version=server_version, error=f"TLS handshake failed: {exc}",
            )

        try:
            raw_version = tls.version() or ""
            tls_version = _TLS_VERSION_LABELS.get(raw_version, raw_version or None)
            cipher = tls.cipher()
            cipher_suite = cipher[0] if cipher else None
            leaf_der = tls.getpeercert(binary_form=True)
        finally:
            try:
                tls.close()
            except OSError:
                pass

        return MysqlTlsProbeResult(
            reachable=True, outcome="success", ip=ip, ssl_supported=True,
            tls_version=tls_version, cipher_suite=cipher_suite,
            key_exchange=_key_exchange_from_cipher(tls_version or "", cipher_suite or ""),
            leaf_cert_der=leaf_der, server_version=server_version,
        )
    except (socket.timeout, ConnectionError) as exc:
        return MysqlTlsProbeResult(reachable=True, outcome="ssl_error", ip=ip, error=str(exc))
    except OSError as exc:
        return MysqlTlsProbeResult(reachable=True, outcome="unknown_error", ip=ip, error=str(exc))
    finally:
        try:
            raw.close()
        except OSError:
            pass
