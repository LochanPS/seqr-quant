"""
SSH cryptographic posture scanner.

Reads a server's SSH_MSG_KEXINIT (sent before authentication) to inventory its
key-exchange and host-key algorithms — no credentials, no login attempt, purely
the algorithm negotiation that any client sees. This is the SSH analogue of the
TLS scan: it tells you whether an SSH endpoint offers post-quantum key exchange
(OpenSSH 9.x: mlkem768x25519-sha256, sntrup761x25519-sha512) and what its host
key algorithm is (still classical everywhere: ssh-ed25519, ssh-rsa, ecdsa-*).

Pure-Python sockets; the name-list parsing is a separate pure function so it can
be unit-tested without a network.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

_SSH_MSG_KEXINIT = 20

# Post-quantum / hybrid SSH key-exchange method names (OpenSSH + libssh).
_PQC_KEX = {
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
}

# KEXINIT name-list fields, in wire order.
_NAMELIST_FIELDS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


@dataclass
class SshScanResult:
    host: str
    port: int
    reachable: bool
    server_banner: str = ""
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    pqc_kex_supported: bool = False
    pqc_kex_methods: list[str] = field(default_factory=list)
    host_key_quantum_status: str = "unknown"   # vulnerable | safe | unknown
    error_message: str = ""


def parse_kexinit_namelists(payload: bytes) -> dict[str, list[str]]:
    """
    Parse the name-lists out of a raw SSH_MSG_KEXINIT *payload*.

    payload[0]      = message code (20)
    payload[1:17]   = 16-byte cookie
    then 10 name-lists, each: uint32 length + comma-separated ASCII.

    Raises ValueError on a malformed / non-KEXINIT payload.
    """
    if not payload or payload[0] != _SSH_MSG_KEXINIT:
        raise ValueError("not a KEXINIT payload")
    off = 1 + 16  # skip message code + cookie
    out: dict[str, list[str]] = {}
    for field_name in _NAMELIST_FIELDS:
        if off + 4 > len(payload):
            raise ValueError(f"truncated before {field_name}")
        (length,) = struct.unpack(">I", payload[off:off + 4])
        off += 4
        if off + length > len(payload):
            raise ValueError(f"truncated name-list {field_name}")
        raw = payload[off:off + length].decode("ascii", errors="replace")
        off += length
        out[field_name] = [s for s in raw.split(",") if s]
    return out


def _classify_host_key(host_key_algs: list[str]) -> str:
    """All current SSH host-key types are quantum-vulnerable signatures."""
    if not host_key_algs:
        return "unknown"
    # No standardised PQC SSH host-key (signature) algorithm is deployed yet.
    return "vulnerable"


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-read")
        buf += chunk
    return buf


def _read_server_banner(sock: socket.socket) -> str:
    """Read lines until the SSH identification string (servers may send pre-banner lines)."""
    data = b""
    while b"\n" not in data or not any(
        line.startswith(b"SSH-") for line in data.split(b"\r\n")
    ):
        chunk = sock.recv(512)
        if not chunk:
            break
        data += chunk
        if len(data) > 8192:
            break
    for line in data.replace(b"\r\n", b"\n").split(b"\n"):
        if line.startswith(b"SSH-"):
            return line.decode("ascii", errors="replace")
    return data.split(b"\n")[0].decode("ascii", errors="replace")


def scan_ssh(host: str, port: int = 22, timeout: float = 10.0) -> SshScanResult:
    """
    Connect to an SSH server and inventory its offered algorithms from KEXINIT.
    Never raises — returns an SshScanResult with reachable=False on failure.
    """
    result = SshScanResult(host=host, port=port, reachable=False)
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        result.server_banner = _read_server_banner(sock)
        # Send our identification string (required before the server proceeds).
        sock.sendall(b"SSH-2.0-SeQr_Scanner\r\n")

        # Read the binary KEXINIT packet: uint32 packet_length, byte padding_length, payload, padding.
        header = _recv_exact(sock, 4)
        (packet_length,) = struct.unpack(">I", header)
        if not (1 < packet_length < 100000):
            result.error_message = f"implausible SSH packet length {packet_length}"
            return result
        body = _recv_exact(sock, packet_length)
        padding_length = body[0]
        payload = body[1:packet_length - padding_length]

        namelists = parse_kexinit_namelists(payload)
        result.reachable = True
        result.kex_algorithms = namelists.get("kex_algorithms", [])
        result.host_key_algorithms = namelists.get("server_host_key_algorithms", [])
        result.pqc_kex_methods = [k for k in result.kex_algorithms if k in _PQC_KEX]
        result.pqc_kex_supported = bool(result.pqc_kex_methods)
        result.host_key_quantum_status = _classify_host_key(result.host_key_algorithms)
        return result
    except (OSError, ValueError, ConnectionError) as exc:
        result.error_message = str(exc)
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
