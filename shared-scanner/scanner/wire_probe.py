"""
Wire-level TLS 1.3 hybrid post-quantum key-exchange probe (no OpenSSL 3.5 needed).

`pqc_probe` drives an OpenSSL 3.5+ binary to offer ML-KEM groups. Most laptops and
Windows hosts ship an older OpenSSL, where that probe is unavailable and scans fall
back to passive results, which cannot see hybrid support at all.

This module speaks just enough TLS 1.3 itself: it sends one ClientHello whose only
key share is X25519MLKEM768 (codepoint 0x11EC, draft-ietf-tls-ecdhe-mlkem) and
reads the server's first handshake message:

- ServerHello with key_share group 0x11EC  -> the server negotiated hybrid ML-KEM.
- HelloRetryRequest naming another group    -> the server does not prefer/support it
                                                (if that group is itself a PQC hybrid,
                                                it still counts as supported).
- handshake_failure alert / TLS 1.2 reply   -> no PQC key exchange.

The ML-KEM-768 encapsulation key we send is well-formed (every coefficient < q,
so it passes the FIPS 203 modulus check) but random: we never finish the
handshake or decapsulate anything. Nothing is authenticated; only the
ServerHello is read and the socket is closed.

Fail-safe like `pqc_probe`: never raises, returns a `PqcProbeResult`.
"""
from __future__ import annotations

import secrets
import socket
import struct

from .pqc_probe import PqcProbeResult

GROUP_NAMES = {
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
    0x001D: "X25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001E: "X448",
}
PQC_GROUPS = {0x11EC, 0x11EB, 0x11ED, 0x6399}
# Hybrid groups first, then classical ones so a non-PQC server answers with a
# HelloRetryRequest (a clean "no") instead of aborting the handshake.
_OFFERED_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x001D, 0x0017, 0x0018]

_HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
_MLKEM_Q = 3329
_MLKEM768_K = 3
_ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 70: "protocol_version",
           71: "insufficient_security", 80: "internal_error", 112: "unrecognized_name"}


def _mlkem768_encaps_key() -> bytes:
    """A well-formed ML-KEM-768 encapsulation key: ByteEncode12(t_hat) || rho (1184 bytes)."""
    out = bytearray()
    for _ in range(_MLKEM768_K * 256 // 2):
        a, b = secrets.randbelow(_MLKEM_Q), secrets.randbelow(_MLKEM_Q)
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(out) + secrets.token_bytes(32)


def _x25519_public() -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def build_client_hello(host: str, alpn: str | None = None) -> bytes:
    """TLS record carrying a TLS 1.3 ClientHello with one X25519MLKEM768 key share."""
    # X25519MLKEM768 share = ML-KEM-768 encapsulation key || X25519 public key
    share = _mlkem768_encaps_key() + _x25519_public()
    groups = b"".join(struct.pack("!H", g) for g in _OFFERED_GROUPS)
    sig_algs = b"".join(struct.pack("!H", s) for s in
                        (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807))
    exts = b""
    if host and not _is_ip(host):
        name = host.encode("idna")
        exts += _ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    exts += _ext(0x000A, struct.pack("!H", len(groups)) + groups)
    exts += _ext(0x000D, struct.pack("!H", len(sig_algs)) + sig_algs)
    exts += _ext(0x002B, b"\x02\x03\x04")                          # supported_versions: TLS 1.3
    exts += _ext(0x002D, b"\x01\x01")                              # psk_dhe_ke
    key_share = struct.pack("!HH", 0x11EC, len(share)) + share
    exts += _ext(0x0033, struct.pack("!H", len(key_share)) + key_share)
    if alpn:
        p = alpn.encode()
        exts += _ext(0x0010, struct.pack("!HB", len(p) + 1, len(p)) + p)

    body = (b"\x03\x03" + secrets.token_bytes(32)                 # legacy_version, random
            + b"\x20" + secrets.token_bytes(32)                     # legacy_session_id
            + b"\x00\x06\x13\x01\x13\x02\x13\x03"                   # TLS 1.3 cipher suites
            + b"\x01\x00"                                           # null compression
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def parse_server_reply(data: bytes) -> PqcProbeResult:
    """Interpret the first TLS record(s) a server sent back."""
    if len(data) < 5:
        return PqcProbeResult(True, True, False, "", "no TLS response")
    ctype = data[0]
    if ctype == 0x15 and len(data) >= 7:
        desc = data[6]
        return PqcProbeResult(True, True, False, "",
                              f"server refused the hybrid ClientHello (alert {_ALERTS.get(desc, desc)})")
    if ctype != 0x16:
        return PqcProbeResult(True, True, False, "", f"unexpected TLS record type {ctype}")
    # Reassemble handshake bytes from consecutive handshake records.
    hs, i = b"", 0
    while i + 5 <= len(data) and data[i] == 0x16:
        n = struct.unpack("!H", data[i + 3:i + 5])[0]
        hs += data[i + 5:i + 5 + n]
        i += 5 + n
    if len(hs) < 4 or hs[0] != 0x02:
        return PqcProbeResult(True, True, False, "", "first handshake message was not a ServerHello")
    body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
    try:
        random = body[2:34]
        p = 34
        p += 1 + body[p]                      # session id
        p += 2 + 1                            # cipher suite + compression
        ext_end = p + 2 + struct.unpack("!H", body[p:p + 2])[0]
        p += 2
        version, group = None, None
        while p + 4 <= ext_end:
            et, ln = struct.unpack("!HH", body[p:p + 4])
            ev = body[p + 4:p + 4 + ln]
            if et == 0x002B and ln >= 2:
                version = struct.unpack("!H", ev[:2])[0]
            elif et == 0x0033 and ln >= 2:
                group = struct.unpack("!H", ev[:2])[0]
            p += 4 + ln
    except (IndexError, struct.error):
        return PqcProbeResult(True, True, False, "", "malformed ServerHello")
    if version != 0x0304:
        return PqcProbeResult(True, True, False, "", "server answered with TLS 1.2 or older (no PQC key exchange)")
    name = GROUP_NAMES.get(group, f"0x{group:04x}" if group is not None else "")
    hrr = random == _HRR_RANDOM
    if group in PQC_GROUPS:
        note = "server asked to retry with a different hybrid group" if hrr else "server accepted the X25519MLKEM768 key share"
        return PqcProbeResult(True, True, True, name, note)
    return PqcProbeResult(True, True, False, name,
                          f"server declined hybrid ML-KEM and asked for {name or 'another group'}" if hrr
                          else f"server negotiated {name or 'a classical group'}")


def probe_wire_pqc(host: str, port: int = 443, timeout: float = 10.0,
                   alpn: str | None = None) -> PqcProbeResult:
    """Send one hybrid ClientHello to host:port and classify the reply. Never raises."""
    try:
        hello = build_client_hello(host, alpn)
    except Exception as exc:  # pragma: no cover — cryptography missing/broken
        return PqcProbeResult(False, False, False, "", f"wire probe unavailable: {exc}")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(hello)
            data = b""
            # The ServerHello is small; read until the first handshake message is complete.
            while len(data) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 9 and data[0] == 0x16:
                    need = 5 + struct.unpack("!H", data[3:5])[0]
                    hs_len = 4 + int.from_bytes(data[6:9], "big")
                    if len(data) >= need and hs_len <= need - 5:
                        break
                elif len(data) >= 7:
                    break
    except socket.timeout:
        return PqcProbeResult(True, False, False, "", "wire probe timed out")
    except OSError as exc:
        return PqcProbeResult(True, False, False, "", f"wire probe connection error: {exc}")
    return parse_server_reply(data)


__all__ = ["build_client_hello", "parse_server_reply", "probe_wire_pqc", "GROUP_NAMES", "PQC_GROUPS"]

# Allow `python -m scanner.wire_probe host [port]` for a quick manual check.
if __name__ == "__main__":  # pragma: no cover
    import sys
    r = probe_wire_pqc(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 443)
    print(r)
