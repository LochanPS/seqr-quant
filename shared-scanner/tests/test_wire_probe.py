"""Tests for the wire-level hybrid PQC probe (scanner/wire_probe.py).

Replies are synthesised byte-for-byte; the one socket test talks to a local fake server.
Set RUN_LIVE_WIRE_PROBE=1 to also probe real hosts.
"""
import os
import socket
import struct
import threading

import pytest

from scanner.wire_probe import _HRR_RANDOM, build_client_hello, parse_server_reply, probe_wire_pqc


def _server_hello(group: int, *, hrr: bool = False, tls13: bool = True, share_len: int = 1120) -> bytes:
    exts = b""
    if tls13:
        exts += struct.pack("!HHH", 0x002B, 2, 0x0304)
    ks = struct.pack("!H", group) if hrr else struct.pack("!HH", group, share_len) + b"\x00" * share_len
    exts += struct.pack("!HH", 0x0033, len(ks)) + ks
    body = (b"\x03\x03" + (_HRR_RANDOM if hrr else os.urandom(32)) + b"\x20" + os.urandom(32)
            + b"\x13\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _parse_hello(record: bytes) -> dict:
    assert record[0] == 0x16 and struct.unpack("!H", record[3:5])[0] == len(record) - 5
    hs = record[5:]
    assert hs[0] == 0x01 and int.from_bytes(hs[1:4], "big") == len(hs) - 4
    body = hs[4:]
    p = 2 + 32
    p += 1 + body[p]
    p += 2 + struct.unpack("!H", body[p:p + 2])[0]
    p += 1 + body[p]
    end = p + 2 + struct.unpack("!H", body[p:p + 2])[0]
    p += 2
    exts = {}
    while p < end:
        t, n = struct.unpack("!HH", body[p:p + 4])
        exts[t] = body[p + 4:p + 4 + n]
        p += 4 + n
    assert p == end == len(body)
    return exts


def test_client_hello_is_well_formed_tls13_with_one_hybrid_share():
    exts = _parse_hello(build_client_hello("bank.example", alpn="h2"))
    assert exts[0x002B] == b"\x02\x03\x04"
    assert b"bank.example" in exts[0x0000]
    ks = exts[0x0033]
    assert struct.unpack("!H", ks[:2])[0] == len(ks) - 2
    group, n = struct.unpack("!HH", ks[2:6])
    assert group == 0x11EC and n == 1184 + 32 == len(ks) - 6     # ML-KEM-768 ek || X25519
    assert exts[0x000A][2:4] == b"\x11\xec"                         # hybrid offered first
    assert b"h2" in exts[0x0010]


def test_encapsulation_key_passes_the_fips203_modulus_check():
    ks = _parse_hello(build_client_hello("x.example"))[0x0033]
    ek = ks[6:6 + 1152]
    for i in range(0, len(ek), 3):
        a = ek[i] | (ek[i + 1] & 0x0F) << 8
        b = ek[i + 1] >> 4 | ek[i + 2] << 4
        assert a < 3329 and b < 3329


def test_no_sni_for_ip_literals():
    assert 0x0000 not in _parse_hello(build_client_hello("192.0.2.1"))


def test_server_hello_with_hybrid_group_is_supported():
    r = parse_server_reply(_server_hello(0x11EC))
    assert r.supported and r.negotiated_group == "X25519MLKEM768"


def test_hello_retry_for_classical_group_is_not_supported():
    r = parse_server_reply(_server_hello(0x001D, hrr=True))
    assert not r.supported and r.negotiated_group == "X25519" and "declined" in r.note


def test_hello_retry_for_another_hybrid_group_still_counts():
    r = parse_server_reply(_server_hello(0x11EB, hrr=True))
    assert r.supported and r.negotiated_group == "SecP256r1MLKEM768"


def test_tls12_reply_is_not_supported():
    r = parse_server_reply(_server_hello(0x001D, tls13=False))
    assert not r.supported and "TLS 1.2" in r.note


def test_alert_is_not_supported():
    r = parse_server_reply(b"\x15\x03\x03\x00\x02\x02\x28")
    assert not r.supported and "handshake_failure" in r.note


def test_garbage_and_empty_replies_never_raise():
    for data in (b"", b"\x16\x03", b"\x17\x03\x03\x00\x01\x00", b"\x16\x03\x03\x00\x04\x02\x00\x00\x50"):
        assert parse_server_reply(data).supported is False


def test_hello_split_across_records_is_reassembled():
    rec = _server_hello(0x11EC)
    hs = rec[5:]
    split = (b"\x16\x03\x03" + struct.pack("!H", 100) + hs[:100]
             + b"\x16\x03\x03" + struct.pack("!H", len(hs) - 100) + hs[100:])
    assert parse_server_reply(split).supported


def test_probe_against_local_fake_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    seen = {}

    def serve():
        conn, _ = srv.accept()
        with conn:
            seen["hello"] = conn.recv(8192)
            conn.sendall(_server_hello(0x11EC))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    r = probe_wire_pqc("127.0.0.1", port, timeout=5)
    t.join(5)
    srv.close()
    assert r.probed and r.supported and r.negotiated_group == "X25519MLKEM768"
    assert seen["hello"][0] == 0x16


def test_unreachable_host_never_raises():
    r = probe_wire_pqc("127.0.0.1", 1, timeout=2)
    assert r.probed is False and r.supported is False


@pytest.mark.skipif(not os.environ.get("RUN_LIVE_WIRE_PROBE"), reason="live network probe")
@pytest.mark.parametrize("host,expected", [("cloudflare.com", True), ("github.com", False)])
def test_live(host, expected):
    assert probe_wire_pqc(host).supported is expected
