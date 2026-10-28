"""Tests for the SSH scanner's KEXINIT parser (pure, no network)."""
import struct

import pytest

from scanner.ssh_scanner import (
    _PQC_KEX,
    _classify_host_key,
    parse_kexinit_namelists,
)


def _namelist(value: str) -> bytes:
    raw = value.encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def _build_kexinit(kex: str, host_key: str) -> bytes:
    """Build a minimal valid SSH_MSG_KEXINIT payload."""
    payload = bytes([20]) + b"\x00" * 16  # msg code + cookie
    payload += _namelist(kex)             # kex_algorithms
    payload += _namelist(host_key)        # server_host_key_algorithms
    for _ in range(8):                    # remaining 8 name-lists (empty)
        payload += _namelist("")
    payload += bytes([0]) + struct.pack(">I", 0)  # first_kex_packet_follows + reserved
    return payload


def test_parses_kex_and_hostkey():
    p = _build_kexinit("mlkem768x25519-sha256,curve25519-sha256", "ssh-ed25519,ssh-rsa")
    nl = parse_kexinit_namelists(p)
    assert nl["kex_algorithms"] == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert nl["server_host_key_algorithms"] == ["ssh-ed25519", "ssh-rsa"]


def test_pqc_kex_detected():
    p = _build_kexinit("sntrup761x25519-sha512,curve25519-sha256", "ssh-ed25519")
    nl = parse_kexinit_namelists(p)
    pqc = [k for k in nl["kex_algorithms"] if k in _PQC_KEX]
    assert pqc == ["sntrup761x25519-sha512"]


def test_classical_only_no_pqc():
    p = _build_kexinit("curve25519-sha256,ecdh-sha2-nistp256", "ssh-ed25519")
    nl = parse_kexinit_namelists(p)
    assert [k for k in nl["kex_algorithms"] if k in _PQC_KEX] == []


def test_rejects_non_kexinit():
    bad = bytes([21]) + b"\x00" * 16  # wrong message code
    with pytest.raises(ValueError):
        parse_kexinit_namelists(bad)


def test_rejects_truncated():
    truncated = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 50) + b"short"
    with pytest.raises(ValueError):
        parse_kexinit_namelists(truncated)


def test_host_key_classification():
    assert _classify_host_key(["ssh-ed25519", "ssh-rsa"]) == "vulnerable"
    assert _classify_host_key([]) == "unknown"


def test_mlkem_and_sntrup_in_pqc_set():
    assert "mlkem768x25519-sha256" in _PQC_KEX
    assert "sntrup761x25519-sha512" in _PQC_KEX
