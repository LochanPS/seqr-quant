"""
Active post-quantum key-exchange detection.

Passive scanning (sslyze) CANNOT confirm hybrid/ML-KEM support — to know whether
a server actually negotiates a PQC group you must send a ClientHello that offers
one. This module does exactly that, by driving OpenSSL 3.5+ (which ships native
ML-KEM hybrid groups: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).

Design notes:
- Server-side only. The free pip CLI stays passive (no OpenSSL 3.5 dependency to
  rely on). The SaaS scanner Docker bakes in OpenSSL 3.5+.
- Fail-SAFE: if OpenSSL 3.5+ is absent, the probe reports `available=False` and
  the caller falls back to passive results. It never raises into the scan flow.
- We offer the PQC groups first, then X25519 as a classical fallback, so the
  handshake completes either way and we can read the *negotiated* group as ground
  truth (a confirmed PQC group = the server genuinely supports it).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

# OpenSSL 3.5 hybrid PQC group names, most-preferred first.
_PQC_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
_PQC_GROUP_SET = {g.lower() for g in _PQC_GROUPS}
# Offer PQC first, then a classical fallback so the handshake still completes
# against servers that don't support PQC (lets us read the negotiated group).
_OFFER = ":".join(_PQC_GROUPS + ["X25519"])

_NEG_RE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)", re.IGNORECASE)
_VER_RE = re.compile(r"OpenSSL\s+(\d+)\.(\d+)")
_MIN_VERSION = (3, 5)


@dataclass
class PqcProbeResult:
    available: bool          # OpenSSL 3.5+ present on this host
    probed: bool             # the probe actually attempted a connection
    supported: bool          # server negotiated a hybrid PQC group
    negotiated_group: str    # e.g. "X25519MLKEM768" or "" if none
    note: str = ""


def _openssl_path_with_pqc() -> str | None:
    """Return the openssl binary path iff it is version 3.5+ (has ML-KEM), else None.

    Honours $SEQR_OPENSSL to point at a specific binary (e.g. a portable OpenSSL
    3.5 build, or a non-PATH location in a container) without a system install.
    """
    openssl = os.environ.get("SEQR_OPENSSL") or shutil.which("openssl")
    if not openssl:
        return None
    try:
        out = subprocess.run(
            [openssl, "version"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = _VER_RE.search(out.stdout or "")
    if not m:
        return None
    if (int(m.group(1)), int(m.group(2))) < _MIN_VERSION:
        return None
    return openssl


def probe_active_pqc(
    host: str, port: int = 443, timeout: float = 10.0, starttls: str | None = None
) -> PqcProbeResult:
    """
    Actively probe whether `host:port` negotiates a hybrid PQC key exchange.

    starttls: optional protocol name for opportunistic TLS ("smtp", "imap",
    "pop3", "ftp", "postgres", ...) passed to `openssl s_client -starttls`.

    Never raises — returns a PqcProbeResult describing what happened. Callers
    should treat `available=False` as "fall back to passive results".
    """
    openssl = _openssl_path_with_pqc()
    if not openssl:
        return PqcProbeResult(
            available=False, probed=False, supported=False, negotiated_group="",
            note="OpenSSL 3.5+ not available; active PQC probe skipped",
        )

    cmd = [
        openssl, "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-groups", _OFFER,
        "-tls1_3",
    ]
    if starttls:
        cmd += ["-starttls", starttls]
    try:
        proc = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return PqcProbeResult(True, False, False, "", "probe timed out")
    except (OSError, subprocess.SubprocessError) as exc:
        return PqcProbeResult(True, False, False, "", f"probe error: {exc}")

    combined = (proc.stdout or "") + (proc.stderr or "")
    m = _NEG_RE.search(combined)
    if not m:
        return PqcProbeResult(
            True, True, False, "",
            "no TLS1.3 group negotiated (handshake failed or no shared group)",
        )
    group = m.group(1)
    return PqcProbeResult(
        available=True,
        probed=True,
        supported=group.lower() in _PQC_GROUP_SET,
        negotiated_group=group,
        note="",
    )
