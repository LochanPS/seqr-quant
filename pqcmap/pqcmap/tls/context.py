"""Best-effort PQC-hybrid TLS — negotiate X25519MLKEM768 when the runtime can, else
degrade cleanly, and always report honestly what happened.

Post-quantum TLS key exchange (the hybrid group **X25519MLKEM768**, IANA 0x11EC) needs
support on *both* sides of the stack:

* **OpenSSL 3.5+** ships the ML-KEM groups natively and includes X25519MLKEM768 in its
  default group list — so a plain client on 3.5+ may negotiate PQC with no extra config.
  Older OpenSSL (3.2–3.4) can expose a *draft* hybrid group only via the liboqs
  ``oqs-provider``.
* **Python's ssl module** only lets you *choose* groups from **3.13+**
  (``SSLContext.set_groups``). Before that, you take whatever the linked OpenSSL
  defaults to — you cannot force or forbid the PQC group from Python.

This module never pretends. :func:`capabilities` probes the real runtime and
:func:`build_client_context` returns a hardened context that *tries* to enable the
hybrid group when it can, and otherwise returns an ordinary secure TLS context whose
capability report says PQC was not configured. It never raises for lack of PQC support —
degrading to classical TLS 1.3 is the safe, correct fallback during the transition.

**MTU / fragmentation caveat (see docs/02_SDK_PRD.md):** an ML-KEM share (~1.2 KB) makes
the TLS ClientHello span multiple packets. Most stacks handle this, but exotic
middleboxes/DTLS paths can choke on a fragmented ClientHello. Test a real handshake
against your endpoints before a production rollout.
"""
from __future__ import annotations

import ssl
import sys
from dataclasses import dataclass, field
from typing import Optional

# Candidate hybrid group names, best first. Different OpenSSL builds spell the same idea
# differently; we offer the modern IANA name plus the older draft/oqs-provider spellings.
PQC_HYBRID_GROUP = "X25519MLKEM768"
_CANDIDATE_GROUPS: tuple[str, ...] = (
    "X25519MLKEM768",       # OpenSSL 3.5+, final IANA codepoint 0x11EC
    "x25519_kyber768",      # oqs-provider / OpenSSL 3.2–3.4 draft spelling
    "X25519Kyber768Draft00",
    "SecP256r1MLKEM768",    # NIST-curve hybrid, some stacks prefer it
)
# Classical fallbacks appended so a handshake still succeeds against a classical peer.
_CLASSICAL_GROUPS: tuple[str, ...] = ("X25519", "x25519", "P-256", "prime256v1")

_OPENSSL_INFO = ssl.OPENSSL_VERSION_INFO  # e.g. (3, 0, 13, ...)
_PY_CAN_SET_GROUPS = hasattr(ssl.SSLContext, "set_groups")  # Python 3.13+


@dataclass(frozen=True)
class TLSCapabilities:
    """Honest report of what PQC TLS this runtime can actually do."""

    openssl_version: str
    openssl_version_info: tuple
    python_version: tuple
    can_configure_groups: bool          # ssl.SSLContext.set_groups exists (py3.13+)
    pqc_group_configured: bool          # we set a hybrid group on the context
    pqc_maybe_default: bool             # OpenSSL >=3.5 may negotiate hybrid unconfigured
    configured_group: Optional[str]     # the group name we managed to set, if any
    candidate_groups: tuple = field(default=_CANDIDATE_GROUPS)
    notes: tuple = field(default=())

    @property
    def pqc_hybrid_available(self) -> bool:
        """True if a PQC hybrid key exchange is achievable on this runtime.

        Either we explicitly configured the group, or the linked OpenSSL is new enough
        (3.5+) to offer it by default even though Python cannot pin it.
        """
        return self.pqc_group_configured or self.pqc_maybe_default

    def summary(self) -> str:
        state = "configured" if self.pqc_group_configured else (
            "available-by-default" if self.pqc_maybe_default else "unavailable"
        )
        grp = self.configured_group or (PQC_HYBRID_GROUP if self.pqc_maybe_default else "-")
        return (
            f"PQC-hybrid TLS: {state} (group {grp}); "
            f"{self.openssl_version}; "
            f"Python ssl set_groups={'yes' if self.can_configure_groups else 'no'}"
        )

    def as_dict(self) -> dict:
        return {
            "openssl_version": self.openssl_version,
            "openssl_version_info": list(self.openssl_version_info),
            "python_version": list(self.python_version),
            "can_configure_groups": self.can_configure_groups,
            "pqc_group_configured": self.pqc_group_configured,
            "pqc_maybe_default": self.pqc_maybe_default,
            "pqc_hybrid_available": self.pqc_hybrid_available,
            "configured_group": self.configured_group,
            "candidate_groups": list(self.candidate_groups),
            "notes": list(self.notes),
        }


def _try_set_groups(ctx: ssl.SSLContext) -> Optional[str]:
    """Best-effort: set a PQC-first group list on ``ctx``. Return the hybrid group we
    managed to include, or ``None``. Never raises."""
    if not _PY_CAN_SET_GROUPS:
        return None
    # Try each hybrid candidate paired with classical fallbacks, first that sticks wins.
    for hybrid in _CANDIDATE_GROUPS:
        group_list = ":".join((hybrid, *_CLASSICAL_GROUPS))
        try:
            ctx.set_groups(group_list)  # type: ignore[attr-defined]
            return hybrid
        except (ssl.SSLError, ValueError, OSError):
            continue
    return None


def capabilities(ctx: Optional[ssl.SSLContext] = None) -> TLSCapabilities:
    """Probe the runtime (and optionally a specific context) for PQC TLS support.

    Pass the context returned by :func:`build_client_context` to report what was
    actually configured on it; omit it for a runtime-only probe.
    """
    pqc_maybe_default = _OPENSSL_INFO >= (3, 5)
    notes: list[str] = []

    configured_group: Optional[str] = None
    if ctx is not None:
        configured_group = getattr(ctx, "_pqcmap_configured_group", None)

    if not _PY_CAN_SET_GROUPS:
        notes.append(
            "Python < 3.13: ssl has no set_groups(); the PQC group cannot be pinned "
            "from Python — the linked OpenSSL's default group list decides."
        )
    if pqc_maybe_default:
        notes.append(
            "OpenSSL >= 3.5 includes X25519MLKEM768 in its default groups, so a hybrid "
            "key exchange may be negotiated even without explicit configuration."
        )
    else:
        notes.append(
            "OpenSSL < 3.5: native ML-KEM groups absent; a hybrid handshake needs the "
            "liboqs oqs-provider or an OpenSSL 3.5+ build."
        )
    notes.append(
        "MTU: an ML-KEM ClientHello (~1.2 KB) fragments; test real handshakes before "
        "production (docs/02_SDK_PRD.md)."
    )

    return TLSCapabilities(
        openssl_version=ssl.OPENSSL_VERSION,
        openssl_version_info=tuple(_OPENSSL_INFO),
        python_version=tuple(sys.version_info[:3]),
        can_configure_groups=_PY_CAN_SET_GROUPS,
        pqc_group_configured=configured_group is not None,
        pqc_maybe_default=pqc_maybe_default,
        configured_group=configured_group,
        notes=tuple(notes),
    )


def build_client_context(
    *,
    verify: bool = True,
    cafile: Optional[str] = None,
    capath: Optional[str] = None,
    prefer_pqc: bool = True,
    minimum_tls: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> tuple[ssl.SSLContext, TLSCapabilities]:
    """Build a hardened client TLS context that uses PQC hybrid key exchange if it can.

    Returns ``(context, capabilities)``. The context is always usable for real TLS: if
    the PQC group cannot be configured on this runtime, it is an ordinary secure context
    and ``capabilities.pqc_group_configured`` is ``False`` — never an error. Set
    ``verify=False`` only for local testing (it disables cert/hostname checks).
    """
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=cafile, capath=capath
    )
    ctx.minimum_version = minimum_tls
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    configured_group: Optional[str] = None
    if prefer_pqc:
        configured_group = _try_set_groups(ctx)
    # Stash what we configured so capabilities(ctx) can report it faithfully.
    try:
        ctx._pqcmap_configured_group = configured_group  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        pass

    return ctx, capabilities(ctx)


def report() -> str:
    """One-line human-readable capability summary for logs / CLIs."""
    return capabilities().summary()
