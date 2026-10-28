"""Executed, verification-gated PQC migration with rollback (QUANT-A-MAZE / PQC-01).

The planner decides WHAT to change and ``optimize.py`` decides the ORDER. This module actually
*applies* one change to a running endpoint, proves it with a fresh measurement, and rolls back
if the proof fails — the "verification-gated" half of PQC-01.

We migrate a bank service's key-establishment from classical **X25519** to hybrid
**X25519MLKEM768** (X25519 + ML-KEM-768, FIPS 203). This is a genuine post-quantum handshake run
on real cryptography — the same hybrid primitive SeQr's ``pqcmap`` ships, and the exact group an
nginx ``ssl_ecdh_curve X25519MLKEM768`` line negotiates at the TLS layer on an OpenSSL 3.5+
runtime. Here it runs at the key-establishment layer so it works without that runtime.

The gate never self-asserts success: ``probe()`` performs a brand-new handshake and reads back
the negotiated group AND checks client/server derived the same session key (compatibility). A
migration is "converged" only if a fresh measurement says so — mirroring ``verify.py``. A botched
apply is detected and rolled back; tampered/forged ciphertexts are rejected.

Real ML-KEM via cryptography's FIPS-203 ``mlkem`` (OpenSSL 4.0.3 backend). No Docker, no TLS 3.5.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CLASSICAL = "X25519"
HYBRID = "X25519MLKEM768"


def _derive(*secrets: bytes) -> bytes:
    """Session key from one or more shared secrets (hybrid = concat, FIPS-style KDF)."""
    ikm = b"".join(secrets)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"seqr-migration-session").derive(ikm)


@dataclass
class Service:
    """A bank service endpoint whose key-establishment config we migrate.

    ``mode`` is the live config (CLASSICAL or HYBRID) — the thing a migration changes. In HYBRID
    mode the server holds an ML-KEM keypair; ``_broken`` simulates a mis-applied migration where
    the advertised public key and the decapsulation key drift apart (a real config error).
    """

    name: str
    mode: str = CLASSICAL
    _kem_sk: object = field(default=None, repr=False)
    _kem_pub_advertised: object = field(default=None, repr=False)
    _broken: bool = False

    def configure(self, mode: str, broken: bool = False) -> None:
        self.mode = mode
        self._broken = broken
        if mode == HYBRID:
            self._kem_sk = mlkem.MLKEM768PrivateKey.generate()
            if broken:
                # advertise a DIFFERENT key than we can decapsulate with → handshake won't agree
                self._kem_pub_advertised = mlkem.MLKEM768PrivateKey.generate().public_key()
            else:
                self._kem_pub_advertised = self._kem_sk.public_key()
        else:
            self._kem_sk = self._kem_pub_advertised = None


@dataclass
class Transcript:
    group: str
    session_agreed: bool          # client & server derived the same key (compatibility)
    pq_secure: bool
    detail: str
    ciphertext_bytes: int = 0


def handshake(server: Service, tamper: bool = False, forge: bool = False) -> Transcript:
    """One fresh key-establishment against the server's CURRENT config. A real negotiation."""
    # classical leg (always present): ephemeral X25519 ECDH
    s_x, c_x = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    ss_ecc_s = s_x.exchange(c_x.public_key())
    ss_ecc_c = c_x.exchange(s_x.public_key())

    if server.mode == CLASSICAL:
        ks = _derive(ss_ecc_s)
        kc = _derive(ss_ecc_c)
        return Transcript(CLASSICAL, ks == kc, False, "ECDHE X25519 only — classical", 0)

    # hybrid leg: client encapsulates to the server's advertised ML-KEM public key
    ss_kem_c, ct = server._kem_pub_advertised.encapsulate()  # (shared_secret, ciphertext)
    if forge:
        ct = ct[:-1]                       # truncated/forged ciphertext (wrong length)
    elif tamper:
        ct = bytes([ct[0] ^ 0x01]) + ct[1:]  # flip one bit (length-valid, content-tampered)

    try:
        ss_kem_s = server._kem_sk.decapsulate(ct)   # ML-KEM implicit rejection → pseudo-random on tamper
    except ValueError as e:
        return Transcript(HYBRID, False, True, f"REJECTED: {e}", len(ct))

    ks = _derive(ss_ecc_s, ss_kem_s)
    kc = _derive(ss_ecc_c, ss_kem_c)
    agreed = ks == kc
    why = "hybrid X25519 + ML-KEM-768 session established" if agreed else \
          "ML-KEM secret mismatch — session rejected"
    return Transcript(HYBRID, agreed, True, why, len(ct))


def probe(server: Service) -> Transcript:
    """Fresh measurement of what the server negotiates NOW (the verify-gate's evidence)."""
    return handshake(server)


# ── rollback ────────────────────────────────────────────────────────────────
@dataclass
class RollbackPoint:
    mode: str


def execute_migration(server: Service, broken: bool = False) -> RollbackPoint:
    """Apply the change (classical → hybrid), capturing pre-state for rollback first."""
    pre = RollbackPoint(mode=server.mode)
    server.configure(HYBRID, broken=broken)
    return pre


def rollback(server: Service, point: RollbackPoint) -> Transcript:
    server.configure(point.mode)
    return probe(server)


def verify_gate(server: Service, target: str = HYBRID) -> tuple[bool, Transcript]:
    """Converged ONLY if a fresh handshake negotiates `target` AND the session agrees."""
    t = probe(server)
    return (t.group == target and t.session_agreed, t)


# ── full loop ──────────────────────────────────────────────────────────────
def migrate_with_gate(server: Service, broken: bool = False) -> dict:
    """before trace → apply → after trace → verify-gate → rollback if the proof fails."""
    before = probe(server)
    pre = execute_migration(server, broken=broken)
    after = probe(server)
    converged, verified = verify_gate(server)
    rolled_back = None
    if not converged:
        rolled_back = rollback(server, pre)
    return {
        "service": server.name, "before": before, "after": after,
        "converged": converged, "verify": verified,
        "rolled_back": rolled_back, "final_mode": server.mode,
    }


def _t(tag: str, t: Transcript) -> None:
    pq = "PQ-safe" if t.pq_secure else "classical"
    ok = "OK" if t.session_agreed else "FAIL"
    ct = f", ct={t.ciphertext_bytes}B" if t.ciphertext_bytes else ""
    print(f"    {tag:16} group={t.group:16} session={ok:4} [{pq}{ct}]  {t.detail}")


if __name__ == "__main__":
    print("=== PQC-01 executed, verification-gated migration (real X25519 + ML-KEM-768) ===\n")

    print("-- Case A: healthy migration (payment-api) --")
    svc = Service("payment-api")
    r = migrate_with_gate(svc)
    _t("before", r["before"]); _t("after", r["after"])
    print(f"    verify-gate converged={r['converged']}  -> final mode = {r['final_mode']}\n")

    print("-- Case B: botched migration -> gate rejects -> rollback --")
    svc2 = Service("auth-svc")
    r2 = migrate_with_gate(svc2, broken=True)
    _t("before", r2["before"]); _t("after(broken)", r2["after"])
    print(f"    verify-gate converged={r2['converged']} (compatibility failed)")
    if r2["rolled_back"]:
        _t("after rollback", r2["rolled_back"])
    print(f"    final mode = {r2['final_mode']}  (safely reverted, service stays up)\n")

    print("-- Case C: negative tests against a migrated service --")
    svc3 = Service("kyc-svc"); svc3.configure(HYBRID)
    _t("tampered ct", handshake(svc3, tamper=True))
    _t("forged ct", handshake(svc3, forge=True))
    _t("honest ct", handshake(svc3))
