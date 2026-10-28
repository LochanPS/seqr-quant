"""Normalized asset observation — the agent's output unit, shaped to the platform schema.

Every plugin emits ``AssetObservation``s; ``to_dict()`` produces a JSON-native dict matching
the platform's ``AgentObservationIn`` (app/routers/agent.py). Keeping the fields identical and
JSON-native is what lets the agent's canonical signing bytes match the server's.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from typing import Optional

# Coarse family classification, aligned with the platform's agent_ingest classifier.
_PQC_FAMILIES = {"ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "sphincs", "falcon", "xmss", "lms"}
_CLASSICAL_FAMILIES = {"rsa", "ecc", "ecdsa", "ecdh", "dh", "dsa", "3des", "des", "rc4", "md5", "sha1"}


def classify(algorithm: str, family: Optional[str] = None) -> tuple[str, str]:
    """Return ``(algorithm_family, quantum_status)``, inferring what a plugin did not set.

    Mirrors the platform-side classifier so the agent sends an authoritative status the server
    will accept verbatim (the server only re-infers when the agent omits ``quantum_status``).
    """
    algo = (algorithm or "").lower()
    fam = (family or "").strip()
    fam_l = fam.lower()
    if not fam:
        for f in list(_PQC_FAMILIES) + list(_CLASSICAL_FAMILIES):
            if f in algo:
                fam, fam_l = f.upper(), f
                break
        else:
            fam, fam_l = "unknown", "unknown"

    if "hybrid" in algo or ("x25519" in algo and any(p in algo for p in ("mlkem", "kyber"))):
        status = "hybrid"
    elif fam_l in _PQC_FAMILIES:
        status = "safe"
    elif fam_l in _CLASSICAL_FAMILIES:
        status = "vulnerable"
    else:
        status = "unknown"
    return fam, status


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


@dataclass
class AssetObservation:
    """One crypto-posture datum about one asset slot. Fields map 1:1 to AgentObservationIn."""

    asset_key: str
    location_type: str
    algorithm: str
    asset_key_type: str = "host"
    asset_type: str = "host"
    asset_name: Optional[str] = None
    location_detail: Optional[str] = None
    algorithm_family: Optional[str] = None
    key_size: Optional[int] = None
    quantum_status: Optional[str] = None
    confidence: Optional[str] = "high"
    observed_at: str = field(default_factory=_now_iso)
    cert_expiry_date: Optional[str] = None
    cert_issuer: Optional[str] = None
    plugin: Optional[str] = None

    def __post_init__(self):
        # Auto-classify when a plugin gave an algorithm but no family/status.
        if self.algorithm and (not self.algorithm_family or not self.quantum_status):
            fam, status = classify(self.algorithm, self.algorithm_family)
            self.algorithm_family = self.algorithm_family or fam
            self.quantum_status = self.quantum_status or status

    def to_dict(self) -> dict:
        """JSON-native dict for the wire body / air-gap envelope (drops Nones for compactness)."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}
