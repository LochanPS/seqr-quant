"""Declarative crypto-policy evaluation for the CI gate.

The CI gate's job in the SeQr lifecycle (docs/13 §4.1) is to **block** PRs that drift
from the org's declared crypto policy — the same policy the scanner *measures* against,
the migration engine *converges* to, and pqcmap *enforces* in code. This module loads a
policy and decides which scanner findings are *drift* from it.

The policy shape is the spine's, not a parallel one. A policy is a ``{"rules": [...]}``
body (see ``audit/backend/app/spine/policy.py`` ``DEFAULT_POLICY_BODY`` and the identical
reuse in ``pqcmap.policy``). Each rule has a ``key``, a ``type``, a ``severity`` and a
human ``target``. We reuse the spine's rule vocabulary directly:

* ``family_in``     — the algorithm's family must be in ``allowed``
* ``family_not_in`` — the algorithm's family must not be in ``forbidden``
* ``min_key_size``  — for a classical ``family``, the key size must be ``>= min``

A full spine policy body is ingestible as-is: rule types that describe network/graph
posture rather than a code algorithm (``graph_no_origin_edge``, and slot-scoped TLS rules
that never match a code finding's family) simply don't fire here and are ignored. This is
the same "read it, don't fork it" contract pqcmap follows for the code layer.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Severity ranking mirrors the scanner/spine scale (most urgent first). Kept local so the
# CI package has no import dependency on the backend spine.
SEVERITY_ORDER = {"immediate": 0, "urgent": 1, "planned": 2}

# Auto-discovery names, in precedence order, for a policy file in the repo root.
POLICY_FILENAMES = ("seqr-policy.json",)

# Code-layer baseline. Same intent as the spine's DEFAULT_POLICY_BODY (PCI DSS 12.3.3 +
# SEBI CSCRF: inventory + prioritise PQC migration), expressed for the crypto a change
# introduces in source: no quantum-vulnerable families. Family names cover both the code
# scanner's vocabulary ("ECC") and the spine/pqcmap vocabulary ("ECDSA"/"ECDH") so a
# policy authored for either layer evaluates correctly here.
DEFAULT_POLICY_BODY: dict[str, Any] = {
    "name": "SeQr CI baseline (PCI DSS + SEBI CSCRF intent)",
    "version": "1",
    "rules": [
        {
            "key": "no_quantum_vulnerable_family",
            "type": "family_not_in",
            "forbidden": ["RSA", "ECC", "ECDSA", "ECDH", "EdDSA", "DSA", "DH"],
            "severity": "immediate",
            "target": "ML-KEM (KEM) / ML-DSA (signatures)",
        },
    ],
}

# Rule types that describe a single algorithm choice. Anything else (graph/infra rules
# from a spine body) is not applicable to a code finding and is skipped.
_ALGORITHM_RULE_TYPES = frozenset({"family_in", "family_not_in", "min_key_size"})


def _parse_key_size(algorithm: str | None) -> int | None:
    """First 3-5 digit run in the name, e.g. ``RSA-2048`` -> 2048. Mirrors the spine."""
    m = re.search(r"(\d{3,5})", algorithm or "")
    return int(m.group(1)) if m else None


@dataclass(frozen=True)
class PolicyViolation:
    """One failed policy rule for one finding (the drift record)."""

    rule_key: str
    severity: str
    actual: str
    target: str
    message: str


class CryptoPolicy:
    """A loaded crypto policy that decides whether a finding drifts from desired state.

    Construct from the spine's ``{"rules": [...]}`` body (:meth:`from_dict`), a JSON file
    (:meth:`from_file`), or use the built-in :meth:`default`.
    """

    def __init__(self, body: dict[str, Any]):
        if not isinstance(body, dict) or "rules" not in body:
            raise ValueError("policy body must be a dict with a 'rules' list")
        self.body = body
        self.name = body.get("name", "custom policy")
        self.rules: list[dict] = list(body.get("rules", []))

    # -- constructors --
    @classmethod
    def default(cls) -> "CryptoPolicy":
        return cls(DEFAULT_POLICY_BODY)

    @classmethod
    def from_dict(cls, body: dict[str, Any]) -> "CryptoPolicy":
        return cls(body)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "CryptoPolicy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    # -- evaluation --
    def evaluate_finding(self, finding) -> list[PolicyViolation]:
        """Return every :class:`PolicyViolation` ``finding`` triggers (empty == compliant)."""
        family = getattr(finding, "algorithm_family", "") or ""
        algorithm = getattr(finding, "algorithm", "") or ""
        key_size = _parse_key_size(algorithm)
        return self.evaluate_algorithm(family, algorithm, key_size)

    def evaluate_algorithm(
        self, family: str, algorithm: str, key_size: int | None = None
    ) -> list[PolicyViolation]:
        """Core evaluation over a resolved ``(family, algorithm, key_size)`` triple."""
        found: list[PolicyViolation] = []
        for rule in self.rules:
            if rule.get("type") not in _ALGORITHM_RULE_TYPES:
                continue  # graph/infra rule — not applicable to a code finding
            v = self._check_rule(rule, family, algorithm, key_size)
            if v is not None:
                found.append(v)
        found.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        return found

    def _check_rule(
        self, rule: dict, family: str, algorithm: str, key_size: int | None
    ) -> PolicyViolation | None:
        rtype = rule["type"]
        target = rule.get("target", "")
        key = rule.get("key", rtype)
        sev = rule.get("severity", "planned")

        if rtype == "family_not_in" and family in set(rule.get("forbidden", [])):
            return PolicyViolation(
                key, sev, f"{algorithm} ({family})", target,
                f"{algorithm} is a {family} algorithm, which policy '{self.name}' "
                f"forbids ({key}). Use {target}.",
            )
        if rtype == "family_in" and family not in set(rule.get("allowed", [])):
            allowed = ", ".join(rule.get("allowed", []))
            return PolicyViolation(
                key, sev, f"{algorithm} ({family})", target,
                f"{algorithm} is a {family} algorithm; policy '{self.name}' allows only "
                f"[{allowed}] here ({key}). Use {target}.",
            )
        if rtype == "min_key_size" and family == rule.get("family"):
            if key_size is not None and key_size < int(rule["min"]):
                return PolicyViolation(
                    key, sev, f"{algorithm} ({key_size}-bit)", target,
                    f"{algorithm} is {key_size}-bit; policy '{self.name}' requires "
                    f"{rule['family']}-{rule['min']}+ ({key}). Use {target}.",
                )
        return None


def find_policy_file(root: str | os.PathLike[str] | None = None) -> Path | None:
    """Return the first auto-discovered policy file in ``root`` (cwd default), or None."""
    base = Path(root or os.getcwd())
    for name in POLICY_FILENAMES:
        p = base / name
        if p.is_file():
            return p
    return None


def load_policy(
    source: str | os.PathLike[str] | dict | CryptoPolicy | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
) -> CryptoPolicy:
    """Resolve a policy: explicit ``source`` > auto-discovered file in ``root`` > default.

    ``source`` may be a :class:`CryptoPolicy`, a policy body ``dict``, or a file path.
    With no source, an auto-discovered ``seqr-policy.json`` is used if present, else the
    built-in :data:`DEFAULT_POLICY_BODY`.
    """
    if isinstance(source, CryptoPolicy):
        return source
    if isinstance(source, dict):
        return CryptoPolicy.from_dict(source)
    if source is not None:
        return CryptoPolicy.from_file(source)
    discovered = find_policy_file(root)
    if discovered is not None:
        return CryptoPolicy.from_file(discovered)
    return CryptoPolicy.default()


def evaluate_findings(policy: CryptoPolicy, findings: list) -> dict[int, list[PolicyViolation]]:
    """Map ``id(finding)`` → its policy violations for every drifting finding.

    Keyed on object identity so callers can look violations back up per finding without
    the finding needing to be hashable.
    """
    out: dict[int, list[PolicyViolation]] = {}
    for f in findings:
        vs = policy.evaluate_finding(f)
        if vs:
            out[id(f)] = vs
    return out


__all__ = [
    "CryptoPolicy",
    "PolicyViolation",
    "DEFAULT_POLICY_BODY",
    "SEVERITY_ORDER",
    "POLICY_FILENAMES",
    "find_policy_file",
    "load_policy",
    "evaluate_findings",
]
