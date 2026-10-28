"""Crypto-policy enforcement for application code.

This is the SDK's job in the SeQr lifecycle (docs/13 §4.1): the scanner *measures*
against a policy, the migration engine *converges* to it, and pqcmap **enforces** it in
code — so an app can't silently fall back to quantum-vulnerable crypto.

The policy shape is the spine's, not a parallel one. A policy is a ``{"rules": [...]}``
body (see ``audit/backend/app/spine/policy.py`` ``DEFAULT_POLICY_BODY``); each rule has a
``key``, a ``type``, a ``severity`` and a human ``target``. We reuse the spine's rule
vocabulary directly:

* ``family_in``     — the algorithm's family must be in ``allowed``
* ``family_not_in`` — the algorithm's family must not be in ``forbidden``
* ``min_key_size``  — for a classical ``family``, the key size must be ``>= min``

and add one rule type the code layer needs that the infra layer expresses through slots:

* ``min_nist_level`` — the algorithm's NIST security level must be ``>= min``

A spine policy body is ingestible as-is: infra rules carry a ``slot`` (``tls:kex`` /
``tls:cert``) which we map to a code ``kind`` (``kem`` / ``sign``) so a kex rule doesn't
get applied to a signature. Rule types that don't describe a single algorithm (e.g. the
graph ``graph_no_origin_edge`` rule) simply don't apply here and are ignored.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqcmap import algorithms
from pqcmap.core.exceptions import PolicyViolationError

# --- algorithm resolution ---------------------------------------------------

# Classical families we recognise so callers can guard arbitrary algorithm strings
# (e.g. from config) — the whole point is catching a silent fall-back to these.
_CLASSICAL_FAMILIES: tuple[tuple[str, str], ...] = (
    ("ML-KEM", "ML-KEM"),
    ("ML-DSA", "ML-DSA"),
    ("SLH-DSA", "SLH-DSA"),
    ("RSA", "RSA"),
    ("ECDSA", "ECDSA"),
    ("ED25519", "EdDSA"),
    ("ED448", "EdDSA"),
    ("ECDH", "ECDH"),
    ("X25519", "ECDH"),
    ("X448", "ECDH"),
    ("DSA", "DSA"),
    ("DH", "DH"),
)


def _parse_key_size(algorithm: str) -> int | None:
    """First 3-5 digit run in the name, e.g. ``RSA-2048`` -> 2048. Mirrors the spine."""
    m = re.search(r"(\d{3,5})", algorithm or "")
    return int(m.group(1)) if m else None


def family_of(algorithm: str) -> str:
    """Best-effort crypto family for ``algorithm`` (``"RSA"``, ``"ML-KEM"``, …).

    Uses pqcmap's own metadata for known PQC names and a substring match for common
    classical names. Returns ``"unknown"`` if nothing matches.
    """
    name = (algorithm or "").upper()
    for needle, fam in _CLASSICAL_FAMILIES:
        if name.startswith(needle) or needle in name:
            return fam
    return "unknown"


@dataclass(frozen=True)
class ResolvedAlgorithm:
    name: str
    family: str
    nist_level: int | None
    key_size: int | None


def resolve(algorithm: str) -> ResolvedAlgorithm:
    """Resolve an algorithm name to ``(family, nist_level, key_size)``.

    Known pqcmap algorithms use the precise :data:`pqcmap.algorithms.ALGORITHM_META`
    (family + NIST level + parameter size). Anything else — classical or unknown — is
    resolved heuristically from the name so it can still be guarded against.
    """
    m = algorithms.ALGORITHM_META.get(algorithm)
    if m is not None:
        return ResolvedAlgorithm(m.name, family_of(m.name), m.nist_level, None)
    return ResolvedAlgorithm(
        algorithm, family_of(algorithm), None, _parse_key_size(algorithm)
    )


# --- policy model -----------------------------------------------------------

# Code-layer baseline. Same intent as the spine's DEFAULT_POLICY_BODY (PCI DSS 12.3.3 +
# SEBI CSCRF: inventory + prioritise PQC migration), expressed for algorithm selection in
# code: no quantum-vulnerable families, and PQC at NIST Level 3 or above.
DEFAULT_POLICY_BODY: dict[str, Any] = {
    "name": "pqcmap baseline (PCI DSS + SEBI CSCRF intent)",
    "version": "1",
    "rules": [
        {
            "key": "no_quantum_vulnerable_family",
            "type": "family_not_in",
            "forbidden": ["RSA", "ECDSA", "EdDSA", "ECDH", "DSA", "DH"],
            "severity": "immediate",
            "target": "ML-KEM (KEM) / ML-DSA (signatures)",
        },
        {
            "key": "min_nist_level_3",
            "type": "min_nist_level",
            "min": 3,
            "severity": "urgent",
            "target": "NIST Level 3+ (ML-KEM-768 / ML-DSA-65)",
        },
    ],
}

# Map a spine infra slot to the code layer's operation kind, so a spine policy body's
# kex/cert rules scope correctly here instead of applying to every algorithm.
_SLOT_TO_KIND = {"tls:kex": "kem", "tls:cert": "sign"}

# Rule types that describe a single algorithm — anything else (infra/graph rules) is
# simply not applicable to a code-level algorithm check.
_ALGORITHM_RULE_TYPES = frozenset(
    {"family_in", "family_not_in", "min_key_size", "min_nist_level"}
)


@dataclass(frozen=True)
class Violation:
    """One failed rule for one algorithm."""

    rule_key: str
    severity: str
    actual: str
    target: str
    message: str


def _rule_kind(rule: dict) -> str | None:
    """The operation kind a rule scopes to: explicit ``kind``, else derived from ``slot``."""
    if rule.get("kind"):
        return rule["kind"]
    return _SLOT_TO_KIND.get(rule.get("slot"))


class CryptoPolicy:
    """A loaded crypto policy that can evaluate a single algorithm choice.

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
    def evaluate(self, algorithm: str, *, kind: str | None = None) -> list[Violation]:
        """Return every :class:`Violation` ``algorithm`` triggers (empty == compliant).

        ``kind`` (``"kem"`` / ``"sign"``) restricts which scoped rules apply; unscoped
        rules always apply. Violations are returned most-severe first.
        """
        r = resolve(algorithm)
        found: list[Violation] = []
        for rule in self.rules:
            rtype = rule.get("type")
            if rtype not in _ALGORITHM_RULE_TYPES:
                continue  # infra/graph rule — not applicable to a code algorithm
            rkind = _rule_kind(rule)
            if rkind is not None and kind is not None and rkind != kind:
                continue
            v = self._check_rule(rule, r)
            if v is not None:
                found.append(v)
        found.sort(key=lambda v: _SEVERITY_ORDER.get(v.severity, 99))
        return found

    def _check_rule(self, rule: dict, r: ResolvedAlgorithm) -> Violation | None:
        rtype = rule["type"]
        target = rule.get("target", "")
        key = rule.get("key", rtype)
        sev = rule.get("severity", "planned")

        if rtype == "family_not_in" and r.family in set(rule.get("forbidden", [])):
            return Violation(
                key, sev, f"{r.name} ({r.family})", target,
                f"{r.name} is a {r.family} algorithm, which policy '{self.name}' "
                f"forbids ({key}). Use {target}.",
            )
        if rtype == "family_in" and r.family not in set(rule.get("allowed", [])):
            allowed = ", ".join(rule.get("allowed", []))
            return Violation(
                key, sev, f"{r.name} ({r.family})", target,
                f"{r.name} is a {r.family} algorithm; policy '{self.name}' allows only "
                f"[{allowed}] here ({key}). Use {target}.",
            )
        if rtype == "min_nist_level" and r.nist_level is not None:
            if r.nist_level < int(rule["min"]):
                return Violation(
                    key, sev, f"{r.name} (NIST Level {r.nist_level})", target,
                    f"{r.name} is NIST Level {r.nist_level}; policy '{self.name}' "
                    f"requires Level {rule['min']}+ ({key}). Use {target}.",
                )
        if rtype == "min_key_size" and r.family == rule.get("family"):
            ks = r.key_size
            if ks is not None and ks < int(rule["min"]):
                return Violation(
                    key, sev, f"{r.name} ({ks}-bit)", target,
                    f"{r.name} is {ks}-bit; policy '{self.name}' requires "
                    f"{rule['family']}-{rule['min']}+ ({key}). Use {target}.",
                )
        return None


# Severity ranking mirrors the scanner/spine scale (most urgent first).
_SEVERITY_ORDER = {"immediate": 0, "urgent": 1, "planned": 2}


# --- active policy (module-global, thread-safe) -----------------------------

_lock = threading.RLock()
_active: CryptoPolicy | None = None


def load_policy(source: str | os.PathLike[str] | dict | CryptoPolicy | None = None) -> CryptoPolicy:
    """Resolve a policy from an explicit source, the ``PQCMAP_POLICY`` env var, or default.

    Precedence: an explicit ``source`` (a :class:`CryptoPolicy`, a body dict, or a path)
    wins; otherwise ``PQCMAP_POLICY`` (a JSON file path) is used; otherwise the built-in
    :data:`DEFAULT_POLICY_BODY`.
    """
    if isinstance(source, CryptoPolicy):
        return source
    if isinstance(source, dict):
        return CryptoPolicy.from_dict(source)
    if source is not None:
        return CryptoPolicy.from_file(source)
    env = os.environ.get("PQCMAP_POLICY")
    if env:
        return CryptoPolicy.from_file(env)
    return CryptoPolicy.default()


def get_active_policy() -> CryptoPolicy:
    """The process-wide active policy (lazy-loaded via :func:`load_policy`)."""
    global _active
    with _lock:
        if _active is None:
            _active = load_policy()
        return _active


def set_active_policy(policy: CryptoPolicy | dict | str | os.PathLike[str] | None) -> CryptoPolicy:
    """Install the process-wide active policy; returns it. ``None`` resets to default."""
    global _active
    with _lock:
        _active = load_policy(policy)
        return _active


def _coerce(policy: CryptoPolicy | dict | str | os.PathLike[str] | None) -> CryptoPolicy:
    return get_active_policy() if policy is None else load_policy(policy)


# --- public enforcement API -------------------------------------------------

def compliant(
    algorithm: str,
    *,
    kind: str | None = None,
    policy: CryptoPolicy | dict | str | os.PathLike[str] | None = None,
) -> bool:
    """True iff ``algorithm`` satisfies the policy (non-raising counterpart)."""
    return not _coerce(policy).evaluate(algorithm, kind=kind)


def violations(
    algorithm: str,
    *,
    kind: str | None = None,
    policy: CryptoPolicy | dict | str | os.PathLike[str] | None = None,
) -> list[Violation]:
    """Every :class:`Violation` ``algorithm`` triggers under the policy (empty == ok)."""
    return _coerce(policy).evaluate(algorithm, kind=kind)


def assert_compliant(
    algorithm: str,
    *,
    kind: str | None = None,
    policy: CryptoPolicy | dict | str | os.PathLike[str] | None = None,
) -> None:
    """Raise :class:`PolicyViolationError` if ``algorithm`` is below policy; else return.

    ``kind`` (``"kem"`` / ``"sign"``) scopes which rules apply. ``policy`` overrides the
    active policy for this call.
    """
    vs = _coerce(policy).evaluate(algorithm, kind=kind)
    if vs:
        raise PolicyViolationError(vs[0].message, algorithm=algorithm, violations=vs)


def requires_pqc(
    _func=None,
    *,
    algorithm_arg: str = "algorithm",
    kind: str | None = None,
    policy: CryptoPolicy | dict | str | os.PathLike[str] | None = None,
):
    """Guard a key-minting / signing function so a below-policy algorithm can't be used.

    Reads the algorithm from the wrapped call's ``algorithm_arg`` parameter (positional
    or keyword; falls back to that parameter's default) and runs :func:`assert_compliant`
    before the body executes::

        @requires_pqc(kind="kem")
        def new_session_key(algorithm="ML-KEM-768"): ...

        @requires_pqc(algorithm_arg="alg", kind="sign")
        def mint(alg): ...

    A below-policy algorithm raises :class:`PolicyViolationError` before any key is minted.
    """
    import functools
    import inspect

    def decorate(func):
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            bound = sig.bind_partial(*args, **kwargs)
            if algorithm_arg in bound.arguments:
                alg = bound.arguments[algorithm_arg]
            else:
                param = sig.parameters.get(algorithm_arg)
                if param is None or param.default is inspect.Parameter.empty:
                    raise TypeError(
                        f"@requires_pqc could not find an '{algorithm_arg}' argument on "
                        f"{func.__name__}(); pass algorithm_arg=... to name it."
                    )
                alg = param.default
            assert_compliant(alg, kind=kind, policy=policy)
            return func(*args, **kwargs)

        return wrapper

    return decorate if _func is None else decorate(_func)


__all__ = [
    "CryptoPolicy",
    "Violation",
    "ResolvedAlgorithm",
    "DEFAULT_POLICY_BODY",
    "family_of",
    "resolve",
    "load_policy",
    "get_active_policy",
    "set_active_policy",
    "compliant",
    "violations",
    "assert_compliant",
    "requires_pqc",
]
