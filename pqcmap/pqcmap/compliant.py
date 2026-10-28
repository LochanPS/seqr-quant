"""Policy-checked drop-ins for the pqcmap primitives.

These are the ordinary primitives with a guard bolted on the front: constructing one
runs the active crypto policy over the chosen algorithm and raises
:class:`~pqcmap.core.exceptions.PolicyViolationError` for a below-policy choice — before
any key is minted. Everything else behaves identically to the plain classes.

    from pqcmap.compliant import KeyEncapsulation, Signature

    KeyEncapsulation()                 # ML-KEM-768 — ok under the default policy
    KeyEncapsulation("ML-KEM-512")     # raises PolicyViolationError (below NIST Level 3)

Pass ``policy=`` to check against a specific policy instead of the process-wide active
one; otherwise :func:`pqcmap.policy.get_active_policy` decides.
"""
from __future__ import annotations

import os

from pqcmap import algorithms
from pqcmap.core.kem import KeyEncapsulation as _KeyEncapsulation
from pqcmap.core.sign import Signature as _Signature
from pqcmap.policy import CryptoPolicy, assert_compliant


class KeyEncapsulation(_KeyEncapsulation):
    """:class:`pqcmap.KeyEncapsulation`, but the algorithm must satisfy the KEM policy."""

    def __init__(
        self,
        algorithm: str = algorithms.DEFAULT_KEM,
        *,
        policy: "CryptoPolicy | dict | str | os.PathLike[str] | None" = None,
    ):
        assert_compliant(algorithm, kind="kem", policy=policy)
        super().__init__(algorithm)


class Signature(_Signature):
    """:class:`pqcmap.Signature`, but the algorithm must satisfy the signature policy."""

    def __init__(
        self,
        algorithm: str = algorithms.DEFAULT_SIGN,
        *,
        policy: "CryptoPolicy | dict | str | os.PathLike[str] | None" = None,
    ):
        assert_compliant(algorithm, kind="sign", policy=policy)
        super().__init__(algorithm)


__all__ = ["KeyEncapsulation", "Signature"]
