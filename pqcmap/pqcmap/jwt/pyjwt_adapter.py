"""PyJWT-shaped façade over :class:`~pqcmap.jwt.token.PQCToken`.

The most common code-level PQC migration is an RS256/ES256 JWT. This module makes
that a *one-line import change*: the ``encode`` / ``decode`` signatures and the
exception names mirror `PyJWT <https://pyjwt.readthedocs.io>`_, so existing call
sites and ``except`` handlers keep working with ML-DSA underneath.

    # before — PyJWT, RSA
    import jwt
    token  = jwt.encode({"user_id": "123"}, rsa_priv, algorithm="RS256")
    claims = jwt.decode(token, rsa_pub, algorithms=["RS256"])

    # after — pqcmap, ML-DSA
    from pqcmap import jwt                      # or: import pqcmap.jwt as jwt
    token  = jwt.encode({"user_id": "123"}, mldsa_priv, algorithm="ML-DSA-65")
    claims = jwt.decode(token, mldsa_pub, algorithms=["ML-DSA-65"])

Differences from PyJWT that are intentional and honest:

* ``algorithm`` / ``algorithms`` take pqcmap names (``ML-DSA-65`` …), not ``RS256``.
* ``key`` is raw ML-DSA key *bytes* (from a :class:`~pqcmap.kms.local.LocalKeyStore`
  or ``Signature().generate_keypair()``), not a PEM/`cryptography` key object.
* This is **not** RFC 7519 wire-compatible with an RS256 verifier — ML-DSA is a
  different ``alg``. It is drop-in at the *code* level, not the token-format level.

Every exception here subclasses both the PyJWT-shaped name **and** pqcmap's
``PQCTokenError`` (hence ``PQCError``), so ``except jwt.ExpiredSignatureError`` and
``except pqcmap.PQCError`` both catch it.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from pqcmap import algorithms
from pqcmap.core.exceptions import (
    PQCTokenError,
    PQCTokenExpiredError,
    PQCTokenInvalidError,
    PQCTokenSignatureError,
)
from pqcmap.jwt.token import PQCToken
from pqcmap.utils import encoding

__all__ = [
    "encode",
    "decode",
    "get_unverified_header",
    "InvalidTokenError",
    "DecodeError",
    "InvalidSignatureError",
    "ExpiredSignatureError",
    "InvalidAlgorithmError",
]


# --- PyJWT-shaped exception hierarchy (also pqcmap PQCTokenErrors) ---------------

class InvalidTokenError(PQCTokenError):
    """Base for token errors — mirrors ``jwt.InvalidTokenError``."""


class DecodeError(InvalidTokenError):
    """The token could not be decoded (malformed / unreadable)."""


class InvalidSignatureError(DecodeError):
    """The token's signature did not verify — mirrors ``jwt.InvalidSignatureError``."""


class ExpiredSignatureError(InvalidTokenError):
    """The token's ``exp`` claim has passed — mirrors ``jwt.ExpiredSignatureError``."""


class InvalidAlgorithmError(InvalidTokenError):
    """The token's ``alg`` is not in the caller's allowed ``algorithms`` list."""


# --- API ------------------------------------------------------------------------

def encode(
    payload: dict[str, Any],
    key: bytes,
    algorithm: str = algorithms.DEFAULT_SIGN,
    headers: Optional[dict[str, Any]] = None,
) -> str:
    """PyJWT-shaped ``encode``: sign ``payload`` with an ML-DSA secret ``key``.

    Returns the compact token string. ``algorithm`` must be an ML-DSA parameter set
    (see :class:`pqcmap.algorithms.SignAlgorithm`).
    """
    if algorithm not in algorithms.SIGN_ALGORITHMS:
        raise InvalidAlgorithmError(
            f"{algorithm!r} is not a pqcmap signature algorithm. "
            f"Choose one of: {', '.join(sorted(algorithms.SIGN_ALGORITHMS))}."
        )
    return PQCToken.encode(payload, key, algorithm=algorithm, headers=headers)


def decode(
    token: str,
    key: bytes,
    algorithms: Optional[Iterable[str]] = None,  # noqa: A002 - PyJWT-compatible name
    *,
    options: Optional[dict[str, Any]] = None,
    leeway: float = 0,
) -> dict[str, Any]:
    """PyJWT-shaped ``decode``: verify ``token`` against an ML-DSA public ``key``.

    ``algorithms`` is required (as in PyJWT ≥ 2) — the explicit allow-list of accepted
    ``alg`` values, which prevents an attacker downgrading the token's algorithm.

    Raises :class:`ExpiredSignatureError`, :class:`InvalidSignatureError`,
    :class:`InvalidAlgorithmError`, or :class:`DecodeError` — all also
    :class:`~pqcmap.core.exceptions.PQCError`.
    """
    # Import here so this name shadows the module-level `algorithms` module only
    # inside this function's signature, not its body.
    from pqcmap import algorithms as _alg

    allowed = list(algorithms) if algorithms is not None else None
    if not allowed:
        raise DecodeError(
            "It is required that you pass in a value for the 'algorithms' argument "
            "when calling decode()."
        )

    header = get_unverified_header(token)
    alg = header.get("alg")
    if alg not in allowed:
        raise InvalidAlgorithmError(
            f"The token's algorithm {alg!r} is not in the allowed set {allowed}."
        )
    if alg not in _alg.SIGN_ALGORITHMS:
        raise InvalidAlgorithmError(f"Unsupported token algorithm {alg!r}.")

    verify_exp = True
    if options is not None and options.get("verify_exp") is False:
        verify_exp = False

    try:
        return PQCToken.decode(token, key, verify_exp=verify_exp, leeway=int(leeway))
    except PQCTokenExpiredError as exc:
        raise ExpiredSignatureError(str(exc)) from exc
    except PQCTokenSignatureError as exc:
        raise InvalidSignatureError(str(exc)) from exc
    except PQCTokenInvalidError as exc:
        raise DecodeError(str(exc)) from exc


def get_unverified_header(token: str) -> dict[str, Any]:
    """Return the token's JOSE header without verifying the signature.

    Mirrors ``jwt.get_unverified_header``. Useful to read ``alg`` / ``kid`` before
    fetching the matching public key. **Never trust these claims** — they are
    unauthenticated until :func:`decode` succeeds.
    """
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise DecodeError("Not enough segments in token.")
    try:
        return json.loads(encoding.b64u_decode(parts[0]))
    except Exception as exc:
        raise DecodeError(f"Invalid header: {exc}") from exc
