"""PQCToken — a drop-in PyJWT-style token signed with ML-DSA instead of RSA/ECDSA.

    from pqcmap.jwt import PQCToken
    token = PQCToken.encode({"user_id": "123", "exp": ...}, secret_key)
    claims = PQCToken.decode(token, public_key)

Compact serialisation matches the JOSE shape developers already know:
    base64url(header) "." base64url(payload) "." base64url(signature)
The signature covers ``header.payload`` exactly (the "signing input"), so any tamper
fails verification. ``exp`` is honoured if present (seconds since epoch), raising
:class:`PQCTokenExpiredError`. This is *not* RFC 7519-wire-compatible with RS256 —
ML-DSA is a different ``alg`` — but the developer ergonomics are identical.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from pqcmap import algorithms
from pqcmap.core.exceptions import (
    PQCTokenExpiredError,
    PQCTokenInvalidError,
    PQCTokenSignatureError,
)
from pqcmap.core.sign import Signature
from pqcmap.utils import encoding

_TYP = "PQC-JWT"


class PQCToken:
    @staticmethod
    def encode(
        payload: dict[str, Any],
        secret_key: bytes,
        algorithm: str = algorithms.DEFAULT_SIGN,
        headers: Optional[dict[str, Any]] = None,
    ) -> str:
        """Sign ``payload`` and return a compact token string.

        Extra ``headers`` are merged into the JOSE header (``alg`` / ``typ`` are set
        by pqcmap and win). The signature covers the final header, so header tampering
        is detected too.
        """
        header = {**(headers or {}), "alg": algorithm, "typ": _TYP}
        signing_input = PQCToken._signing_input(header, payload)
        signature = Signature(algorithm).sign(signing_input.encode("ascii"), secret_key)
        return f"{signing_input}.{encoding.b64u_encode(signature)}"

    @staticmethod
    def decode(
        token: str,
        public_key: bytes,
        *,
        verify_exp: bool = True,
        leeway: int = 0,
    ) -> dict[str, Any]:
        """Verify ``token`` against ``public_key`` and return its claims.

        Raises :class:`PQCTokenInvalidError` on a malformed token or bad signature,
        and :class:`PQCTokenExpiredError` when a present ``exp`` claim has passed.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise PQCTokenInvalidError("Token must have three dot-separated segments.")
        header_b64, payload_b64, sig_b64 = parts

        try:
            header = json.loads(encoding.b64u_decode(header_b64))
            payload = json.loads(encoding.b64u_decode(payload_b64))
            signature = encoding.b64u_decode(sig_b64)
        except Exception as exc:  # decode / JSON errors → invalid, never a crash
            raise PQCTokenInvalidError(f"Malformed token: {exc}") from exc

        algorithm = header.get("alg")
        if algorithm not in algorithms.SIGN_ALGORITHMS:
            raise PQCTokenInvalidError(f"Unsupported token alg {algorithm!r}.")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            ok = Signature(algorithm).verify(signing_input, signature, public_key)
        except Exception as exc:  # wrong-size key, bad bytes → invalid, never a crash
            raise PQCTokenInvalidError(f"Could not verify token: {exc}") from exc
        if not ok:
            raise PQCTokenSignatureError("Signature verification failed.")

        if verify_exp and "exp" in payload:
            try:
                exp = float(payload["exp"])
            except (TypeError, ValueError) as exc:
                raise PQCTokenInvalidError("Invalid 'exp' claim.") from exc
            if time.time() > exp + leeway:
                raise PQCTokenExpiredError("Token has expired.")

        return payload

    @staticmethod
    def _signing_input(header: dict, payload: dict) -> str:
        # sort_keys keeps the bytes deterministic so re-serialisation on decode is
        # never needed — we sign/verify the exact received segments instead.
        h = encoding.b64u_encode(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        p = encoding.b64u_encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        return f"{h}.{p}"
