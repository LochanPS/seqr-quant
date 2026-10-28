"""PQC-signed JSON Web Tokens (ML-DSA).

Two entry points:

* :class:`PQCToken` — the explicit ``PQCToken.encode`` / ``.decode`` API.
* A **PyJWT-shaped** module surface (``encode`` / ``decode`` / ``get_unverified_header``
  and PyJWT-named exceptions) so a codebase can migrate by changing only its import:

      import pqcmap.jwt as jwt      # was: import jwt
      token  = jwt.encode(payload, mldsa_secret, algorithm="ML-DSA-65")
      claims = jwt.decode(token, mldsa_public, algorithms=["ML-DSA-65"])
"""
from pqcmap.jwt.pyjwt_adapter import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
    decode,
    encode,
    get_unverified_header,
)
from pqcmap.jwt.token import PQCToken

__all__ = [
    "PQCToken",
    "encode",
    "decode",
    "get_unverified_header",
    "InvalidTokenError",
    "DecodeError",
    "InvalidSignatureError",
    "ExpiredSignatureError",
    "InvalidAlgorithmError",
]
