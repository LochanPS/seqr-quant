"""Runnable FastAPI auth example — login issues an ML-DSA JWT, a dependency verifies it.

This is the "before/after" a real service hits when migrating RS256 auth to PQC. The
only crypto change from a stock PyJWT app is the import and the key type:

    import pqcmap.jwt as jwt                       # was: import jwt
    token  = jwt.encode(claims, signing_key, algorithm="ML-DSA-65")
    claims = jwt.decode(token, verify_key, algorithms=["ML-DSA-65"])

Run it:

    pip install "fastapi" "uvicorn"
    python -m uvicorn examples.fastapi_auth:app --reload

    # get a token
    curl -s -XPOST localhost:8000/login -d '{"username":"alice","password":"password"}' \
         -H 'content-type: application/json'
    # call the protected route
    curl -s localhost:8000/me -H "authorization: Bearer <token>"

The signing keypair is generated in-process on startup for a self-contained demo. A
real service would hold the ML-DSA key in a :class:`pqcmap.kms.local.LocalKeyStore`
(or the hosted KMS) and load the public key into every verifier.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

import pqcmap.jwt as jwt
from pqcmap import Signature
from pqcmap.algorithms import SignAlgorithm

ALGORITHM = SignAlgorithm.ML_DSA_65
TOKEN_TTL_SECONDS = 3600

# Demo signing keypair. Real deployments: load from a key store, never generate per boot.
_keypair = Signature(ALGORITHM).generate_keypair()
SIGNING_KEY = _keypair.secret_key
VERIFY_KEY = _keypair.public_key

# Toy user store. Real deployments: a database + a real password hash (argon2/bcrypt).
_USERS = {"alice": "password", "bob": "hunter2"}

app = FastAPI(title="pqcmap ML-DSA auth example")


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    algorithm: str = ALGORITHM


@app.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """Authenticate a user and mint an ML-DSA-signed JWT."""
    if _USERS.get(body.username) != body.password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad username or password.")
    now = int(time.time())
    claims = {"sub": body.username, "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    token = jwt.encode(claims, SIGNING_KEY, algorithm=ALGORITHM)
    return TokenResponse(access_token=token)


def current_user(authorization: str = Header(default="")) -> dict[str, Any]:
    """Dependency: verify the Bearer ML-DSA JWT and return its claims.

    Rejects a missing header, a wrong scheme, an expired token, a bad signature, or a
    token signed with an algorithm outside the allow-list.
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing or malformed Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return jwt.decode(token, VERIFY_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token.")


@app.get("/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    """A protected route — reachable only with a valid ML-DSA token."""
    return {"user": user["sub"], "claims": user}


if __name__ == "__main__":  # pragma: no cover - manual run
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
