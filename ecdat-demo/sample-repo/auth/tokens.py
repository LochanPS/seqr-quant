"""ACME Bank — customer session tokens.

Issues the JWTs that authenticate customers to the mobile app and net-banking
portal. Signed with the RSA key so downstream services can verify offline.
"""

import jwt
import datetime

from payments.rsa_keys import generate_settlement_signing_key

# In production this is loaded from the HSM-backed keystore.
_SIGNING_KEY = generate_settlement_signing_key()


def issue_session_token(customer_id: str) -> str:
    payload = {
        "sub": customer_id,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12),
        "scope": "netbanking",
    }
    # RS256 = RSA signature — quantum-vulnerable.
    token = jwt.encode(payload, _SIGNING_KEY, algorithm="RS256")
    return token
