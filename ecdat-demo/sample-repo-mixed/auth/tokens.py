"""ACME Bank — customer session tokens (MIGRATED to post-quantum).

Session JWTs are now signed with ML-DSA instead of RSA.
"""

import pqcmap


def issue_session_token(customer_id: str) -> str:
    token = pqcmap.PQCToken("ML-DSA-65")
    return token.sign({"sub": customer_id, "scope": "netbanking"})
