"""ACME Bank — settlement signing keys (MIGRATED to post-quantum).

This is the same service as the legacy repo, after migration to SeQr's
quantum-safe SDK. No classical RSA / ECC / DH remains.
"""

import pqcmap


def generate_settlement_signing_key():
    """ML-DSA-65 (FIPS 204) signing key — quantum-safe."""
    sig = pqcmap.Signature("ML-DSA-65")
    return sig.generate_keypair()


def establish_card_channel():
    """ML-KEM-768 (FIPS 203) key exchange — quantum-safe."""
    kem = pqcmap.KeyEncapsulation("ML-KEM-768")
    return kem.generate_keypair()
