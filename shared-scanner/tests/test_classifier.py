"""
Unit tests for engines/classifier.py.
No network needed — pure function tests.
"""

import pytest
from engines.classifier import (
    AlgorithmClassification,
    classify_algorithm,
    classify_tls_version,
    recommended_algorithm,
)


class TestClassifyAlgorithm:
    def test_rsa_2048_is_vulnerable(self):
        c = classify_algorithm("RSA", key_size=2048)
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 8
        assert c.algorithm_family == "RSA"
        assert c.hndl_candidate is True

    def test_rsa_4096_is_still_vulnerable(self):
        c = classify_algorithm("RSA", key_size=4096)
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 7

    def test_rsa_1024_is_deprecated(self):
        c = classify_algorithm("RSA", key_size=1024)
        assert c.quantum_status == "deprecated"
        assert c.algorithm_risk == 9

    def test_rsa_512_is_critically_deprecated(self):
        c = classify_algorithm("RSA", key_size=512)
        assert c.quantum_status == "deprecated"
        assert c.algorithm_risk == 10

    def test_ecdsa_p256_is_vulnerable(self):
        c = classify_algorithm("ECDSA-P256")
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 7

    def test_ecdsa_p384_lower_risk(self):
        c = classify_algorithm("ECDSA-P384")
        assert c.algorithm_risk == 6

    def test_ml_kem_768_is_safe(self):
        c = classify_algorithm("ML-KEM-768")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0

    def test_ml_dsa_65_is_safe(self):
        c = classify_algorithm("ML-DSA-65")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0
        assert c.hndl_candidate is False

    def test_aes_256_is_safe(self):
        c = classify_algorithm("AES-256")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0

    def test_aes_128_low_risk(self):
        c = classify_algorithm("AES-128")
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 2

    def test_sha_1_deprecated(self):
        c = classify_algorithm("SHA-1")
        assert c.quantum_status == "deprecated"
        assert c.algorithm_risk == 10

    def test_sha_256_safe(self):
        c = classify_algorithm("SHA-256")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0

    def test_ed25519_vulnerable_not_hndl(self):
        c = classify_algorithm("Ed25519")
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 5
        assert c.hndl_candidate is False

    def test_dh_small_key_deprecated(self):
        c = classify_algorithm("DHE", key_size=1024)
        assert c.quantum_status == "deprecated"

    def test_dh_2048_vulnerable(self):
        c = classify_algorithm("DH", key_size=2048)
        assert c.quantum_status == "vulnerable"

    def test_case_insensitive(self):
        c1 = classify_algorithm("rsa", key_size=2048)
        c2 = classify_algorithm("RSA", key_size=2048)
        assert c1.quantum_status == c2.quantum_status
        assert c1.algorithm_risk == c2.algorithm_risk

    def test_openssl_prime256v1_maps_to_ecdsa_p256(self):
        c = classify_algorithm("prime256v1")
        assert c.algorithm_family == "ECC"
        assert c.quantum_status == "vulnerable"

    def test_hybrid_pqc_cipher_is_safe(self):
        c = classify_algorithm("X25519Kyber768")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0

    def test_unknown_algorithm_returns_unknown(self):
        c = classify_algorithm("SOME-UNKNOWN-ALGO-XYZ")
        assert c.quantum_status == "unknown"

    def test_slh_dsa_safe(self):
        c = classify_algorithm("SLH-DSA")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0


class TestClassifyTLSVersion:
    def test_tls_10_deprecated(self):
        c = classify_tls_version("TLS_1_0")
        assert c.quantum_status == "deprecated"
        assert c.algorithm_risk == 9

    def test_tls_11_deprecated(self):
        c = classify_tls_version("TLS_1_1")
        assert c.quantum_status == "deprecated"

    def test_tls_12_moderate(self):
        c = classify_tls_version("TLS_1_2")
        assert c.quantum_status == "vulnerable"
        assert c.algorithm_risk == 4

    def test_tls_13_safe(self):
        c = classify_tls_version("TLS_1_3")
        assert c.quantum_status == "safe"
        assert c.algorithm_risk == 0

    def test_tls_with_dot_notation(self):
        c = classify_tls_version("TLS 1.2")
        assert c.quantum_status == "vulnerable"

    def test_ssl_20_critical(self):
        c = classify_tls_version("SSL_2_0")
        assert c.quantum_status == "deprecated"
        assert c.algorithm_risk == 10

    def test_unknown_version(self):
        c = classify_tls_version("TLS_9_9")
        assert c.quantum_status == "unknown"


class TestRecommendedAlgorithm:
    def test_rsa_recommends_ml_dsa_and_ml_kem(self):
        algo, fips = recommended_algorithm("RSA")
        assert "ML-DSA" in algo
        assert "ML-KEM" in algo

    def test_ecdsa_recommends_ml_dsa(self):
        algo, fips = recommended_algorithm("ECDSA")
        assert "ML-DSA" in algo
        assert "FIPS 204" in fips

    def test_ecdh_recommends_ml_kem(self):
        algo, fips = recommended_algorithm("ECDH")
        assert "ML-KEM" in algo
        assert "FIPS 203" in fips

    def test_sha1_recommends_sha256(self):
        algo, fips = recommended_algorithm("SHA-1")
        assert "SHA-256" in algo

    def test_tls10_recommends_tls13(self):
        algo, fips = recommended_algorithm("TLS_1_0")
        assert "TLS 1.3" in algo
