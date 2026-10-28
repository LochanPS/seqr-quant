"""Algorithm constants + metadata (no crypto backend needed)."""
import pytest

from pqcmap import KEMAlgorithm, SignAlgorithm, algorithms
from pqcmap.core.exceptions import UnsupportedAlgorithmError


def test_defaults_are_level_3():
    assert algorithms.DEFAULT_KEM == "ML-KEM-768"
    assert algorithms.DEFAULT_SIGN == "ML-DSA-65"
    assert algorithms.meta(algorithms.DEFAULT_KEM).nist_level == 3
    assert algorithms.meta(algorithms.DEFAULT_SIGN).nist_level == 3


def test_kem_and_sign_sets_are_disjoint_and_complete():
    assert KEMAlgorithm.ML_KEM_768 in algorithms.KEM_ALGORITHMS
    assert SignAlgorithm.ML_DSA_65 in algorithms.SIGN_ALGORITHMS
    assert algorithms.KEM_ALGORITHMS.isdisjoint(algorithms.SIGN_ALGORITHMS)
    assert algorithms.KEM_ALGORITHMS | algorithms.SIGN_ALGORITHMS == set(
        algorithms.ALGORITHM_META
    )


def test_known_sizes_match_fips_parameter_sets():
    m = algorithms.meta("ML-KEM-768")
    assert (m.public_key_bytes, m.secret_key_bytes, m.output_bytes) == (1184, 2400, 1088)
    m = algorithms.meta("ML-DSA-65")
    assert (m.public_key_bytes, m.output_bytes) == (1952, 3309)


def test_unknown_algorithm_raises():
    with pytest.raises(UnsupportedAlgorithmError):
        algorithms.meta("RSA-2048")
