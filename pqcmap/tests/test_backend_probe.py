"""Backend selection + PQCUnavailableError behaviour."""
import pytest

import pqcmap
from pqcmap import KeyEncapsulation, Signature
from pqcmap.core.exceptions import PQCUnavailableError

from tests.conftest import requires_liboqs


def test_available_true_out_of_the_box(pqc_backend):
    # Pure-python backend is a hard dependency, so real PQC is always available.
    assert pqcmap.available() is True
    assert pqcmap.backend() in {"pure-python", "liboqs"}


def test_available_false_only_when_backends_removed(no_backend):
    assert pqcmap.available() is False
    assert pqcmap.backend() is None


def test_pqc_ops_raise_clear_error_without_backend(no_backend):
    with pytest.raises(PQCUnavailableError) as exc:
        KeyEncapsulation().generate_keypair()
    assert "pip install pqcmap" in str(exc.value)
    with pytest.raises(PQCUnavailableError):
        Signature().generate_keypair()


def test_backend_selection_is_cached(pqc_backend):
    assert pqcmap.backend() == pqcmap.backend()


@requires_liboqs
def test_liboqs_backend_active_when_installed(pqc_backend):
    assert pqcmap.backend() == "liboqs"
