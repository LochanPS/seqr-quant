"""Shared fixtures. Tests run against the REAL PQC backend (pure-python here, liboqs
in CI where it is installed) — there is no mock in the product path."""
from __future__ import annotations

import pytest

import pqcmap._backend as backend


@pytest.fixture
def pqc_backend():
    """Ensure a fresh backend selection, then yield the active (real) backend.

    Present so tests can depend on "a working backend"; on this host that is the
    pure-Python FIPS 203/204 backend, in CI it may be liboqs.
    """
    backend._reset_backend_cache()
    b = backend.get_backend()
    assert b is not None, "no PQC backend available (pure-python deps missing?)"
    yield b
    backend._reset_backend_cache()


@pytest.fixture
def no_backend(monkeypatch):
    """Force every backend to look unavailable, for PQCUnavailableError tests."""
    monkeypatch.setattr(backend, "_try_liboqs", lambda: None)
    monkeypatch.setattr(backend, "_try_pure_python", lambda: None)
    backend._reset_backend_cache()
    yield
    backend._reset_backend_cache()


requires_liboqs = pytest.mark.skipif(
    backend.backend_name() != "liboqs",
    reason="liboqs backend not active (pure-python backend in use)",
)
