"""Crypto backend selection.

pqcmap runs **real** NIST PQC through one of two interchangeable backends:

* ``pure-python`` — kyber-py (ML-KEM / FIPS 203) + dilithium-py (ML-DSA / FIPS 204).
  Pure-Python reference implementations: no C toolchain, install everywhere (incl.
  Windows), always available. These are hard dependencies, so pqcmap works out of the
  box with real crypto — there is no mock in the product path.
* ``liboqs`` — the Open Quantum Safe C library via ``oqs``. Faster, and adds algorithms
  the pure backend lacks (e.g. SLH-DSA). Optional (``pip install pqcmap[liboqs]``).
  Its binding builds liboqs from source at import time when no prebuilt lib is present,
  raising ``SystemExit`` on failure — so we probe for it cheaply and import-free first.

Selection prefers liboqs (speed) and falls back to pure-python. All wrappers call the
selected backend through the small adapter interface below, so they never touch a
specific library directly.
"""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

from pqcmap.core.exceptions import PQCUnavailableError, UnsupportedAlgorithmError

_INSTALL_HINT = (
    "No PQC backend is available. pqcmap normally ships the pure-Python backend "
    "(kyber-py + dilithium-py) as a hard dependency; reinstall with `pip install pqcmap` "
    "to restore it. For the faster native backend, `pip install pqcmap[liboqs]`."
)


# --------------------------------------------------------------------------- #
# Backend adapters
# --------------------------------------------------------------------------- #

class _PurePythonBackend:
    """kyber-py (ML-KEM) + dilithium-py (ML-DSA). Real FIPS 203/204 crypto, pure Python."""

    name = "pure-python"

    def __init__(self):
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

        self._kem = {
            "ML-KEM-512": ML_KEM_512,
            "ML-KEM-768": ML_KEM_768,
            "ML-KEM-1024": ML_KEM_1024,
        }
        self._sig = {
            "ML-DSA-44": ML_DSA_44,
            "ML-DSA-65": ML_DSA_65,
            "ML-DSA-87": ML_DSA_87,
        }

    def _kem_cls(self, alg):
        try:
            return self._kem[alg]
        except KeyError:
            raise UnsupportedAlgorithmError(
                f"{alg!r} is not supported by the pure-python backend "
                f"(install pqcmap[liboqs] for it)."
            ) from None

    def _sig_cls(self, alg):
        try:
            return self._sig[alg]
        except KeyError:
            raise UnsupportedAlgorithmError(
                f"{alg!r} is not supported by the pure-python backend "
                f"(install pqcmap[liboqs] for it)."
            ) from None

    def kem_keypair(self, alg):
        ek, dk = self._kem_cls(alg).keygen()
        return bytes(ek), bytes(dk)

    def kem_encaps(self, alg, public_key):
        shared, ciphertext = self._kem_cls(alg).encaps(public_key)
        return bytes(ciphertext), bytes(shared)

    def kem_decaps(self, alg, secret_key, ciphertext):
        return bytes(self._kem_cls(alg).decaps(secret_key, ciphertext))

    def sign_keypair(self, alg):
        pk, sk = self._sig_cls(alg).keygen()
        return bytes(pk), bytes(sk)

    def sign(self, alg, secret_key, message):
        return bytes(self._sig_cls(alg).sign(secret_key, message))

    def verify(self, alg, public_key, signature, message):
        return bool(self._sig_cls(alg).verify(public_key, message, signature))


class _LiboqsBackend:
    """Open Quantum Safe liboqs via the ``oqs`` binding. Faster; optional dependency."""

    name = "liboqs"

    def kem_keypair(self, alg):
        import oqs

        with oqs.KeyEncapsulation(alg) as k:
            pk = k.generate_keypair()
            sk = k.export_secret_key()
        return bytes(pk), bytes(sk)

    def kem_encaps(self, alg, public_key):
        import oqs

        with oqs.KeyEncapsulation(alg) as k:
            ct, ss = k.encap_secret(public_key)
        return bytes(ct), bytes(ss)

    def kem_decaps(self, alg, secret_key, ciphertext):
        import oqs

        with oqs.KeyEncapsulation(alg, secret_key=secret_key) as k:
            return bytes(k.decap_secret(ciphertext))

    def sign_keypair(self, alg):
        import oqs

        with oqs.Signature(alg) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        return bytes(pk), bytes(sk)

    def sign(self, alg, secret_key, message):
        import oqs

        with oqs.Signature(alg, secret_key=secret_key) as s:
            return bytes(s.sign(message))

    def verify(self, alg, public_key, signature, message):
        import oqs

        with oqs.Signature(alg) as s:
            return bool(s.verify(message, signature, public_key))


# --------------------------------------------------------------------------- #
# Availability probes + selection
# --------------------------------------------------------------------------- #

_UNSET = object()
_backend_cache = _UNSET


def _liboqs_lib_present() -> bool:
    """Cheaply check for an already-built liboqs shared library.

    Never imports ``oqs`` and never triggers its source auto-installer.
    """
    import ctypes.util

    for name in ("oqs", "liboqs"):
        try:
            if ctypes.util.find_library(name):
                return True
        except Exception:
            pass

    root = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    system = platform.system()
    if system == "Windows":
        candidates = [root / "bin" / "oqs.dll", root / "bin" / "liboqs.dll"]
    elif system == "Darwin":
        candidates = [root / d / "liboqs.dylib" for d in ("lib", "lib64")]
    else:
        candidates = [root / d / "liboqs.so" for d in ("lib", "lib64")]
    return any(c.exists() for c in candidates)


def _try_liboqs() -> _LiboqsBackend | None:
    if "oqs" not in sys.modules and not _liboqs_lib_present():
        return None
    try:
        import oqs

        with oqs.KeyEncapsulation("ML-KEM-768"):
            pass
        return _LiboqsBackend()
    except BaseException:  # ImportError, SystemExit from auto-build, native errors
        return None


def _try_pure_python() -> _PurePythonBackend | None:
    try:
        return _PurePythonBackend()
    except Exception:
        return None


def get_backend():
    """Return the selected backend (liboqs preferred, then pure-python), or None.

    Cached after the first call. Never triggers a liboqs source build.
    """
    global _backend_cache
    if _backend_cache is not _UNSET:
        return _backend_cache
    _backend_cache = _try_liboqs() or _try_pure_python()
    return _backend_cache


def require_backend():
    """Return the selected backend or raise :class:`PQCUnavailableError`."""
    backend = get_backend()
    if backend is None:
        raise PQCUnavailableError(_INSTALL_HINT)
    return backend


def backend_available() -> bool:
    """True iff a real PQC backend is usable (pure-python is always installed)."""
    return get_backend() is not None


def backend_name() -> str | None:
    """Name of the active backend (``"liboqs"`` / ``"pure-python"``) or None."""
    backend = get_backend()
    return backend.name if backend else None


def _reset_backend_cache() -> None:
    """Test hook — clear the cached backend selection."""
    global _backend_cache
    _backend_cache = _UNSET
