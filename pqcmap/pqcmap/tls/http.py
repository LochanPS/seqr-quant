"""Ready-made HTTP clients that use pqcmap's best-effort PQC-hybrid TLS context.

    from pqcmap.tls import http
    with http.pqc_httpx_client() as client:
        r = client.get("https://example.com")
        print(client.pqc_capabilities.summary())   # what TLS actually did

Both helpers build their TLS via :func:`pqcmap.tls.build_client_context`, so they
negotiate X25519MLKEM768 where the runtime allows and fall back to secure classical TLS
otherwise. ``httpx`` and ``requests`` are optional — import the one you use; each helper
raises a clear :class:`ImportError` with an install hint if its library is missing.

The returned client carries a ``pqc_capabilities`` attribute (a
:class:`~pqcmap.tls.context.TLSCapabilities`) so callers can log or assert on the
negotiated posture.
"""
from __future__ import annotations

from typing import Any

from pqcmap.tls.context import TLSCapabilities, build_client_context

__all__ = ["pqc_httpx_client", "pqc_requests_session", "PQCTLSAdapter"]

_HTTPX_HINT = "httpx is not installed. Install it with `pip install httpx`."
_REQUESTS_HINT = "requests is not installed. Install it with `pip install requests`."


def pqc_httpx_client(
    *,
    verify: bool = True,
    cafile: str | None = None,
    prefer_pqc: bool = True,
    **httpx_kwargs: Any,
):
    """Return an ``httpx.Client`` whose TLS uses the pqcmap PQC-hybrid context.

    Extra keyword args pass straight to ``httpx.Client``. The client gains a
    ``pqc_capabilities`` attribute describing the runtime's PQC TLS posture.
    """
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised only without httpx
        raise ImportError(_HTTPX_HINT) from exc

    ctx, caps = build_client_context(verify=verify, cafile=cafile, prefer_pqc=prefer_pqc)
    # httpx accepts an ssl.SSLContext as `verify`.
    client = httpx.Client(verify=ctx, **httpx_kwargs)
    client.pqc_capabilities = caps  # type: ignore[attr-defined]
    return client


class PQCTLSAdapter:
    """A ``requests`` HTTPAdapter that drives connections through a given SSLContext.

    Defined as a thin subclass created on demand (so importing this module does not
    require ``requests``). Use via :func:`pqc_requests_session`.
    """

    def __new__(cls, ssl_context, **kwargs):  # noqa: D401 - factory over requests' adapter
        try:
            from requests.adapters import HTTPAdapter
        except ImportError as exc:  # pragma: no cover
            raise ImportError(_REQUESTS_HINT) from exc

        class _Adapter(HTTPAdapter):
            def init_poolmanager(self, *a, **kw):
                kw["ssl_context"] = ssl_context
                return super().init_poolmanager(*a, **kw)

            def proxy_manager_for(self, *a, **kw):
                kw["ssl_context"] = ssl_context
                return super().proxy_manager_for(*a, **kw)

        return _Adapter(**kwargs)


def pqc_requests_session(
    *,
    verify: bool = True,
    cafile: str | None = None,
    prefer_pqc: bool = True,
):
    """Return a ``requests.Session`` whose HTTPS transport uses the pqcmap PQC context.

    The session gains a ``pqc_capabilities`` attribute. Note: ``requests``' own
    ``verify=`` handling is bypassed for the SSLContext, so certificate verification is
    controlled by ``verify`` here (passed into the context).
    """
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - exercised only without requests
        raise ImportError(_REQUESTS_HINT) from exc

    ctx, caps = build_client_context(verify=verify, cafile=cafile, prefer_pqc=prefer_pqc)
    session = requests.Session()
    session.mount("https://", PQCTLSAdapter(ctx))
    session.pqc_capabilities = caps  # type: ignore[attr-defined]
    return session


def capabilities() -> TLSCapabilities:
    """Convenience re-export of the runtime PQC TLS capability probe."""
    from pqcmap.tls.context import capabilities as _caps

    return _caps()
