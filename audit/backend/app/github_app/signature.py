"""Validate the GitHub webhook signature (HMAC-SHA256).

GitHub signs every webhook body with the App's webhook secret and sends the digest in the
``X-Hub-Signature-256`` header as ``sha256=<hex>``. We recompute it over the *raw* request
body and compare in constant time. An unsigned, mis-signed, or malformed request is
rejected before any parsing — the webhook endpoint is otherwise an unauthenticated,
internet-facing code path.
"""
from __future__ import annotations

import hashlib
import hmac

_PREFIX = "sha256="


class SignatureError(Exception):
    """Raised when a webhook signature is missing, malformed, or does not match."""


def compute_signature(secret: str, body: bytes) -> str:
    """Return the ``sha256=<hex>`` signature GitHub would send for ``body``."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return _PREFIX + digest


def verify_signature(secret: str, body: bytes, header: str | None) -> None:
    """Verify ``header`` against HMAC-SHA256 of ``body`` under ``secret``.

    Raises :class:`SignatureError` on any failure. Returns ``None`` on success.

    A missing secret is a configuration error (the App must not accept unsigned webhooks),
    so it is treated as a failure rather than skipped.
    """
    if not secret:
        raise SignatureError("webhook secret is not configured")
    if not header:
        raise SignatureError("missing X-Hub-Signature-256 header")
    if not header.startswith(_PREFIX):
        raise SignatureError("malformed signature header (expected sha256=…)")

    expected = compute_signature(secret, body)
    # Constant-time compare over the full "sha256=<hex>" strings.
    if not hmac.compare_digest(expected, header):
        raise SignatureError("signature mismatch")


__all__ = ["verify_signature", "compute_signature", "SignatureError"]
