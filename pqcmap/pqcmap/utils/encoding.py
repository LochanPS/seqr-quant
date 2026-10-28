"""Serialisation helpers for raw key / ciphertext bytes.

liboqs emits raw bytes; these helpers move them to/from the text forms developers
actually store and transmit (base64url for JSON/JWT, hex for logs, a light PEM-style
armor for files). All are pure and backend-free.
"""
from __future__ import annotations

import base64
import binascii

from pqcmap.core.exceptions import PQCError


def b64u_encode(data: bytes) -> str:
    """URL-safe base64 without padding — the JOSE/JWT convention."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Inverse of :func:`b64u_encode`; tolerates missing padding."""
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (binascii.Error, ValueError) as exc:
        raise PQCError(f"Invalid base64url input: {exc}") from exc


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise PQCError(f"Invalid hex input: {exc}") from exc


def to_pem(data: bytes, label: str) -> str:
    """Wrap raw bytes in a PEM-style armor, e.g. label='ML-KEM-768 PUBLIC KEY'.

    Not an ASN.1/SPKI encoding — a transport wrapper for raw PQC keys, which have no
    universally deployed ASN.1 OID story yet. Round-trips with :func:`from_pem`.
    """
    label = label.upper()
    body = base64.b64encode(data).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    inner = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{inner}\n-----END {label}-----\n"


def from_pem(text: str) -> bytes:
    """Extract raw bytes from :func:`to_pem` output (ignores the label)."""
    lines = [ln.strip() for ln in text.strip().splitlines()]
    body = "".join(
        ln for ln in lines if ln and not ln.startswith("-----")
    )
    if not body:
        raise PQCError("No PEM body found.")
    try:
        return base64.b64decode(body)
    except (binascii.Error, ValueError) as exc:
        raise PQCError(f"Invalid PEM body: {exc}") from exc
