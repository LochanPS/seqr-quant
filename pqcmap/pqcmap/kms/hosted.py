"""HostedKMS — client for the SeQr hosted Key Management Service.

The revenue-side counterpart to :class:`~pqcmap.kms.local.LocalKeyStore`: the *master
key never leaves the KMS*. The client uses **envelope encryption** — the KMS mints a
short-lived data key (returned once in plaintext, plus a copy wrapped under the master
key), the client encrypts data locally under that data key, and stores only the wrapped
form. Decryption asks the KMS to unwrap the data key; the master key stays server-side.

    kms = HostedKMS(endpoint="https://kms.seqrlabs.com", api_key="sq_live_…")
    blob = kms.encrypt(b"card number", master_key_id="mk-prod-1")   # -> self-describing bytes
    assert kms.decrypt(blob) == b"card number"

Authentication is a bearer API key (the SeQr ``sq_live_`` format). HTTP status maps to
the pqcmap error family: 401/403 → :class:`KMSAuthError`, 404 → :class:`KMSKeyNotFoundError`,
any other non-2xx (or a transport failure) → :class:`KMSError`.

The network layer is a pluggable ``transport`` callable, so tests inject a mock while the
**local envelope crypto stays real**. The default transport is stdlib ``urllib`` over
pqcmap's best-effort PQC-hybrid TLS context.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcmap.core.exceptions import KMSAuthError, KMSError, KMSKeyNotFoundError
from pqcmap.utils import encoding

# Envelope wire format: magic || u16 mkid_len || mkid || u16 wrapped_len || wrapped
#                       || nonce(12) || ciphertext
_MAGIC = b"PQCKMS1"
_NONCE_LEN = 12
_DEFAULT_DATA_KEY_BYTES = 32  # AES-256

__all__ = ["HostedKMS", "DataKey", "HTTPResponse"]


@dataclass(frozen=True)
class HTTPResponse:
    """Minimal transport response — a status and a raw body."""

    status: int
    body: bytes

    def json(self) -> dict:
        return json.loads(self.body.decode("utf-8"))


# transport(method, url, headers, body) -> HTTPResponse
Transport = Callable[[str, str, dict, Optional[bytes]], HTTPResponse]


@dataclass(frozen=True)
class DataKey:
    """A KMS-minted data key: ``plaintext`` for immediate use, ``wrapped`` to persist."""

    plaintext: bytes
    wrapped: bytes
    master_key_id: str


class HostedKMS:
    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        timeout: float = 10.0,
        transport: Optional[Transport] = None,
        verify_tls: bool = True,
    ):
        if not endpoint:
            raise KMSError("A KMS endpoint URL is required.")
        if not api_key:
            raise KMSAuthError("A KMS API key is required.")
        self.endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._transport = transport or _UrllibTransport(timeout, verify_tls)

    # -- high-level envelope API --------------------------------------------------

    def generate_data_key(
        self, master_key_id: str, *, key_bytes: int = _DEFAULT_DATA_KEY_BYTES
    ) -> DataKey:
        """Ask the KMS to mint a data key under ``master_key_id`` (envelope pattern)."""
        body = self._request(
            "POST",
            f"/v1/keys/{master_key_id}/data-key",
            {"key_bytes": key_bytes},
        )
        return DataKey(
            plaintext=self._b64(body, "plaintext"),
            wrapped=self._b64(body, "ciphertext"),
            master_key_id=body.get("master_key_id", master_key_id),
        )

    def decrypt_data_key(
        self, wrapped: bytes, *, master_key_id: Optional[str] = None
    ) -> bytes:
        """Ask the KMS to unwrap a previously wrapped data key."""
        payload: dict[str, Any] = {"ciphertext": encoding.b64u_encode(wrapped)}
        if master_key_id is not None:
            payload["master_key_id"] = master_key_id
        body = self._request("POST", "/v1/decrypt", payload)
        return self._b64(body, "plaintext")

    def encrypt(self, plaintext: bytes, *, master_key_id: str) -> bytes:
        """Envelope-encrypt ``plaintext`` and return a self-describing byte blob."""
        dk = self.generate_data_key(master_key_id)
        nonce = secrets.token_bytes(_NONCE_LEN)
        ciphertext = AESGCM(dk.plaintext).encrypt(nonce, plaintext, None)
        return _pack(dk.master_key_id, dk.wrapped, nonce, ciphertext)

    def decrypt(self, envelope: bytes) -> bytes:
        """Decrypt a blob produced by :meth:`encrypt`."""
        master_key_id, wrapped, nonce, ciphertext = _unpack(envelope)
        data_key = self.decrypt_data_key(wrapped, master_key_id=master_key_id or None)
        try:
            return AESGCM(data_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:  # tag mismatch / wrong key → surface as KMSError
            raise KMSError(f"Envelope decryption failed: {exc}") from exc

    def health(self) -> dict:
        """Return the KMS health/status document (a cheap connectivity check)."""
        return self._request("GET", "/v1/health")

    # -- HTTP plumbing ------------------------------------------------------------

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        url = f"{self.endpoint}{path}"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": "pqcmap-hosted-kms",
        }
        body: Optional[bytes] = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        try:
            resp = self._transport(method, url, headers, body)
        except (KMSError, KMSAuthError, KMSKeyNotFoundError):
            raise
        except Exception as exc:  # network / DNS / TLS → KMSError, never a raw crash
            raise KMSError(f"KMS request to {path} failed: {exc}") from exc

        return self._handle_status(path, resp)

    @staticmethod
    def _handle_status(path: str, resp: HTTPResponse) -> dict:
        if 200 <= resp.status < 300:
            if not resp.body:
                return {}
            try:
                return resp.json()
            except Exception as exc:
                raise KMSError(f"KMS returned invalid JSON from {path}: {exc}") from exc
        detail = _error_detail(resp)
        if resp.status in (401, 403):
            raise KMSAuthError(f"KMS rejected the API key ({resp.status}): {detail}")
        if resp.status == 404:
            raise KMSKeyNotFoundError(f"KMS key not found (404): {detail}")
        raise KMSError(f"KMS error {resp.status} from {path}: {detail}")

    @staticmethod
    def _b64(body: dict, field: str) -> bytes:
        try:
            return encoding.b64u_decode(body[field])
        except KeyError as exc:
            raise KMSError(f"KMS response missing {field!r}.") from exc
        except Exception as exc:
            raise KMSError(f"KMS response {field!r} was not valid base64: {exc}") from exc


# --- envelope (de)serialisation --------------------------------------------------

def _pack(master_key_id: str, wrapped: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    mkid = master_key_id.encode("utf-8")
    return b"".join(
        (
            _MAGIC,
            len(mkid).to_bytes(2, "big"),
            mkid,
            len(wrapped).to_bytes(2, "big"),
            wrapped,
            nonce,
            ciphertext,
        )
    )


def _unpack(blob: bytes) -> tuple[str, bytes, bytes, bytes]:
    try:
        if blob[: len(_MAGIC)] != _MAGIC:
            raise KMSError("Not a pqcmap KMS envelope (bad magic).")
        pos = len(_MAGIC)
        mkid_len = int.from_bytes(blob[pos : pos + 2], "big"); pos += 2
        mkid = blob[pos : pos + mkid_len].decode("utf-8"); pos += mkid_len
        wrapped_len = int.from_bytes(blob[pos : pos + 2], "big"); pos += 2
        wrapped = blob[pos : pos + wrapped_len]; pos += wrapped_len
        nonce = blob[pos : pos + _NONCE_LEN]; pos += _NONCE_LEN
        ciphertext = blob[pos:]
    except KMSError:
        raise
    except Exception as exc:
        raise KMSError(f"Malformed KMS envelope: {exc}") from exc
    if len(nonce) != _NONCE_LEN or wrapped_len != len(wrapped):
        raise KMSError("Truncated KMS envelope.")
    return mkid, wrapped, nonce, ciphertext


def _error_detail(resp: HTTPResponse) -> str:
    try:
        data = resp.json()
        return str(data.get("error") or data.get("message") or data)
    except Exception:
        return resp.body[:200].decode("utf-8", "replace") if resp.body else "(no body)"


# --- default transport (stdlib urllib over pqcmap PQC-hybrid TLS) ----------------

class _UrllibTransport:
    """Default HTTP transport: ``urllib`` with pqcmap's best-effort PQC TLS context."""

    def __init__(self, timeout: float, verify_tls: bool):
        self._timeout = timeout
        self._verify_tls = verify_tls

    def __call__(
        self, method: str, url: str, headers: dict, body: Optional[bytes]
    ) -> HTTPResponse:
        import urllib.error
        import urllib.request

        context = None
        if url.lower().startswith("https"):
            from pqcmap.tls.context import build_client_context

            context, _ = build_client_context(verify=self._verify_tls)

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=context) as r:
                return HTTPResponse(status=r.status, body=r.read())
        except urllib.error.HTTPError as e:  # non-2xx still carries a body
            return HTTPResponse(status=e.code, body=e.read() or b"")
