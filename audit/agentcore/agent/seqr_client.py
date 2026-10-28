"""Thin HTTP client for the SeQr audit backend.

The AgentCore agent never talks to the database or the spine directly — it calls the same
org-scoped REST API a customer's dashboard uses, authenticating with an ``sq_live_`` API key
(the key's org scopes every read/write, so the agent is tenant-isolated by construction).

Credentials come from the environment (SEQR_API_BASE / SEQR_API_KEY), never hardcoded — on
AgentCore they are injected from a Secrets Manager reference by the runtime, and locally from
``.env``. The key is an ``agent``-or-user-scoped ``sq_live_`` credential minted from the
dashboard; it is read-only for everything except triggering a scan.
"""

import os

import httpx

_DEFAULT_TIMEOUT = 60.0


class SeqrClientError(RuntimeError):
    """A backend call failed — surfaced to the model as a tool error, not a crash."""


class SeqrClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ):
        self.base_url = (base_url or os.environ.get("SEQR_API_BASE", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("SEQR_API_KEY", "")
        if not self.base_url:
            raise SeqrClientError("SEQR_API_BASE is not set")
        if not self.api_key:
            raise SeqrClientError("SEQR_API_KEY is not set")
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        # sq_live_ keys authenticate through the same get_current_user path as JWTs.
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def get(self, path: str, params: dict | None = None) -> object:
        return self._request("GET", path, params=params)

    def post(self, path: str, json: dict | None = None) -> object:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kw) -> object:
        url = f"{self.base_url}/api/v1{path}"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.request(method, url, headers=self._headers(), **kw)
        except httpx.HTTPError as exc:  # network/timeout — advisory, so degrade gracefully
            raise SeqrClientError(f"{method} {path} failed: {exc}") from exc
        if resp.status_code >= 400:
            raise SeqrClientError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
        if not resp.content:
            return None
        return resp.json()
