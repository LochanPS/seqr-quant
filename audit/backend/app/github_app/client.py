"""Minimal GitHub REST client for the hosted App (PRD 07, CI-4).

Mints a short-lived App JWT (RS256, signed with the App private key), exchanges it for an
installation access token scoped to one install, and exposes just the calls the PR-scan
worker needs: list a PR's files, fetch a file's content at a ref, post a review, and set a
commit status. Uses ``httpx`` synchronously because the Celery worker runs sync.

No call here registers, lists, or deletes anything on GitHub's side — those are manual
operator steps. The App only reads changed files and writes a review + commit status.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
from jose import jwt

_API_VERSION = "2022-11-28"
_JSON = "application/vnd.github+json"
# JWT is valid for <=10 min; use 9 to stay inside clock-skew tolerance.
_JWT_TTL_SECONDS = 9 * 60


class GitHubAPIError(RuntimeError):
    """A GitHub API call returned a non-success status."""

    def __init__(self, status: int, detail: str):
        self.status = status
        super().__init__(f"GitHub API {status}: {detail}")


def restore_pem(key: str) -> str:
    """Restore real newlines in a PEM whose newlines were flattened by env vars.

    Deployments often paste the App private key into a single-line env var with literal
    ``\\n`` sequences; PEM parsing needs real newlines. A key that already has newlines is
    returned unchanged.
    """
    if "\\n" in key and "\n" not in key.strip("\n"):
        key = key.replace("\\n", "\n")
    return key


class GitHubAppClient:
    def __init__(
        self,
        app_id: str,
        private_key_pem: str,
        *,
        api_url: str = "https://api.github.com",
        timeout: float = 20.0,
        transport: httpx.BaseTransport | None = None,
    ):
        if not app_id:
            raise ValueError("GITHUB_APP_ID is not configured")
        if not private_key_pem:
            raise ValueError("GITHUB_APP_PRIVATE_KEY is not configured")
        self.app_id = str(app_id)
        self.private_key = restore_pem(private_key_pem)
        self.api_url = api_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubAppClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- auth -----------------------------------------------------------------
    def app_jwt(self) -> str:
        now = int(time.time())
        claims = {"iat": now - 60, "exp": now + _JWT_TTL_SECONDS, "iss": self.app_id}
        return jwt.encode(claims, self.private_key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        data = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            bearer=self.app_jwt(),
        )
        return data["token"]

    # -- PR data --------------------------------------------------------------
    def list_pull_request_files(
        self, owner: str, repo: str, number: int, token: str, *, max_files: int = 300
    ) -> list[dict[str, Any]]:
        """Return the PR's changed files (paginated), capped at ``max_files``."""
        files: list[dict[str, Any]] = []
        page = 1
        while len(files) < max_files:
            batch = self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{number}/files",
                token=token,
                params={"per_page": 100, "page": page},
            )
            if not batch:
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return files[:max_files]

    def get_file_content(self, owner: str, repo: str, path: str, ref: str, token: str) -> str:
        """Return a file's raw text at ``ref``. Empty string if it cannot be fetched."""
        try:
            resp = self._raw_request(
                "GET",
                f"/repos/{owner}/{repo}/contents/{path}",
                token=token,
                params={"ref": ref},
                accept="application/vnd.github.raw",
            )
        except GitHubAPIError:
            return ""
        return resp.text

    # -- writes ---------------------------------------------------------------
    def create_review(
        self,
        owner: str,
        repo: str,
        number: int,
        token: str,
        *,
        body: str,
        event: str = "COMMENT",
        comments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"body": body, "event": event}
        if comments:
            payload["comments"] = comments
        return self._request(
            "POST", f"/repos/{owner}/{repo}/pulls/{number}/reviews", token=token, json=payload
        )

    def create_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        token: str,
        *,
        state: str,
        description: str,
        context: str = "seqr/pqc",
        target_url: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"state": state, "description": description[:140], "context": context}
        if target_url:
            payload["target_url"] = target_url
        return self._request(
            "POST", f"/repos/{owner}/{repo}/statuses/{sha}", token=token, json=payload
        )

    # -- transport ------------------------------------------------------------
    def _headers(self, *, token: str | None, bearer: str | None, accept: str) -> dict[str, str]:
        auth = f"Bearer {bearer}" if bearer else f"token {token}"
        return {
            "Authorization": auth,
            "Accept": accept,
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": "seqr-pqc-app",
        }

    def _raw_request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        bearer: str | None = None,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        accept: str = _JSON,
    ) -> httpx.Response:
        resp = self._client.request(
            method,
            f"{self.api_url}{path}",
            headers=self._headers(token=token, bearer=bearer, accept=accept),
            params=params,
            json=json,
        )
        if resp.status_code >= 300:
            detail = resp.text[:300]
            raise GitHubAPIError(resp.status_code, detail)
        return resp

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        return self._raw_request(method, path, **kw).json()
