"""Extract the scan job from a GitHub ``pull_request`` webhook (PRD 07, CI-4).

Pure parsing, no side effects. Only ``opened``, ``reopened``, and ``synchronize`` (new
commits pushed) warrant a re-scan; every other action and event type is ignored so the App
stays quiet and cheap. Returns None when there is nothing to do.
"""
from __future__ import annotations

from dataclasses import dataclass

_RESCAN_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}


@dataclass(frozen=True)
class PullRequestJob:
    installation_id: int
    owner: str
    repo: str
    number: int
    head_sha: str
    action: str


def parse_pull_request_event(event: str | None, payload: dict) -> PullRequestJob | None:
    """Return a job for a rescan-worthy pull_request event, else None."""
    if event != "pull_request":
        return None
    action = payload.get("action")
    if action not in _RESCAN_ACTIONS:
        return None

    pr = payload.get("pull_request") or {}
    # Skip draft PRs unless they were just marked ready — mirrors CI's usual gate.
    if pr.get("draft") and action != "ready_for_review":
        return None

    installation = (payload.get("installation") or {}).get("id")
    repo = payload.get("repository") or {}
    full_name = repo.get("full_name") or ""
    head = (pr.get("head") or {})
    number = pr.get("number")
    head_sha = head.get("sha")

    if not (installation and "/" in full_name and number and head_sha):
        return None

    owner, name = full_name.split("/", 1)
    return PullRequestJob(
        installation_id=int(installation),
        owner=owner,
        repo=name,
        number=int(number),
        head_sha=head_sha,
        action=action,
    )
