"""Hosted GitHub App webhook receiver (PRD 07, CI-4).

The single internet-facing entry point of the App. It is an UNAUTHENTICATED code path in
the usual sense — GitHub does not send a bearer token — so every request is verified by its
HMAC-SHA256 signature before the body is parsed. The endpoint stays hidden (404) unless the
App is explicitly enabled, and only enqueues work for pull-request events worth scanning.
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.github_app.events import parse_pull_request_event
from app.github_app.signature import SignatureError, verify_signature

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/webhook")
async def github_webhook(request: Request):
    """Receive, verify, and dispatch a GitHub webhook."""
    # Hidden unless configured — do not advertise the App on a deployment that has not
    # turned it on (returns the same 404 as an unknown route).
    if not settings.GITHUB_APP_ENABLED:
        raise HTTPException(status_code=404, detail="Not Found")

    raw = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    try:
        verify_signature(settings.GITHUB_WEBHOOK_SECRET, raw, signature)
    except SignatureError as exc:
        raise HTTPException(status_code=401, detail=f"invalid signature: {exc}")

    event = request.headers.get("X-GitHub-Event", "")

    # GitHub sends a "ping" when the webhook is first configured — acknowledge it.
    if event == "ping":
        return {"ok": True, "pong": True}

    import json
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="malformed JSON body")

    job = parse_pull_request_event(event, payload)
    if job is None:
        # Nothing to scan (unsupported event/action, draft PR, missing fields) — 200 so
        # GitHub does not retry.
        return {"ok": True, "queued": False}

    from app.github_app.tasks import scan_pull_request_task

    scan_pull_request_task.delay(
        job.installation_id, job.owner, job.repo, job.number, job.head_sha
    )
    return {"ok": True, "queued": True, "repo": f"{job.owner}/{job.repo}", "pr": job.number}
