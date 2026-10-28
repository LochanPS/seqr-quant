"""Celery worker: scan a PR and post the review (PRD 07, CI-4).

Runs the network + DB side of a scan. Kept thin — the scan/review logic lives in
``scan.py`` and ``review.py`` (pure, unit-tested); this module only wires the real GitHub
client, the shared scanner, and optional dashboard persistence, and never crashes the
worker on a GitHub or scan error.
"""
from __future__ import annotations

import logging
import uuid as _uuid

from app.config import settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)

# CodeScanner loads tree-sitter parsers on init — build it once per worker process.
_scanner = None


def _get_scanner():
    global _scanner
    if _scanner is None:
        from seqr_scanner import CodeScanner
        _scanner = CodeScanner()
    return _scanner


def _build_client():
    from app.github_app.client import GitHubAppClient

    return GitHubAppClient(
        settings.GITHUB_APP_ID,
        settings.GITHUB_APP_PRIVATE_KEY,
        api_url=settings.GITHUB_API_URL,
    )


def _resolve_org_id(installation_id: int) -> "uuid.UUID | None":
    """Look up the SeQr org linked to this GitHub installation, if any."""
    from app.database import SyncSessionLocal
    from app.models.github_installation import GitHubInstallation

    db = SyncSessionLocal()
    try:
        link = db.query(GitHubInstallation).filter(
            GitHubInstallation.installation_id == installation_id
        ).first()
        return link.org_id if link else None
    finally:
        db.close()


def _persist_report(org_id, job_owner, job_repo, number, head_sha, review, findings) -> None:
    from app.database import SyncSessionLocal
    from app.models.ci_report import CIReport
    from app.github_app.review import finding_to_dict

    db = SyncSessionLocal()
    try:
        report = CIReport(
            org_id=org_id,
            actor="github-app",
            repo=f"{job_owner}/{job_repo}",
            pr_number=number,
            commit_sha=head_sha,
            branch=None,
            source="github-app",
            findings_count=review.findings_count,
            summary=review.summary or None,
            findings=[finding_to_dict(f) for f in findings],
        )
        db.add(report)
        db.commit()
    except Exception as exc:  # pragma: no cover — persistence is best-effort
        db.rollback()
        logger.warning("github-app: failed to persist CIReport: %s", exc)
    finally:
        db.close()


@celery_app.task(bind=True, name="github_app.scan_pull_request")
def scan_pull_request_task(
    self,
    installation_id: int,
    owner: str,
    repo: str,
    number: int,
    head_sha: str,
) -> dict:
    """Scan one PR, post the review + commit status, and optionally sync the dashboard."""
    if not settings.GITHUB_APP_ENABLED:
        return {"skipped": "github app disabled"}

    from app.github_app.scan import scan_and_review

    client = _build_client()
    try:
        token = client.installation_token(installation_id)
        review, findings = scan_and_review(
            client, _get_scanner(),
            owner=owner, repo=repo, number=number, head_sha=head_sha, token=token,
            fail_on=settings.GITHUB_APP_FAIL_ON,
        )
    except Exception as exc:
        logger.warning("github-app: scan failed for %s/%s#%s: %s", owner, repo, number, exc)
        return {"error": str(exc)}
    finally:
        client.close()

    if settings.GITHUB_APP_PERSIST_REPORTS:
        org_id = _resolve_org_id(installation_id)
        if org_id is not None:
            _persist_report(org_id, owner, repo, number, head_sha, review, findings)

    return {
        "findings": review.findings_count,
        "status": review.status_state,
        "max_severity": review.max_severity,
    }
