"""Hosted SeQr GitHub App (PRD 07, CI-4).

Zero-config PQC review for pull requests: GitHub sends a webhook, a Celery worker mints a
short-lived installation token, fetches only the changed files, scans the crypto a PR
*adds*, and posts an inline review + commit status. Reuses the audit backend stack
(FastAPI + Celery + the shared scanner) — no new tech.

The App is **feature-flagged off** (`GITHUB_APP_ENABLED`) and, even on, only reacts to
signed webhooks. Nothing here registers, deploys, or lists anything — those are manual
operator steps (see docs/07_GitHub_App_PRD.md and docs/GITHUB_APP_OPERATIONS.md).
"""
from app.github_app.signature import SignatureError, verify_signature

__all__ = ["verify_signature", "SignatureError"]
