"""Scan a pull request's added crypto and post the review (PRD 07, CI-4).

Ties the pieces together without touching Celery or the DB, so it can be driven with a fake
client in tests: list the PR's files, fetch each supported file at the head SHA, scan its
content, keep only findings on lines the PR ADDED, then build + post the review and set the
commit status. Reuses the shared ``seqr_scanner`` code scanner — the same engine behind
``seqr scan code`` and the CLI CI gate.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from app.github_app.client import GitHubAppClient
from app.github_app.diff import added_lines
from app.github_app.review import ScanReview, build_review

logger = logging.getLogger(__name__)

# Extension → tree-sitter language, mirrored from CodeScanner so we skip non-code files
# (and their API fetches) before scanning.
_LANG_EXTS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go",
}


def scan_changed_files(
    client: GitHubAppClient,
    scanner: Any,
    *,
    owner: str,
    repo: str,
    number: int,
    head_sha: str,
    token: str,
    max_files: int = 300,
) -> list[Any]:
    """Return the CodeFindings on lines this PR added, across its changed code files."""
    files = client.list_pull_request_files(owner, repo, number, token, max_files=max_files)
    findings: list[Any] = []

    for entry in files:
        path = entry.get("filename", "")
        if entry.get("status") == "removed":
            continue
        if os.path.splitext(path)[1].lower() not in _LANG_EXTS:
            continue
        added = added_lines(entry.get("patch"))
        if not added:
            continue  # rename/mode-change/binary with no added text lines

        content = client.get_file_content(owner, repo, path, head_sha, token)
        if not content:
            continue

        lang = scanner.LANGUAGE_EXTENSIONS.get(os.path.splitext(path)[1].lower())
        if lang is None:
            continue
        try:
            file_findings = scanner.scan_content(content, lang, path)
        except Exception as exc:  # never let one bad file sink the whole scan
            logger.warning("github-app: scan failed for %s: %s", path, exc)
            continue

        for f in file_findings:
            if getattr(f, "line_number", None) in added:
                findings.append(f)

    return findings


def scan_and_review(
    client: GitHubAppClient,
    scanner: Any,
    *,
    owner: str,
    repo: str,
    number: int,
    head_sha: str,
    token: str,
    fail_on: str = "",
    target_url: str | None = None,
    post: bool = True,
) -> tuple[ScanReview, list[Any]]:
    """Scan the PR, build the review, and (by default) post it + set the commit status.

    Returns the ``ScanReview`` and the raw findings so the caller can persist them.
    """
    findings = scan_changed_files(
        client, scanner, owner=owner, repo=repo, number=number, head_sha=head_sha, token=token
    )
    review = build_review(findings, fail_on=fail_on)

    if post:
        client.create_review(
            owner, repo, number, token,
            body=review.body, event=review.event, comments=review.comments,
        )
        client.create_commit_status(
            owner, repo, head_sha, token,
            state=review.status_state, description=review.status_description,
            context="seqr/pqc", target_url=target_url,
        )
    return review, findings
