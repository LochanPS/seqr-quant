"""Tests for the hosted GitHub App (PRD 07, CI-4).

Covers the pure units (signature, diff, events, review, severity), the scan orchestrator
against a fake GitHub client + the real code scanner, and the webhook route end-to-end
(feature flag, signature enforcement, ping, dispatch).
"""
import json

import pytest

from app.config import settings
from app.github_app.diff import added_lines
from app.github_app.events import parse_pull_request_event
from app.github_app.review import build_review, finding_to_dict
from app.github_app.severity import at_or_above, severity_for_risk
from app.github_app.signature import (
    SignatureError,
    compute_signature,
    verify_signature,
)

# --------------------------------------------------------------------------- #
# signature
# --------------------------------------------------------------------------- #

def test_signature_roundtrip():
    body = b'{"hello":"world"}'
    sig = compute_signature("s3cret", body)
    verify_signature("s3cret", body, sig)  # no raise


def test_signature_rejects_tampered_body():
    sig = compute_signature("s3cret", b"original")
    with pytest.raises(SignatureError):
        verify_signature("s3cret", b"tampered", sig)


@pytest.mark.parametrize("secret,header", [("", "sha256=x"), ("s", None), ("s", "md5=x")])
def test_signature_bad_inputs(secret, header):
    with pytest.raises(SignatureError):
        verify_signature(secret, b"body", header)


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #

def test_added_lines_multi_hunk():
    patch = (
        "@@ -1,2 +1,3 @@\n context\n+added_a\n+added_b\n-removed\n"
        "@@ -20,0 +21,1 @@\n+added_c\n"
    )
    assert added_lines(patch) == {2, 3, 21}


def test_added_lines_none_and_empty():
    assert added_lines(None) == set()
    assert added_lines("") == set()


def test_added_lines_ignores_no_newline_marker():
    patch = "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n"
    assert added_lines(patch) == {1}


# --------------------------------------------------------------------------- #
# severity
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("risk,exp", [(10, "critical"), (9, "critical"), (8, "high"),
                                      (7, "high"), (5, "medium"), (2, "low"), (0, "low")])
def test_severity_for_risk(risk, exp):
    assert severity_for_risk(risk) == exp


def test_at_or_above():
    assert at_or_above("high", "medium")
    assert at_or_above("high", "high")
    assert not at_or_above("low", "high")
    assert not at_or_above("bogus", "low")  # unknown never arms the gate


# --------------------------------------------------------------------------- #
# events
# --------------------------------------------------------------------------- #

def _pr_payload(action="opened", draft=False):
    return {
        "action": action,
        "installation": {"id": 4242},
        "repository": {"full_name": "acme/widgets"},
        "pull_request": {"number": 7, "draft": draft, "head": {"sha": "abc123"}},
    }


def test_parse_event_opened():
    job = parse_pull_request_event("pull_request", _pr_payload())
    assert job is not None
    assert (job.installation_id, job.owner, job.repo, job.number, job.head_sha) == (
        4242, "acme", "widgets", 7, "abc123"
    )


@pytest.mark.parametrize("action", ["closed", "labeled", "assigned"])
def test_parse_event_ignored_actions(action):
    assert parse_pull_request_event("pull_request", _pr_payload(action=action)) is None


def test_parse_event_wrong_event_type():
    assert parse_pull_request_event("push", _pr_payload()) is None


def test_parse_event_draft_skipped_but_ready_scanned():
    assert parse_pull_request_event("pull_request", _pr_payload(draft=True)) is None
    job = parse_pull_request_event(
        "pull_request", _pr_payload(action="ready_for_review", draft=True)
    )
    assert job is not None


def test_parse_event_missing_installation():
    payload = _pr_payload()
    payload.pop("installation")
    assert parse_pull_request_event("pull_request", payload) is None


# --------------------------------------------------------------------------- #
# review
# --------------------------------------------------------------------------- #

class _Finding:
    def __init__(self, risk=8, line=42, hndl=True):
        self.algorithm_risk = risk
        self.file_path = "src/auth/jwt.py"
        self.line_number = line
        self.algorithm = "RS256"
        self.algorithm_family = "RSA"
        self.quantum_status = "vulnerable"
        self.confidence = "high"
        self.recommended_replacement = "Replace PyJWT RS256 with pqcmap ML-DSA"
        self.estimated_effort_hours = 4
        self.hndl_risk = hndl
        self.library_name = "PyJWT"
        self.pattern_id = "jwt_rs256"


def test_review_empty_is_advisory_success():
    r = build_review([], fail_on="high")
    assert r.findings_count == 0
    assert r.status_state == "success"
    assert "✅" in r.body
    assert not r.comments


def test_review_gate_fails_at_threshold():
    r = build_review([_Finding(risk=8)], fail_on="high")
    assert r.status_state == "failure"
    assert r.max_severity == "high"
    assert len(r.comments) == 1
    c = r.comments[0]
    assert c["path"] == "src/auth/jwt.py" and c["line"] == 42 and c["side"] == "RIGHT"


def test_review_gate_advisory_when_no_fail_on():
    r = build_review([_Finding(risk=9)], fail_on="")
    assert r.status_state == "success"  # exit-0-by-default
    assert r.max_severity == "critical"


def test_review_gate_below_threshold_passes():
    r = build_review([_Finding(risk=4)], fail_on="high")  # medium < high
    assert r.status_state == "success"


def test_review_body_has_hndl_disclaimer_and_no_cnsa():
    r = build_review([_Finding(hndl=True)], fail_on="high")
    assert "predictive cryptographic risk metrics" in r.body
    assert "HNDL" in r.body
    assert "CNSA" not in r.body


def test_finding_to_dict_is_json_safe():
    d = finding_to_dict(_Finding())
    json.dumps(d)  # no raise
    assert d["severity"] == "high"
    assert d["file_path"] == "src/auth/jwt.py"


# --------------------------------------------------------------------------- #
# scan orchestrator (fake client + real scanner)
# --------------------------------------------------------------------------- #

class _FakeClient:
    """Records writes; serves canned PR files + file contents."""

    def __init__(self, files, contents):
        self._files = files
        self._contents = contents
        self.reviews = []
        self.statuses = []

    def list_pull_request_files(self, owner, repo, number, token, max_files=300):
        return self._files

    def get_file_content(self, owner, repo, path, ref, token):
        return self._contents.get(path, "")

    def create_review(self, owner, repo, number, token, *, body, event, comments=None):
        self.reviews.append({"body": body, "event": event, "comments": comments})
        return {"id": 1}

    def create_commit_status(self, owner, repo, sha, token, *, state, description,
                             context="seqr/pqc", target_url=None):
        self.statuses.append({"state": state, "description": description})
        return {"id": 1}


@pytest.fixture(scope="module")
def scanner():
    from seqr_scanner import CodeScanner
    s = CodeScanner()
    # Guard: if tree-sitter parsers are unavailable, code scanning is a no-op — skip.
    probe = s.scan_content('import jwt\njwt.encode(p, k, algorithm="RS256")\n', "python", "p.py")
    if not probe:
        pytest.skip("code scanner unavailable in this environment")
    return s


def test_scan_only_flags_added_lines(scanner):
    from app.github_app.scan import scan_and_review

    # Line 1 pre-exists (context); line 2 is added and contains the vulnerable call.
    content = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n'
    files = [{"filename": "auth.py", "status": "modified",
              "patch": "@@ -1,1 +1,2 @@\n import jwt\n+token = jwt.encode(payload, key, algorithm=\"RS256\")"}]
    client = _FakeClient(files, {"auth.py": content})

    review, findings = scan_and_review(
        client, scanner, owner="acme", repo="widgets", number=7,
        head_sha="deadbeef", token="t", fail_on="high",
    )
    assert review.findings_count == 1
    assert findings[0].line_number == 2
    assert client.statuses[0]["state"] == "failure"
    assert client.reviews[0]["comments"][0]["line"] == 2


def test_scan_excludes_finding_on_unadded_line(scanner):
    from app.github_app.scan import scan_and_review

    # The vulnerable call is on line 2, but the diff only adds line 3 (a comment).
    content = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n# note\n'
    files = [{"filename": "auth.py", "status": "modified",
              "patch": "@@ -2,0 +3,1 @@\n+# note"}]
    client = _FakeClient(files, {"auth.py": content})

    review, findings = scan_and_review(
        client, scanner, owner="acme", repo="widgets", number=7,
        head_sha="x", token="t", fail_on="high",
    )
    assert review.findings_count == 0
    assert client.statuses[0]["state"] == "success"


def test_scan_skips_removed_and_non_code_files(scanner):
    from app.github_app.scan import scan_changed_files

    files = [
        {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1,2 @@\n+text"},
        {"filename": "gone.py", "status": "removed", "patch": None},
    ]
    client = _FakeClient(files, {})
    findings = scan_changed_files(
        client, scanner, owner="a", repo="b", number=1, head_sha="x", token="t"
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# webhook route
# --------------------------------------------------------------------------- #

@pytest.fixture
def app_enabled(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_APP_ENABLED", True)
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "whsec")
    yield


@pytest.mark.asyncio
async def test_webhook_hidden_when_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_APP_ENABLED", False)
    r = await client.post("/api/v1/github/webhook", content=b"{}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_webhook_rejects_bad_signature(client, app_enabled):
    r = await client.post(
        "/api/v1/github/webhook",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "ping"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_webhook_ping(client, app_enabled):
    body = b'{"zen":"hi"}'
    sig = compute_signature("whsec", body)
    r = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "ping"},
    )
    assert r.status_code == 200
    assert r.json()["pong"] is True


@pytest.mark.asyncio
async def test_webhook_dispatches_pull_request(client, app_enabled, monkeypatch):
    calls = []

    def fake_delay(*args):
        calls.append(args)

    import app.github_app.tasks as tasks_mod
    monkeypatch.setattr(tasks_mod.scan_pull_request_task, "delay", fake_delay)

    body = json.dumps(_pr_payload()).encode()
    sig = compute_signature("whsec", body)
    r = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request"},
    )
    assert r.status_code == 200
    assert r.json()["queued"] is True
    assert calls == [(4242, "acme", "widgets", 7, "abc123")]


@pytest.mark.asyncio
async def test_webhook_ignores_unscannable_event(client, app_enabled):
    body = json.dumps(_pr_payload(action="closed")).encode()
    sig = compute_signature("whsec", body)
    r = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request"},
    )
    assert r.status_code == 200
    assert r.json()["queued"] is False


# --------------------------------------------------------------------------- #
# link CLI (installation -> org)
# --------------------------------------------------------------------------- #

@pytest.fixture
def sync_db():
    """A throwaway sync sqlite session with the schema + one org and user."""
    from argparse import Namespace  # noqa: F401 (kept for readers of this fixture)
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import Base
    import app.models  # noqa: F401 — register all tables
    from app.models.organisation import Organisation
    from app.models.user import User

    engine = create_engine("sqlite://")  # in-memory, single connection
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    org = Organisation(name="Acme")
    db.add(org)
    db.flush()
    db.add(User(org_id=org.id, email="dev@acme.com", password_hash="x", name="Dev"))
    db.commit()
    db._test_org_id = org.id  # stash for assertions
    try:
        yield db
    finally:
        db.close()


def _ns(**kw):
    from argparse import Namespace
    base = dict(installation_id=None, org_id=None, org_email=None, org_name=None,
                account_login=None, account_type=None)
    base.update(kw)
    return Namespace(**base)


def test_link_set_by_email_then_list_and_unset(sync_db, capsys):
    from app.github_app.link import _cmd_set, _cmd_list, _cmd_unset
    from app.models.github_installation import GitHubInstallation

    rc = _cmd_set(sync_db, _ns(installation_id=4242, org_email="dev@acme.com",
                               account_login="acme", account_type="Organization"))
    assert rc == 0
    link = sync_db.get(GitHubInstallation, 4242)
    assert link is not None and link.org_id == sync_db._test_org_id
    assert link.account_login == "acme"

    assert _cmd_list(sync_db, _ns()) == 0
    assert "4242" in capsys.readouterr().out

    assert _cmd_unset(sync_db, _ns(installation_id=4242)) == 0
    assert sync_db.get(GitHubInstallation, 4242) is None


def test_link_set_is_idempotent_update(sync_db):
    from app.github_app.link import _cmd_set
    from app.models.github_installation import GitHubInstallation

    _cmd_set(sync_db, _ns(installation_id=1, org_email="dev@acme.com", account_login="old"))
    _cmd_set(sync_db, _ns(installation_id=1, org_id=str(sync_db._test_org_id), account_login="new"))
    rows = sync_db.query(GitHubInstallation).all()
    assert len(rows) == 1
    assert rows[0].account_login == "new"


def test_link_set_by_org_id(sync_db):
    from app.github_app.link import _cmd_set
    from app.models.github_installation import GitHubInstallation

    assert _cmd_set(sync_db, _ns(installation_id=9, org_id=str(sync_db._test_org_id))) == 0
    assert sync_db.get(GitHubInstallation, 9).org_id == sync_db._test_org_id


def test_link_requires_exactly_one_selector(sync_db):
    from app.github_app.link import _cmd_set
    with pytest.raises(SystemExit):
        _cmd_set(sync_db, _ns(installation_id=2))  # none given
    with pytest.raises(SystemExit):
        _cmd_set(sync_db, _ns(installation_id=2, org_id="x", org_email="dev@acme.com"))


def test_link_unknown_email_and_bad_uuid(sync_db):
    from app.github_app.link import _cmd_set
    with pytest.raises(SystemExit):
        _cmd_set(sync_db, _ns(installation_id=3, org_email="nobody@nowhere.com"))
    with pytest.raises(SystemExit):
        _cmd_set(sync_db, _ns(installation_id=3, org_id="not-a-uuid"))


def test_link_unset_missing_returns_1(sync_db):
    from app.github_app.link import _cmd_unset
    assert _cmd_unset(sync_db, _ns(installation_id=777)) == 1


def test_link_parser_roundtrip():
    from app.github_app.link import build_parser
    args = build_parser().parse_args(
        ["set", "--installation-id", "5", "--org-email", "a@b.com"]
    )
    assert args.command == "set" and args.installation_id == 5 and args.org_email == "a@b.com"
