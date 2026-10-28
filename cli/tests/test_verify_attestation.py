"""Offline `seqr verify-attestation` — air-gap auditor tool. No network, no SeQr account."""
import base64
import json

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seqr.cli import main, _att_canonical_payload, _att_key_id


@pytest.fixture
def runner():
    return CliRunner()


def _make_artifact():
    """Build a valid signed certificate exactly the way the backend signer does."""
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fields = {
        "org_id": "11111111-1111-1111-1111-111111111111",
        "policy_id": "22222222-2222-2222-2222-222222222222",
        "policy_version": "v1",
        "policy_content_hash": "abc123",
        "evaluation_id": "33333333-3333-3333-3333-333333333333",
        "evaluation_result_hash": "def456",
        "covered_asset_set": ["a1", "a2", "a3"],
        "scanner_version": "0.1.1",
        "migration_engine_version": None,
        "graph_schema_version": 1,
        "key_id": _att_key_id(pk_raw),
        "created_at": "2026-07-16T00:00:00+00:00",
    }
    signature = base64.b64encode(sk.sign(_att_canonical_payload(fields))).decode()
    return {**fields, "signature": signature,
            "public_key": base64.b64encode(pk_raw).decode(), "algorithm": "ed25519"}


def _write(tmp_path, artifact):
    p = tmp_path / "cert.json"
    p.write_text(json.dumps(artifact))
    return str(p)


def test_valid_certificate_verifies(runner, tmp_path):
    path = _write(tmp_path, _make_artifact())
    result = runner.invoke(main, ["verify-attestation", path])
    assert result.exit_code == 0
    assert "VALID" in result.output
    assert "covered assets : 3" in result.output


def test_tampered_field_is_invalid(runner, tmp_path):
    art = _make_artifact()
    art["evaluation_result_hash"] = "tampered"  # signed field changed -> sig breaks
    path = _write(tmp_path, art)
    result = runner.invoke(main, ["verify-attestation", path])
    assert result.exit_code == 1
    assert "INVALID" in result.output


def test_mismatched_key_id_is_invalid(runner, tmp_path):
    art = _make_artifact()
    art["key_id"] = "att_deadbeefdeadbeef"  # key_id no longer matches embedded public key
    path = _write(tmp_path, art)
    result = runner.invoke(main, ["verify-attestation", path])
    assert result.exit_code == 1
    assert "INVALID" in result.output


def test_json_output(runner, tmp_path):
    path = _write(tmp_path, _make_artifact())
    result = runner.invoke(main, ["verify-attestation", path, "--output", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["policy_version"] == "v1"
