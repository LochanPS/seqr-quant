"""Delivery — connected upload (POST /agent/observations) and air-gap export/verify.

Connected: signs the batch and POSTs it. The first run also sends ``X-Agent-Public-Key`` so the
platform trusts-on-first-use and binds the key; every later run is signature-verified server-side.

Air-gap: builds a signed ``AgentImportEnvelope`` (matching app/routers/agent.py) and writes it to
a file with zero network egress. An operator later uploads that file to POST /agent/import.
"""

from __future__ import annotations

import datetime
import json
import urllib.error
import urllib.request

from . import signing


def upload(api: str, credential: str, agent_name: str, observations: list[dict],
           priv, first_run: bool = True, timeout: int = 60) -> tuple[int, dict]:
    """Sign and POST a batch to the live ingest endpoint. Returns ``(http_status, body)``.

    Always sends both the signature and the public key: if the credential is not yet key-bound
    the server binds the key (trust-on-first-use); if it already is, the server verifies the
    signature and ignores the key header. Sending both makes the client stateless about binding.
    """
    sig = signing.sign(priv, observations)
    body = json.dumps({"agent": agent_name, "observations": observations}).encode()
    req = urllib.request.Request(api.rstrip("/") + "/agent/observations", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + credential)
    req.add_header("X-Agent-Signature", sig)
    req.add_header("X-Agent-Public-Key", signing.public_key_b64(priv))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:400]}


def build_envelope(agent_name: str, key_prefix: str, observations: list[dict], priv) -> dict:
    """Build a signed air-gap envelope (AgentImportEnvelope shape). No network I/O."""
    return {
        "version": 1,
        "agent": agent_name,
        "key_prefix": key_prefix,
        "signed_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "observations": observations,
        "signature": signing.sign(priv, observations),
    }


def write_envelope(path: str, envelope: dict) -> None:
    """Serialize the envelope to ``path`` (pretty JSON) for offline transfer."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2, sort_keys=True)


def verify_envelope_file(path: str, pubkey_b64_or_pem: str) -> bool:
    """Self-check that a written envelope's signature validates over its observations —
    the exact check the platform's /agent/import performs. Used by `verify-envelope` + tests."""
    with open(path, "r", encoding="utf-8") as f:
        env = json.load(f)
    return signing.verify(pubkey_b64_or_pem, env.get("signature", ""), env.get("observations", []))
