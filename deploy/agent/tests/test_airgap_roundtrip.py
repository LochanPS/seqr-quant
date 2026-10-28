"""Air-gap round-trip (PRD 15 §8, Slice 2).

The agent collects offline, writes a signed envelope, and an operator uploads it to
POST /agent/import. This test proves the envelope the agent writes verifies under BOTH:
  * the agent's own verifier (verify_envelope_file), and
  * the *platform's* verifier code (app/spine/agent_sig), loaded directly from the backend
    source so the two sides are proven byte-compatible — the exact check /agent/import runs.
"""
import importlib.util
import json
import os

from seqr_agent import signing, uploader
from seqr_agent.config import AgentConfig
from seqr_agent.plugins.cert_store import CertStorePlugin
from seqr_agent.runtime import collect

from _certs import rsa_pem

# Load the platform's verifier straight from the backend tree (only depends on cryptography).
_BACKEND_SIG = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "audit", "backend", "app", "spine", "agent_sig.py"
))


def _platform_verifier():
    spec = importlib.util.spec_from_file_location("_platform_agent_sig", _BACKEND_SIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _observations(tmp_path) -> list[dict]:
    (tmp_path / "leaf.pem").write_bytes(rsa_pem(cn="airgap-leaf.internal"))
    obs = CertStorePlugin(config={"paths": [str(tmp_path)]}).collect()
    return [o.to_dict() for o in obs]


def test_envelope_verifies_with_agent_and_platform(tmp_path):
    priv, _ = signing.load_or_create_key(str(tmp_path / "k.pem"))
    obs = _observations(tmp_path)
    assert obs, "cert_store should have produced at least one observation"

    envelope = uploader.build_envelope("dc-mumbai-agent", "sq_live_", obs, priv)
    out = str(tmp_path / "export.json")
    uploader.write_envelope(out, envelope)

    # 1) Agent self-check.
    assert uploader.verify_envelope_file(out, signing.public_key_pem(priv)) is True

    # 2) Platform verifier (the real /agent/import check) over the same wire observations.
    plat = _platform_verifier()
    written = json.load(open(out, encoding="utf-8"))
    assert plat.verify(signing.public_key_pem(priv), written["signature"], written["observations"]) is True
    # raw-32 base64 public key must verify too (TOFU header form).
    assert plat.verify(signing.public_key_b64(priv), written["signature"], written["observations"]) is True


def test_platform_rejects_tampered_envelope(tmp_path):
    priv, _ = signing.load_or_create_key(str(tmp_path / "k.pem"))
    obs = _observations(tmp_path)
    envelope = uploader.build_envelope("a", "sq_live_", obs, priv)
    # Tamper: flip an algorithm after signing.
    envelope["observations"][0]["algorithm"] = "ML-KEM-1024"
    plat = _platform_verifier()
    assert plat.verify(signing.public_key_pem(priv), envelope["signature"], envelope["observations"]) is False


def test_run_airgap_mode_writes_envelope(tmp_path):
    (tmp_path / "leaf.pem").write_bytes(rsa_pem(cn="run-leaf.internal"))
    out = str(tmp_path / "export.json")
    cfg = AgentConfig(
        name="airgap-agent", mode="airgap", credential="sq_live_abc123",
        keyfile=str(tmp_path / "k.pem"), export_path=out,
        plugins={"cert_store": {"paths": [str(tmp_path)]}},
    )
    from seqr_agent.runtime import run
    summary = run(cfg, log=lambda *a: None)
    assert summary["mode"] == "airgap"
    assert summary["observations"] >= 1
    assert os.path.isfile(out)
    env = json.load(open(out, encoding="utf-8"))
    assert env["key_prefix"] == "sq_live_"
    assert env["version"] == 1 and env["signature"]


def test_collect_isolates_failing_plugin(tmp_path):
    # A configured-but-broken pkcs11 enumerator must not abort a good cert_store run.
    (tmp_path / "leaf.pem").write_bytes(rsa_pem(cn="iso.internal"))

    def _boom(_c):
        raise RuntimeError("hsm exploded")

    cfg = AgentConfig(
        name="a", mode="airgap", keyfile=str(tmp_path / "k.pem"),
        plugins={"cert_store": {"paths": [str(tmp_path)]},
                 "pkcs11": {"_enumerator": _boom}},
    )
    res = collect(cfg, log=lambda *a: None)
    assert "cert_store" in res.ran
    # pkcs11's enumerator swallows its own error and yields nothing -> ran with 0 obs, not failed.
    assert res.observations  # cert_store still delivered
