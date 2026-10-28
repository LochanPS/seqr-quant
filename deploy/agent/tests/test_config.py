"""Config loading: JSON + YAML, env overrides, mode validation, enabled-plugin selection."""
import json

import pytest

from seqr_agent.config import AgentConfig, load_config


def test_load_json(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({
        "name": "agent-x", "mode": "airgap", "api": "http://h/api/v1",
        "plugins": {"tls": {"targets": []}, "pkcs11": False},
    }))
    cfg = load_config(str(f))
    assert cfg.name == "agent-x" and cfg.mode == "airgap"
    assert cfg.enabled_plugins == ["tls"]  # pkcs11:false disabled


def test_load_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("name: y-agent\nmode: connected\nplugins:\n  cert_store:\n    include_os_trust: true\n")
    cfg = load_config(str(f))
    assert cfg.name == "y-agent"
    assert cfg.enabled_plugins == ["cert_store"]


def test_env_overrides_secret_fields(tmp_path, monkeypatch):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"name": "file-name", "api": "http://file/api/v1"}))
    monkeypatch.setenv("AGENT_KEY", "sq_live_secret")
    monkeypatch.setenv("SEQR_API", "http://env/api/v1")
    monkeypatch.setenv("AGENT_NAME", "env-name")
    cfg = load_config(str(f))
    assert cfg.credential == "sq_live_secret"
    assert cfg.api == "http://env/api/v1"
    assert cfg.name == "env-name"


def test_invalid_mode_rejected(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"mode": "bogus"}))
    with pytest.raises(ValueError):
        load_config(str(f))


def test_defaults_without_file():
    cfg = load_config(None)
    assert isinstance(cfg, AgentConfig)
    assert cfg.mode == "connected"
