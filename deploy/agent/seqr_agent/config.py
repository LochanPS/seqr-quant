"""Agent configuration — a single file naming targets, plugins, and the upload/export path.

Supports JSON natively and YAML when PyYAML is present (the packaged image ships it). Env vars
override the sensitive/credential fields so a config file never has to carry a secret:

    SEQR_API      base API URL           -> api
    AGENT_KEY     sq_live_ credential     -> credential
    AGENT_NAME    agent display name      -> name
    AGENT_KEYFILE Ed25519 key path        -> keyfile

Shape (see agent.example.yaml):

    name: dc-mumbai-agent
    mode: connected            # connected | airgap
    api: http://host:8000/api/v1
    credential: sq_live_...     # or via AGENT_KEY
    keyfile: ./.agent_ed25519.pem
    export_path: ./seqr-agent-export.json   # airgap mode output
    plugins:
      tls: {targets: [...]}
      cert_store: {paths: [...], include_os_trust: true}
      proxy_conf: {nginx: [...], haproxy: [...]}
      pkcs11: {module: /usr/lib/softhsm/libsofthsm2.so}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    name: str = "seqr-discovery-agent"
    mode: str = "connected"  # connected | airgap
    api: str = "http://localhost:8000/api/v1"
    credential: str = ""
    keyfile: str = "./.agent_ed25519.pem"
    export_path: str = "./seqr-agent-export.json"
    plugins: dict = field(default_factory=dict)
    timeout: int = 60

    @property
    def enabled_plugins(self) -> list[str]:
        return [k for k, v in self.plugins.items() if v is not False]


def _load_raw(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except Exception as e:  # pragma: no cover
            raise RuntimeError("PyYAML is required to read a YAML config; use JSON or install pyyaml") from e
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_config(path: str | None) -> AgentConfig:
    """Load config from ``path`` (JSON/YAML), then apply env-var overrides for secrets."""
    raw: dict = {}
    if path:
        raw = _load_raw(path)
        if not isinstance(raw, dict):
            raise ValueError("config root must be a mapping")

    cfg = AgentConfig(
        name=raw.get("name", AgentConfig.name),
        mode=raw.get("mode", AgentConfig.mode),
        api=raw.get("api", AgentConfig.api),
        credential=raw.get("credential", ""),
        keyfile=raw.get("keyfile", AgentConfig.keyfile),
        export_path=raw.get("export_path", AgentConfig.export_path),
        plugins=raw.get("plugins", {}) or {},
        timeout=int(raw.get("timeout", AgentConfig.timeout)),
    )

    # Env overrides (never put a live secret in the file).
    cfg.api = os.environ.get("SEQR_API", cfg.api)
    cfg.credential = os.environ.get("AGENT_KEY", cfg.credential)
    cfg.name = os.environ.get("AGENT_NAME", cfg.name)
    cfg.keyfile = os.environ.get("AGENT_KEYFILE", cfg.keyfile)

    if cfg.mode not in ("connected", "airgap"):
        raise ValueError(f"mode must be 'connected' or 'airgap', got {cfg.mode!r}")
    return cfg
