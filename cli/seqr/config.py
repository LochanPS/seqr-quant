"""
Reads and writes ~/.seqr/config.toml.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import toml
except ImportError:
    toml = None  # type: ignore

_CONFIG_DIR = Path.home() / ".seqr"
_CONFIG_FILE = _CONFIG_DIR / "config.toml"

_DEFAULTS: dict[str, Any] = {
    "auth": {
        "api_key": "",
        "api_url": "https://api.seqr.in",
    },
    "scan": {
        "default_severity": "medium",
        "default_output": "terminal",
        "exclude_patterns": [
            "node_modules/",
            ".venv/",
            "__pycache__/",
            "vendor/",
            "*.test.*",
            "*.spec.*",
        ],
        "languages": ["python", "javascript", "java", "go"],
    },
    "patterns": {
        "version": "1.4.0",
        "auto_update": True,
        "update_channel": "stable",
    },
}


def _load() -> dict[str, Any]:
    if toml is None:
        return _DEFAULTS.copy()
    if not _CONFIG_FILE.exists():
        return _DEFAULTS.copy()
    try:
        return toml.load(_CONFIG_FILE)
    except Exception:
        return _DEFAULTS.copy()


def get(section: str, key: str, fallback: Any = None) -> Any:
    cfg = _load()
    return cfg.get(section, {}).get(key, _DEFAULTS.get(section, {}).get(key, fallback))


def get_api_key() -> str:
    env = os.environ.get("SEQR_API_KEY", "")
    if env:
        return env
    return get("auth", "api_key", "")


def init_config() -> Path:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not _CONFIG_FILE.exists():
        _CONFIG_FILE.write_text(_render_defaults(), encoding="utf-8")
    return _CONFIG_FILE


def set_value(key_path: str, value: str) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = _load()
    parts = key_path.split(".")
    if len(parts) != 2:
        raise ValueError(f"Key must be section.key format, got: {key_path}")
    section, key = parts
    cfg.setdefault(section, {})[key] = value
    if toml is None:
        raise RuntimeError("toml package not available")
    _CONFIG_FILE.write_text(toml.dumps(cfg), encoding="utf-8")


def show() -> str:
    cfg = _load()
    if toml is None:
        import json
        return json.dumps(cfg, indent=2)
    return toml.dumps(cfg)


def _render_defaults() -> str:
    lines = [
        "# ~/.seqr/config.toml\n",
        "[auth]",
        'api_key = ""',
        'api_url = "https://api.seqr.in"',
        "",
        "[scan]",
        'default_severity = "medium"',
        'default_output = "terminal"',
        "exclude_patterns = [",
        '    "node_modules/",',
        '    ".venv/",',
        '    "__pycache__/",',
        '    "vendor/",',
        '    "*.test.*",',
        '    "*.spec.*"',
        "]",
        'languages = ["python", "javascript", "java", "go"]',
        "",
        "[patterns]",
        'version = "1.4.0"',
        "auto_update = true",
        'update_channel = "stable"',
        "",
    ]
    return "\n".join(lines)
