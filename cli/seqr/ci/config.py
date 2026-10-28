"""Optional ``seqr-ci.yml`` — repo-level defaults for the gate.

So a team configures the gate once (in-repo, reviewable) instead of threading flags
through every CI invocation. Every key is optional and mirrors a ``seqr ci`` flag; an
explicit command-line flag always wins over the file, which always wins over the built-in
defaults. Example::

    fail_on: high            # or: policy: strict
    fail_on_drift: true      # fail the build on NEW drift from the crypto policy
    policy_file: seqr-policy.json
    baseline: seqr-baseline.json
    exclude:                 # directories to skip
      - vendor
      - third_party
    language: python

Unknown keys are ignored (forward-compatible). A malformed file raises
:class:`CIConfigError` so a typo fails loudly rather than silently disabling the gate.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

CONFIG_FILENAMES = ("seqr-ci.yml", "seqr-ci.yaml")

# Recognised keys and the type each must be, so a bad value is caught early.
_SCALAR_KEYS = {
    "fail_on": str,
    "policy": str,
    "policy_file": str,
    "baseline": str,
    "fail_on_drift": bool,
    "language": str,
}
_LIST_KEYS = {"exclude"}


class CIConfigError(ValueError):
    """Raised when ``seqr-ci.yml`` is present but cannot be parsed or is malformed."""


def find_config_file(root: str | os.PathLike[str] | None = None) -> Path | None:
    """Return the first auto-discovered config file in ``root`` (cwd default), or None."""
    base = Path(root or os.getcwd())
    for name in CONFIG_FILENAMES:
        p = base / name
        if p.is_file():
            return p
    return None


def parse_config(text: str) -> dict[str, Any]:
    """Parse and validate ``seqr-ci.yml`` text into a defaults dict."""
    import yaml

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - message passthrough
        raise CIConfigError(f"could not parse seqr-ci.yml: {exc}") from exc
    if not isinstance(data, dict):
        raise CIConfigError("seqr-ci.yml must be a mapping of settings")

    out: dict[str, Any] = {}
    for key, value in data.items():
        if key in _SCALAR_KEYS:
            expected = _SCALAR_KEYS[key]
            # YAML parses `true/false` as bool and numbers as int — coerce a stray bool
            # away from string keys and validate the rest.
            if expected is bool:
                if not isinstance(value, bool):
                    raise CIConfigError(f"'{key}' must be true or false")
            elif not isinstance(value, str):
                raise CIConfigError(f"'{key}' must be a string")
            out[key] = value
        elif key in _LIST_KEYS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise CIConfigError(f"'{key}' must be a list of strings")
            out[key] = value
        # unknown keys ignored (forward-compatible)
    return out


def load_config(
    source: str | os.PathLike[str] | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Load config from an explicit ``source`` path or an auto-discovered file.

    Returns ``{}`` when no config file exists. An explicit ``source`` that does not exist
    raises :class:`CIConfigError` (the user asked for a specific file).
    """
    if source is not None:
        p = Path(source)
        if not p.is_file():
            raise CIConfigError(f"config file not found: {source}")
    else:
        p = find_config_file(root)
        if p is None:
            return {}
    return parse_config(p.read_text(encoding="utf-8"))


__all__ = [
    "CIConfigError",
    "CONFIG_FILENAMES",
    "find_config_file",
    "parse_config",
    "load_config",
]
