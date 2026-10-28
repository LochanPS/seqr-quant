"""Core runtime — load config, run the enabled plugins, deliver the batch.

`collect(cfg)` instantiates every enabled, available plugin, isolates each `collect()`, and
returns the merged normalized observations. `run(cfg)` then either uploads them live or writes a
signed air-gap envelope, depending on `cfg.mode`. One plugin failing never aborts the run.
"""

from __future__ import annotations

from .config import AgentConfig
from .plugins import REGISTRY


class PluginRunResult:
    def __init__(self):
        self.observations: list[dict] = []
        self.ran: list[str] = []
        self.skipped: list[str] = []
        self.failed: dict[str, str] = {}


def collect(cfg: AgentConfig, log=print) -> PluginRunResult:
    """Run every enabled, available plugin; return merged observations + per-plugin status."""
    result = PluginRunResult()
    for key in cfg.enabled_plugins:
        cls = REGISTRY.get(key)
        if cls is None:
            result.skipped.append(key)
            log(f"  [--] {key:12} unknown plugin — skipped")
            continue
        plugin = cls(config=cfg.plugins.get(key) or {})
        try:
            if not plugin.available():
                result.skipped.append(key)
                log(f"  [--] {key:12} unavailable (no targets/deps) — skipped")
                continue
            obs = plugin.collect()
            dicts = [o.to_dict() for o in obs]
            result.observations.extend(dicts)
            result.ran.append(key)
            log(f"  [OK] {key:12} {len(dicts)} observation(s)")
        except Exception as e:  # noqa: BLE001 — never let one source abort the run
            result.failed[key] = str(e)
            log(f"  [XX] {key:12} failed: {e}")
    return result


def run(cfg: AgentConfig, log=print) -> dict:
    """Collect and deliver. Returns a summary dict; raises only on unrecoverable config errors."""
    from . import signing, uploader

    log(f"[agent] {cfg.name} — mode={cfg.mode}")
    log(f"[agent] plugins: {', '.join(cfg.enabled_plugins) or '(none)'}")

    priv, created = signing.load_or_create_key(cfg.keyfile)
    log(f"[agent] key {'generated' if created else 'loaded'} ({cfg.keyfile})")

    res = collect(cfg, log=log)
    obs = res.observations
    if not obs:
        log("[agent] no observations gathered — nothing to deliver")
        return {"observations": 0, "ran": res.ran, "skipped": res.skipped, "failed": res.failed}

    if cfg.mode == "airgap":
        key_prefix = (cfg.credential or "sq_live_")[:8]
        envelope = uploader.build_envelope(cfg.name, key_prefix, obs, priv)
        uploader.write_envelope(cfg.export_path, envelope)
        log(f"[agent] wrote signed air-gap envelope -> {cfg.export_path} "
            f"({len(obs)} observations, {len(envelope['signature'])}-char sig)")
        log(f"[agent] enrol this key once (PEM) if the credential is not yet key-bound:")
        log(signing.public_key_pem(priv).strip())
        return {"observations": len(obs), "mode": "airgap", "export_path": cfg.export_path,
                "ran": res.ran, "skipped": res.skipped, "failed": res.failed}

    # connected
    if not cfg.credential:
        raise ValueError("connected mode needs a credential (AGENT_KEY env or config.credential)")
    status, body = uploader.upload(cfg.api, cfg.credential, cfg.name, obs, priv,
                                   first_run=created, timeout=cfg.timeout)
    log(f"[agent] upload -> HTTP {status}: {body}")
    return {"observations": len(obs), "mode": "connected", "http_status": status,
            "result": body, "ran": res.ran, "skipped": res.skipped, "failed": res.failed}
