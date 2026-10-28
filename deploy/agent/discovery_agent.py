#!/usr/bin/env python3
"""SeQr discovery agent — back-compat entrypoint.

The agent is now a plugin package (`seqr_agent/`). This thin wrapper preserves the original
env-driven, TLS-only invocation so existing runbooks keep working:

    AGENT_KEY=sq_live_xxx python deploy/agent/discovery_agent.py

It builds a connected-mode config with the historical default TLS targets and the TLS probe
plugin, then delegates to the package runtime. For the full plugin set (cert stores, proxy
configs, HSM) and air-gap mode, use a config file:

    python -m seqr_agent.cli run --config agent.yaml
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seqr_agent.config import AgentConfig  # noqa: E402
from seqr_agent.runtime import run  # noqa: E402

# Historical default targets (real TLS endpoints) — unchanged from the original agent.
_DEFAULT_TARGETS = [
    {"host": "seqrlabs.com", "port": 443, "role": "web-frontend"},
    {"host": "smtp.gmail.com", "port": 465, "role": "mail-relay"},
    {"host": "github.com", "port": 443, "role": "source-control"},
    {"host": "login.microsoftonline.com", "port": 443, "role": "identity-provider"},
    {"host": "s3.amazonaws.com", "port": 443, "role": "object-store"},
    {"host": "api.stripe.com", "port": 443, "role": "payments-gateway"},
]


def main():
    if not os.environ.get("AGENT_KEY"):
        sys.exit("AGENT_KEY env var required")
    cfg = AgentConfig(
        name=os.environ.get("AGENT_NAME", "prod-discovery-agent-01"),
        mode="connected",
        api=os.environ.get("SEQR_API", "http://13.207.4.171:8000/api/v1"),
        credential=os.environ["AGENT_KEY"],
        keyfile=os.environ.get(
            "AGENT_KEYFILE",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_ed25519.pem"),
        ),
        plugins={"tls": {"targets": _DEFAULT_TARGETS}},
    )
    summary = run(cfg)
    if (summary.get("http_status") or 200) >= 400:
        sys.exit(1)


if __name__ == "__main__":
    main()
