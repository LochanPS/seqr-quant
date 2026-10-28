"""Command-line entrypoint for the SeQr discovery agent.

    seqr-agent run       --config agent.yaml     # collect + deliver (connected or airgap)
    seqr-agent collect   --config agent.yaml     # collect only, print JSON (dry run)
    seqr-agent export    --config agent.yaml     # force air-gap envelope write
    seqr-agent verify    --config agent.yaml --envelope out.json   # self-check a signature

The single packaged binary/image invokes `run`. Everything else is for operators/debugging.
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .runtime import collect, run


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="seqr-agent", description="SeQr discovery agent (read-only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("run", "collect", "export"):
        sp = sub.add_parser(name)
        sp.add_argument("--config", "-c", help="path to agent config (JSON/YAML)")

    vp = sub.add_parser("verify")
    vp.add_argument("--config", "-c", required=True)
    vp.add_argument("--envelope", "-e", required=True, help="envelope file to verify")

    args = p.parse_args(argv)
    cfg = load_config(getattr(args, "config", None))

    if args.cmd == "collect":
        res = collect(cfg)
        print(json.dumps(res.observations, indent=2))
        return 0

    if args.cmd == "export":
        cfg.mode = "airgap"
        summary = run(cfg)
        return 0 if summary.get("observations", 0) >= 0 else 1

    if args.cmd == "verify":
        from . import signing, uploader
        priv, _ = signing.load_or_create_key(cfg.keyfile)
        ok = uploader.verify_envelope_file(args.envelope, signing.public_key_pem(priv))
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1

    # run
    summary = run(cfg)
    status = summary.get("http_status")
    if status is not None and status >= 400:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
