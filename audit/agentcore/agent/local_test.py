"""Run the whole agent loop locally — NO AgentCore, NO ECR, NO container.

This is the credit-lean dev path: it still calls Bedrock (a few cents of Haiku/Nova tokens) and
your live SeQr backend, but skips every AgentCore/ECR resource. Use it to iterate on tools and
the prompt before you ever deploy.

    export SEQR_API_BASE=http://13.207.4.171:8000     # or http://localhost:8000
    export SEQR_API_KEY=sq_live_xxx
    export AWS_REGION=ap-south-1
    python -m agent.local_test --org "Demo Org"

Requires Bedrock model access enabled for SEQR_MODEL_ID in AWS_REGION.
"""

import argparse
import json

from .entrypoint import invoke


def main() -> None:
    ap = argparse.ArgumentParser(description="Local A4 audit (no AgentCore deploy)")
    ap.add_argument("--org", default="Demo Org")
    ap.add_argument("--instructions", default="")
    args = ap.parse_args()

    out = invoke({"org": args.org, "instructions": args.instructions})
    print("\n=== TOOLS USED ===")
    print(", ".join(out.get("tools_used") or []) or "(none)")
    print("\n=== MIGRATION PLAN (advisory) ===\n")
    print(out.get("plan", ""))
    print("\n=== RAW ===")
    print(json.dumps({k: v for k, v in out.items() if k != "plan"}, indent=2))


if __name__ == "__main__":
    main()
