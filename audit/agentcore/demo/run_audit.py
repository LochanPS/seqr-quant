"""Run ONE full autonomous audit against the deployed AgentCore Runtime, then print the plan
and the CloudWatch trace link. This is the demo script (acceptance: agent runs on AgentCore,
calls >=3 tools, returns a prioritised plan, trace viewable).

    python demo/run_audit.py --org "Demo Org"

Reads the runtime id from .agentcore-runtime.json (written by deploy). Invocation is the only
step that costs meaningful credits (a short Haiku/Nova session); nothing bills while idle.
"""

import argparse
import json
import pathlib
import uuid

import boto3

STATE = pathlib.Path(__file__).resolve().parent.parent / ".agentcore-runtime.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", default="Demo Org")
    ap.add_argument("--instructions", default="")
    ap.add_argument("--region", default=None)
    args = ap.parse_args()

    if not STATE.exists():
        raise SystemExit("no .agentcore-runtime.json — run iac/setup.sh first")
    state = json.loads(STATE.read_text())
    region = args.region or state.get("region", "ap-south-1")
    runtime_arn = state["agentRuntimeArn"]

    rt = boto3.client("bedrock-agentcore", region_name=region)
    session_id = str(uuid.uuid4())  # session id carries short-term memory across turns
    payload = json.dumps({"org": args.org, "instructions": args.instructions}).encode()

    print(f">> invoking {state.get('name')} (session {session_id[:8]})...")
    resp = rt.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id,
        payload=payload,
    )
    body = resp["response"].read() if hasattr(resp.get("response"), "read") else resp.get("response")
    data = json.loads(body) if isinstance(body, (bytes, str)) else body

    print("\n=== TOOLS USED ===")
    print(", ".join(data.get("tools_used") or []) or "(none)")
    print("\n=== MIGRATION PLAN (advisory — human approves the bundle) ===\n")
    print(data.get("plan", data))

    log_group = f"/aws/bedrock-agentcore/runtimes/{state.get('agentRuntimeId')}"
    print("\n=== TRACE ===")
    print(f"CloudWatch logs: {log_group}")
    print("GenAI Observability: CloudWatch console -> GenAI Observability -> Bedrock AgentCore")


if __name__ == "__main__":
    main()
