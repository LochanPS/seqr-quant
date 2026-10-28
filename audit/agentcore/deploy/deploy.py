"""Create or update the SeQr AgentCore Runtime from an ECR image (boto3, no console clicks).

Uses the bedrock-agentcore-control plane. Writes the runtime id/arn to .agentcore-runtime.json
so demo/run_audit.py and iac/teardown.sh can find it. Passes the backend creds by Secrets
Manager reference (never plaintext) and the model id as an env var.
"""

import argparse
import json
import pathlib

import boto3
from botocore.exceptions import ClientError

STATE = pathlib.Path(__file__).resolve().parent.parent / ".agentcore-runtime.json"


def _client(region: str):
    return boto3.client("bedrock-agentcore-control", region_name=region)


def _find_existing(c, name: str) -> str | None:
    for rt in c.list_agent_runtimes().get("agentRuntimes", []):
        if rt.get("agentRuntimeName") == name:
            return rt.get("agentRuntimeId")
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--role-arn", required=True)
    ap.add_argument("--secret-arn", required=True)
    ap.add_argument("--model-id", required=True)
    ap.add_argument("--region", default="ap-south-1")
    args = ap.parse_args()

    c = _client(args.region)
    container = {"containerConfiguration": {"containerUri": args.image}}
    env = {
        "SEQR_MODEL_ID": args.model_id,
        "AWS_REGION": args.region,
        # The runtime resolves these two from the secret at start; keys map to secret JSON fields.
        "SEQR_SECRET_ARN": args.secret_arn,
    }
    common = dict(
        agentRuntimeArtifact=container,
        roleArn=args.role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        environmentVariables=env,
    )

    existing = _find_existing(c, args.name)
    try:
        if existing:
            resp = c.update_agent_runtime(agentRuntimeId=existing, **common)
            print(f"updated runtime {existing}")
        else:
            resp = c.create_agent_runtime(agentRuntimeName=args.name, **common)
            print(f"created runtime {resp.get('agentRuntimeId')}")
    except ClientError as exc:
        raise SystemExit(f"AgentCore create/update failed: {exc}")

    STATE.write_text(json.dumps({
        "agentRuntimeId": resp.get("agentRuntimeId", existing),
        "agentRuntimeArn": resp.get("agentRuntimeArn"),
        "name": args.name,
        "region": args.region,
    }, indent=2))
    print(f"wrote {STATE.name}")


if __name__ == "__main__":
    main()
