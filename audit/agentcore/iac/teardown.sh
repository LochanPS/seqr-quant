#!/usr/bin/env bash
# Remove every A4 AgentCore resource. Run from audit/agentcore/ when judging ends.
# Leaves your EC2 demo box and Bedrock model access untouched.
set -uo pipefail

REGION="${AWS_REGION:-ap-south-1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REPO="seqr-agentcore"
ROLE="seqr-agentcore-exec"
SECRET_NAME="seqr/agentcore/api-key"
STATE="./.agentcore-runtime.json"

echo ">> [1/5] delete AgentCore Runtime"
if [ -f "$STATE" ]; then
  RID="$(python -c "import json;print(json.load(open('$STATE')).get('agentRuntimeId',''))")"
  [ -n "$RID" ] && aws bedrock-agentcore-control delete-agent-runtime \
    --agent-runtime-id "$RID" --region "$REGION" && rm -f "$STATE" || true
fi

echo ">> [2/5] delete ECR repo (images included)"
aws ecr delete-repository --repository-name "$REPO" --region "$REGION" --force >/dev/null 2>&1 || true

echo ">> [3/5] delete secret"
aws secretsmanager delete-secret --secret-id "$SECRET_NAME" --region "$REGION" \
  --force-delete-without-recovery >/dev/null 2>&1 || true

echo ">> [4/5] delete IAM role"
aws iam delete-role-policy --role-name "$ROLE" --policy-name seqr-agentcore-exec >/dev/null 2>&1 || true
aws iam delete-role --role-name "$ROLE" >/dev/null 2>&1 || true

echo ">> [5/5] remove local buildx builder"
docker buildx rm seqrbuilder >/dev/null 2>&1 || true

echo ">> teardown complete. Nothing from A4 is still billing."
