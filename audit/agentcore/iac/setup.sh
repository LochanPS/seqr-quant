#!/usr/bin/env bash
# Scripted IaC for the SeQr A4 AgentCore agent. Idempotent-ish; run from audit/agentcore/.
# Creates: IAM execution role, ECR repo, arm64 image (built + pushed), Secrets Manager secret,
# and the AgentCore Runtime. Costs are near-zero until you INVOKE the runtime; teardown.sh
# removes everything. Bedrock model access must be enabled once in the console (see README).
set -euo pipefail

REGION="${AWS_REGION:-ap-south-1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REPO="seqr-agentcore"
ROLE="seqr-agentcore-exec"
RUNTIME_NAME="${RUNTIME_NAME:-seqr_discovery_agent}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
ECR_URI="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${REPO}"
SECRET_NAME="seqr/agentcore/api-key"

: "${SEQR_API_BASE:?set SEQR_API_BASE (e.g. http://13.207.4.171:8000)}"
: "${SEQR_API_KEY:?set SEQR_API_KEY (sq_live_... agent credential)}"

echo ">> account=${ACCOUNT} region=${REGION}"

echo ">> [1/6] IAM execution role"
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" \
    --assume-role-policy-document file://iac/trust-policy.json >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE" \
  --policy-name seqr-agentcore-exec --policy-document file://iac/execution-policy.json
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${ROLE}"

echo ">> [2/6] Secrets Manager (agent sq_live_ key, never baked into the image)"
if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" >/dev/null 2>&1; then
  aws secretsmanager put-secret-value --secret-id "$SECRET_NAME" --region "$REGION" \
    --secret-string "{\"SEQR_API_BASE\":\"${SEQR_API_BASE}\",\"SEQR_API_KEY\":\"${SEQR_API_KEY}\"}" >/dev/null
else
  aws secretsmanager create-secret --name "$SECRET_NAME" --region "$REGION" \
    --secret-string "{\"SEQR_API_BASE\":\"${SEQR_API_BASE}\",\"SEQR_API_KEY\":\"${SEQR_API_KEY}\"}" >/dev/null
fi

echo ">> [3/6] ECR repo"
aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "$REPO" --region "$REGION" >/dev/null

echo ">> [4/6] build + push arm64 image"
aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
docker buildx create --use --name seqrbuilder >/dev/null 2>&1 || docker buildx use seqrbuilder
docker buildx build --platform linux/arm64 -t "${ECR_URI}:${IMAGE_TAG}" --push .

echo ">> [5/6] create/update AgentCore Runtime"
python deploy/deploy.py \
  --name "$RUNTIME_NAME" \
  --image "${ECR_URI}:${IMAGE_TAG}" \
  --role-arn "$ROLE_ARN" \
  --secret-arn "arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:${SECRET_NAME}" \
  --model-id "${SEQR_MODEL_ID:-anthropic.claude-haiku-4-5-20251001-v1:0}"

echo ">> [6/6] done. Run one audit:  python demo/run_audit.py --org 'Demo Org'"
echo ">> TEAR DOWN when judging ends:  ./iac/teardown.sh"
