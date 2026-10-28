# SeQr A4 — Bedrock AgentCore discovery/analysis agent

An autonomous crypto-migration analyst that runs on **AWS Bedrock AgentCore Runtime** with a
Bedrock model as its reasoning engine. Given a target org it gathers the CBOM, policy
violations, HNDL exposure and compliance status, then returns a **prioritised migration order**.
Advisory only — it proposes; a human applies the signed bundle + runbook.

Region: **ap-south-1** (Mumbai) — sovereignty preserved, same as the rest of SeQr.

## What it is (and isn't)

- **Is:** a thin reasoning layer over the *existing* org-scoped SeQr REST API. Four tools, no
  new backend logic. It reuses the spine, policy engine and migration engine already shipped.
- **Isn't:** the on-prem discovery agent of PRD 15 (that's a dumb, read-only plugin collector,
  still deferred). A4 is the *analyst* that reasons over what the platform already knows.

## Files

```
agent/
  entrypoint.py    AgentCore Runtime entrypoint (BedrockAgentCoreApp + Strands Agent)
  tools.py         the 4 tools: scan_domain, get_cbom, get_policy_violations, propose_migration_order
  seqr_client.py   httpx client -> SeQr API, org-scoped by an sq_live_ key
  prompts.py       system prompt (advisory, HNDL disclaimer, no CNSA, PLANNED language)
  local_test.py    run the whole loop locally — NO AgentCore/ECR spend
Dockerfile         linux/arm64 (AgentCore requirement)
requirements.txt
iac/
  setup.sh         one-shot: IAM role + ECR + build/push + secret + create runtime
  teardown.sh      delete everything A4 (leaves EC2 + model access alone)
  trust-policy.json / execution-policy.json   least-privilege IAM
deploy/deploy.py   boto3 create/update runtime from the ECR image
demo/run_audit.py  run ONE autonomous audit against the deployed runtime + print trace link
```

## Credit discipline (this was a hard requirement)

| Phase | Spend |
|---|---|
| Build + edit code | **$0** — nothing touches AWS |
| `agent/local_test.py` | a few cents of Bedrock tokens (Haiku/Nova), **no** AgentCore/ECR |
| Idle after deploy | ~pennies/mo (ECR image storage only; runtime bills per session, not idle) |
| One `run_audit.py` | one short Haiku/Nova session — cents |
| After `teardown.sh` | **$0** |

Levers already applied: reasoning model defaults to **Haiku 4.5** (swap to `amazon.nova-lite-v1:0`
via `SEQR_MODEL_ID` for the cheapest tokens); long-term AgentCore Memory is **off** (session
short-term memory is free); Gateway is **not** provisioned (tools run in-runtime — see below);
`temperature=0.2` keeps runs short and deterministic.

> Iterate with `local_test.py`. Only deploy for the actual demo, then run `teardown.sh`.

## Prerequisites (once)

1. **Enable Bedrock model access** for your model in ap-south-1: Bedrock console → Model access →
   enable `Claude Haiku 4.5` (and/or `Amazon Nova Lite`). Listing a model ≠ access granted.
2. Docker with **buildx** (arm64 cross-build) and the AWS CLI v2, authenticated.
3. An **`sq_live_` agent credential** for the demo org (dashboard → mint agent credential, or
   `POST /api/v1/agent/credentials`).

## Deploy

```bash
cd audit/agentcore
export SEQR_API_BASE=http://13.207.4.171:8000     # the EC2 demo backend
export SEQR_API_KEY=sq_live_xxxxxxxx              # agent credential for the demo org
export SEQR_MODEL_ID=anthropic.claude-haiku-4-5-20251001-v1:0   # or amazon.nova-lite-v1:0
./iac/setup.sh
python demo/run_audit.py --org "Demo Org"
```

`run_audit.py` prints the tools the agent called, the prioritised plan, and the CloudWatch /
GenAI-Observability location of the trace.

### ap-south-1 model-id note
On-demand Anthropic invocation in ap-south-1 may require the **inference-profile** id
`apac.anthropic.claude-haiku-4-5-20251001-v1:0` instead of the bare model id. If invocation
returns an "on-demand throughput isn't supported" error, set `SEQR_MODEL_ID` to the `apac.`
profile (the execution policy already allows it).

## Teardown (when judging ends)

```bash
./iac/teardown.sh
```

Removes the runtime, ECR repo/images, secret, IAM role and local builder. Your EC2 demo box and
Bedrock model access are left untouched.

## Optional upgrade — AgentCore Gateway (MCP tools)

The four tools run **in-runtime** by default (cheapest: no extra resource, no OAuth authorizer).
To expose them as managed **Gateway MCP tools** instead, front the SeQr endpoints with a Gateway
target (OpenAPI or Lambda) behind a Cognito authorizer and point the agent at the Gateway MCP
URL. That adds a Gateway + user pool to provision and bill — worth it for multi-agent reuse,
overkill for a single hackathon demo. Left documented, not wired.

## Security

- No credentials in the image or code. The `sq_live_` key lives in Secrets Manager; the runtime
  reads it via an IAM role (`iac/execution-policy.json`, least privilege — InvokeModel on the two
  allowed models, pull on the one ECR repo, read on the one secret, logs/traces).
- Tenant boundary is the API key's org, not the payload. The agent cannot cross orgs.
- Read-only except `scan_domain` (triggers a scan). No infra changes — migration stays advisory.
