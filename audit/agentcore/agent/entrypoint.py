"""AgentCore Runtime entrypoint for the SeQr discovery/analysis agent (A4 / PRD 15).

The container serves the AgentCore Runtime contract (POST /invocations, GET /ping on :8080) via
``BedrockAgentCoreApp``. A Strands ``Agent`` drives a Bedrock model (Haiku 4.5 by default — cheap
and strong at tool use; swap to Nova Lite via SEQR_MODEL_ID for the lowest token cost) over the
four SeQr tools.

Session context (short-term memory) is carried by the Runtime per session id, so a multi-turn
audit remembers earlier tool results without a paid long-term Memory store. Long-term AgentCore
Memory is an optional upgrade wired in iac/ (off by default to conserve credits).

Run locally with agent/local_test.py — that path exercises the whole loop against Bedrock with
NO AgentCore/ECR spend.
"""

import os

from strands import Agent
from strands.models import BedrockModel

from .prompts import SYSTEM_PROMPT
from .tools import ALL_TOOLS

# ap-south-1 on-demand Anthropic Haiku 4.5 uses the "global." inference profile (no "apac."
# variant exists); both a bare id and a profile id are accepted via SEQR_MODEL_ID (see README).
_DEFAULT_MODEL = "anthropic.claude-haiku-4-5-20251001-v1:0"

# The AgentCore Runtime package is only needed when serving inside the container. Keep it an
# optional import so the local path (agent/local_test.py) runs with just strands + httpx.
try:
    from bedrock_agentcore.runtime import BedrockAgentCoreApp

    app = BedrockAgentCoreApp()
    _entrypoint = app.entrypoint
except ModuleNotFoundError:  # local dev without bedrock-agentcore installed
    app = None

    def _entrypoint(fn):  # no-op decorator; @app.entrypoint is a server-only concern
        return fn


def build_agent() -> Agent:
    model = BedrockModel(
        model_id=os.environ.get("SEQR_MODEL_ID", _DEFAULT_MODEL),
        region_name=os.environ.get("AWS_REGION", "ap-south-1"),
        temperature=0.2,  # deterministic-ish: this is an audit, not brainstorming
    )
    return Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=ALL_TOOLS)


def _prompt_for(payload: dict) -> str:
    org = payload.get("org") or payload.get("org_name") or "the target organisation"
    extra = payload.get("instructions", "")
    base = (
        f"Perform a full autonomous crypto-migration audit for {org}. "
        "Gather the CBOM, policy violations, HNDL exposure and compliance status, then return a "
        "prioritised migration order."
    )
    return f"{base}\n\n{extra}".strip()


@_entrypoint
def invoke(payload: dict) -> dict:
    """One autonomous audit. Payload: {"org": "...", "instructions": "..."(optional)}.

    Returns the model's prioritised migration plan plus which tools ran, so the trace and the
    result are both inspectable. The org the plan covers is whichever org the SEQR_API_KEY is
    scoped to — the key, not the payload, is the tenant boundary.
    """
    agent = build_agent()
    result = agent(_prompt_for(payload or {}))
    text = str(result)
    tools_used = sorted({
        block["name"]
        for msg in getattr(agent, "messages", [])
        for block in (msg.get("content") or [])
        if isinstance(block, dict) and "name" in block and msg.get("role") == "assistant"
    })
    return {"plan": text, "tools_used": tools_used, "advisory": True}


if __name__ == "__main__":
    # Runs the AgentCore Runtime HTTP server (used inside the container).
    if app is None:
        raise SystemExit("bedrock-agentcore not installed — this entrypoint runs inside the "
                         "AgentCore container. For local runs use: python -m agent.local_test")
    app.run()
