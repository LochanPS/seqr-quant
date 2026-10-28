# AgentCore Runtime requires linux/arm64. Build with buildx (see iac/setup.sh).
FROM --platform=linux/arm64 python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AWS_REGION=ap-south-1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/

# AgentCore Runtime contract: serve POST /invocations + GET /ping on 8080.
EXPOSE 8080
# Observability (GenAI traces -> CloudWatch) turns on when the runtime sets this; cheap.
ENV AGENT_OBSERVABILITY_ENABLED=true

CMD ["python", "-m", "agent.entrypoint"]
