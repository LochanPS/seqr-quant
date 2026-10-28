# SeQr discovery agent — slim, read-only, runs from a mounted config (PRD 15 Slice 3).
#
#   docker build -t seqrlabs/seqr-agent:0.1.0 deploy/agent
#   docker run --rm \
#     -e AGENT_KEY=sq_live_xxx \
#     -v $PWD/agent.yaml:/etc/seqr/agent.yaml:ro \
#     -v seqr-agent-state:/var/lib/seqr \
#     seqrlabs/seqr-agent:0.1.0 run --config /etc/seqr/agent.yaml
#
# Air-gap: mount an output dir and use mode: airgap in the config; the signed envelope lands in it.
FROM python:3.12-slim-trixie

# Non-root: the agent only reads. No build toolchain — cryptography ships manylinux wheels.
RUN useradd --system --create-home --home-dir /home/seqr seqr \
    && mkdir -p /var/lib/seqr /etc/seqr \
    && chown -R seqr:seqr /var/lib/seqr

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY seqr_agent/ ./seqr_agent/

# Persist the agent's Ed25519 identity key across runs (bind a volume here).
ENV AGENT_KEYFILE=/var/lib/seqr/.agent_ed25519.pem
USER seqr

ENTRYPOINT ["python", "-m", "seqr_agent.cli"]
CMD ["run", "--config", "/etc/seqr/agent.yaml"]
