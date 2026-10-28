# SeQr async scan worker.
#
# Same runtime as the API image (Dockerfile.render) — it needs the shared scanner
# and OpenSSL 3.5 for active ML-KEM probing — but its entrypoint is the Celery
# worker instead of uvicorn. Build context MUST be the seqr-labs repo root (sibling
# of shared-scanner/), because the scanner installs from ../../shared-scanner.
#
#   docker build -f deploy/worker/Dockerfile -t seqrlabs/seqr-worker .
#
# trixie ships OpenSSL 3.5.x (native ML-KEM hybrid groups); older OpenSSL falls back
# to passive scanning automatically.
FROM python:3.12-slim-trixie

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Scanner first (changes least → better layer caching).
COPY shared-scanner /app/shared-scanner
COPY audit/backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
    && pip install --no-cache-dir /app/shared-scanner

COPY audit/backend /app/backend
WORKDIR /app/backend

# --concurrency: global parallelism (worker slots). Override per host size.
# --prefetch-multiplier=1 and acks_late are set in app.tasks conf; the flag here is
# belt-and-suspenders. Per-org fairness is enforced in the task (MAX_CONCURRENT_SCANS_PER_ORG).
ENV SCAN_WORKER_CONCURRENCY=8
CMD ["sh", "-c", "celery -A app.tasks worker --loglevel=info --concurrency=${SCAN_WORKER_CONCURRENCY:-8} --prefetch-multiplier=1"]
