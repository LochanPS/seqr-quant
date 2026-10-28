# Build context must be the seqr-labs repo root (sibling of shared-scanner/),
# not this directory — see render.yaml `dockerContext: .` at repo root.
#
# trixie (Debian 13) ships OpenSSL 3.5.x, which has native ML-KEM hybrid groups
# (X25519MLKEM768 etc.) — required for active PQC detection (scanner/pqc_probe.py).
# bookworm's OpenSSL 3.0 lacks them; the probe falls back to passive there.
FROM python:3.12-slim-trixie

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc openssl && rm -rf /var/lib/apt/lists/*

COPY shared-scanner /app/shared-scanner
COPY scan-demo-service/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir "/app/shared-scanner[code]"

COPY scan-demo-service/main.py /app/main.py

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
