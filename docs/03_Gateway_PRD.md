# SeQr Gateway — Engineering PRD v1.0
### Quantum-Safe API Gateway · Drop-in TLS Upgrade Middleware
**Status: LARGELY SUPERSEDED by the Migration Engine (2026-07).** The inline PQC-terminating
gateway is now a *later, opt-in* delivery mode. The primary remediation path is the migration
engine (`docs/12` §8, `docs/13`): a **signed change bundle + runbook** the customer's ops applies
to their own nginx/Apache/HAProxy/CDN/ALB — no inline SeQr box in the traffic path, lower
liability, air-gap friendly. Keep this doc as reference for the eventual managed-gateway option.

**Hand this entire document to Claude Code when building.**

---

## Deferral Rationale

SeQr Gateway is the "deploy" layer of the Audit → SDK → Gateway migration stack.
It requires pqcmap SDK (which is also not started) and a stable audit backend.
Build order: audit backend (sessions 1-8 done) → Session 9 frontend → first customer
→ pqcmap SDK → SeQr Gateway.

Gateway solves a different buyer problem: customers who want quantum-safe TLS NOW
without code changes. They pay for the audit to know what to fix, pay for the gateway
to fix the network layer immediately while code migration happens on a longer timeline.

Domain: gateway.seqrlabs.com
Docker: docker pull seqrlabs/gateway:latest (not seqr/gateway)

---

## PRODUCT SUMMARY

SeQr Gateway is a reverse proxy that sits in front of existing APIs and
upgrades all TLS connections to quantum-safe hybrid TLS (X25519+ML-KEM-768 key
exchange, ML-DSA certificates) without requiring any code changes in the
customer's backend.

Deployed as: Docker container (primary), Kubernetes sidecar, or VM appliance.
Built on: NGINX + OpenSSL 3.x + oqs-provider (Open Quantum Safe).
Managed via: REST management API + YAML config.

Revenue: Per gateway instance per month. Enterprise: custom.

---

## HOW IT WORKS (SIMPLE EXPLANATION)

```
BEFORE SeQr Gateway:
  Client Browser ──[RSA TLS handshake]──► Customer API (port 443)
  (vulnerable to quantum harvest-now-decrypt-later)

AFTER SeQr Gateway:
  Client Browser ──[ML-KEM hybrid TLS]──► SeQr Gateway ──[internal TLS]──► Customer API
  (quantum-safe on client-facing side, classical on internal hop)

Customer's backend code: unchanged
Customer's DNS: points to gateway IP/hostname instead of their API
Gateway: handles all TLS termination and re-encryption
```

---

## PROJECT STRUCTURE

```
seqr-gateway/
├── nginx/
│   ├── nginx.conf.template      # NGINX config template (rendered from gateway.yaml)
│   ├── oqs-provider.conf        # OpenSSL oqs-provider configuration
│   └── snippets/
│       ├── pqc-tls.conf         # PQC TLS settings block
│       ├── proxy-headers.conf   # Standard proxy headers
│       └── security-headers.conf
├── management-api/
│   ├── main.py                  # FastAPI management API
│   ├── config/
│   │   ├── loader.py            # Load and validate gateway.yaml
│   │   ├── validator.py         # Config schema validation
│   │   └── renderer.py          # Render NGINX config from gateway.yaml
│   ├── cert/
│   │   ├── generator.py         # Generate PQC self-signed or CSR
│   │   └── acme.py              # Let's Encrypt ACME (when PQC certs available)
│   ├── models.py
│   └── requirements.txt
├── scripts/
│   ├── build-oqs-nginx.sh       # Build NGINX with oqs-provider from source
│   ├── generate-pqc-cert.sh     # Generate ML-DSA certificate
│   └── healthcheck.sh
├── Dockerfile
├── docker-compose.yml           # For local development and testing
├── helm/
│   └── seqr-gateway/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── examples/
│   ├── single-api/              # Protect one API
│   ├── multi-api/               # Protect multiple APIs
│   └── kubernetes-sidecar/      # K8s deployment
└── gateway.yaml.example         # Customer config file
```

---

## NGINX BUILD WITH OQS-PROVIDER

```bash
# scripts/build-oqs-nginx.sh
# This is the critical build step — NGINX with quantum-safe TLS support

# OpenSSL 3.x + oqs-provider gives NGINX hybrid PQC TLS
# oqs-provider adds ML-KEM, ML-DSA, and hybrid groups to OpenSSL

# Install oqs-provider (pre-built binary available from Open Quantum Safe)
# Supports: X25519Kyber768 (hybrid), kyber768, ML-KEM-768, etc.

# NGINX configured with:
#   ssl_protocols TLSv1.3;
#   ssl_ecdh_curve X25519Kyber768:X25519:prime256v1;  # prefer PQC hybrid, fallback to classical
#   ssl_certificate /certs/server-mldsa.pem;           # ML-DSA certificate
#   ssl_certificate_key /certs/server-mldsa-key.pem;
```

---

## CUSTOMER CONFIGURATION FILE (gateway.yaml)

```yaml
# gateway.yaml — the only file the customer needs to edit

gateway:
  name: "My Company API Gateway"
  license_key: "SQ-ENTERPRISE-eyJ...base64payload....signature"
  management_api_port: 9090   # internal only, bind to 127.0.0.1

tls:
  mode: hybrid                # hybrid (recommended) | pqc-only | classical-fallback
  kem_algorithm: ML-KEM-768   # key exchange
  sig_algorithm: ML-DSA-65    # certificate signature
  certificate:
    mode: self-signed          # self-signed | provided | acme (future)
    # If provided:
    # cert_path: /certs/my-cert.pem
    # key_path: /certs/my-key.pem
    organization: "Acme Fintech Pvt Ltd"
    validity_days: 365

upstream_services:
  - name: payment-api
    listen_port: 443
    listen_host: "0.0.0.0"
    upstream_url: "http://payment-service:8080"
    health_check: "http://payment-service:8080/health"
    # Optional: per-service TLS settings
    require_client_cert: false

  - name: auth-api
    listen_port: 8443
    upstream_url: "https://auth-service:8081"
    upstream_tls: true         # if upstream uses HTTPS
    upstream_tls_verify: true

  - name: internal-api
    listen_port: 9443
    upstream_url: "http://internal-service:3000"
    # Restrict access to internal IPs only
    allow_cidrs:
      - "10.0.0.0/8"
      - "172.16.0.0/12"

logging:
  level: info                  # debug | info | warn | error
  access_log: true
  pqc_handshake_log: true      # log which TLS algorithms were negotiated
  log_path: /var/log/seqr/

metrics:
  enabled: true
  prometheus_port: 9091        # Prometheus scrape endpoint
  # Metrics include:
  # seqr_connections_total{algorithm="ML-KEM-768"}
  # seqr_classical_fallback_total
  # seqr_tls_handshake_duration_seconds
```

---

## MANAGEMENT API (management-api/main.py)

```
FastAPI app listening on 127.0.0.1:9090 (internal only, never exposed)
Authenticated by: local API key set in gateway.yaml or env var

Routes:

GET  /health              → gateway health, upstream health, cert expiry
GET  /status              → full status: algorithms in use, connections count
GET  /config              → current effective config (rendered)
POST /config/reload       → reload config + NGINX hot-reload (nginx -s reload)
GET  /certs               → certificate details (expiry, algorithm, SANs)
POST /certs/rotate        → generate new certificate, hot-swap
GET  /metrics             → Prometheus text format
GET  /connections         → active connections count by algorithm
GET  /logs                → last N log lines
POST /test-upstream/{name} → test connectivity to upstream service
```

---

## DOCKER SETUP

```dockerfile
# Dockerfile
# Multi-stage build

# Stage 1: Build NGINX with oqs-provider
FROM ubuntu:24.04 AS nginx-builder
RUN apt-get update && apt-get install -y build-essential cmake libpcre3-dev zlib1g-dev
# Install oqs-provider, OpenSSL 3.x, compile NGINX

# Stage 2: Python management API
FROM python:3.12-slim AS management-api
WORKDIR /app
COPY management-api/requirements.txt .
RUN pip install -r requirements.txt
COPY management-api/ .

# Stage 3: Final image
FROM ubuntu:24.04
# Copy NGINX binary from stage 1
COPY --from=nginx-builder /usr/local/nginx /usr/local/nginx
# Copy management API from stage 2
COPY --from=management-api /app /management-api
# Supervisor to run both NGINX and management API
RUN apt-get install -y supervisor python3
COPY supervisord.conf /etc/supervisor/conf.d/seqr.conf
EXPOSE 443 8443 9090 9091
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/seqr.conf"]
```

```yaml
# docker-compose.yml (for testing)
version: '3.9'
services:
  gateway:
    image: seqrlabs/gateway:latest
    ports:
      - "443:443"
      - "9090:9090"   # management API (should be 127.0.0.1 in production)
    volumes:
      - ./gateway.yaml:/etc/seqr/gateway.yaml
      - ./certs:/certs
      - gateway_logs:/var/log/seqr
    environment:
      LICENSE_KEY: ${LICENSE_KEY}

  # Test upstream (mock API for local testing)
  mock-api:
    image: nginx:alpine
    volumes:
      - ./examples/mock-api/nginx.conf:/etc/nginx/nginx.conf

volumes:
  gateway_logs:
```

---

## GENERATED NGINX CONFIG (what the renderer produces)

```nginx
# Auto-generated by SeQr Gateway — do not edit manually
# Re-generated on config reload

events {
    worker_connections 1024;
}

http {
    # Logging
    log_format pqc_combined '$remote_addr - [$time_local] '
                            '"$request" $status $body_bytes_sent '
                            '"$ssl_protocol" "$ssl_cipher" '
                            '"$ssl_curve" "$ssl_session_reused"';

    # SeQr upstream: payment-api
    upstream payment_api_upstream {
        server payment-service:8080;
        keepalive 32;
    }

    server {
        listen 443 ssl;
        server_name _;

        # PQC hybrid TLS
        ssl_protocols TLSv1.3;
        ssl_ecdh_curve X25519Kyber768:X25519:prime256v1;
        ssl_prefer_server_ciphers off;

        # ML-DSA certificate (or hybrid cert during transition)
        ssl_certificate /certs/server-mldsa.pem;
        ssl_certificate_key /certs/server-mldsa-key.pem;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-PQC-Algorithm "X25519Kyber768+ML-DSA-65" always;

        location / {
            proxy_pass http://payment_api_upstream;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-PQC-Protected "true";
        }

        access_log /var/log/seqr/payment-api-access.log pqc_combined;
    }
}
```

---

## CERTIFICATE GENERATION

```bash
# scripts/generate-pqc-cert.sh
# Generates a self-signed ML-DSA certificate using oqs-provider

# Self-signed ML-DSA-65 certificate (for testing and initial deployment)
# Once CAs support PQC (Let's Encrypt roadmap: 2026-2027),
# replace with CA-signed ML-DSA certificate

openssl req -x509 -new -newkey ML-DSA-65 \
  -keyout /certs/server-mldsa-key.pem \
  -out /certs/server-mldsa.pem \
  -days 365 \
  -subj "/CN=${COMMON_NAME}/O=${ORG_NAME}/C=IN" \
  -nodes

# Hybrid certificate (recommended during transition):
# Contains BOTH classical (ECDSA) and PQC (ML-DSA) in one cert
# Supported by most PQC-aware clients while classical clients fall back to ECDSA
```

---

## KUBERNETES HELM CHART (helm/seqr-gateway/values.yaml)

```yaml
replicaCount: 2

image:
  repository: seqrlabs/gateway
  tag: latest
  pullPolicy: IfNotPresent

gateway:
  licenseKey: ""        # set via secret
  config: {}            # gateway.yaml contents as dict

service:
  type: LoadBalancer
  ports:
    - name: https
      port: 443
      targetPort: 443
    - name: management
      port: 9090
      targetPort: 9090
      # Only expose management internally
      internalOnly: true

resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "1000m"

# TLS certificates stored in K8s secret
tls:
  secretName: seqr-gateway-tls

# Prometheus monitoring
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
```

---

## PRICING MODEL

```
Starter Gateway    ₹15,000/month
  1 gateway instance
  Up to 5 upstream services
  Standard support (48h response)
  Metrics + logs

Professional       ₹40,000/month
  3 gateway instances
  Unlimited upstream services
  Priority support (24h response)
  Prometheus + Grafana dashboard template
  Custom TLS policy rules

Enterprise         Custom (₹1,00,000+/month)
  Unlimited instances
  Kubernetes Helm chart
  Air-gapped deployment (no internet)
  Dedicated support engineer
  Custom SLA
  HSM integration (hardware key storage)
```

---

## INSTALLATION GUIDE (for customer docs)

```bash
# 1. Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh

# 2. Download SeQr Gateway
docker pull seqrlabs/gateway:latest

# 3. Create your config file
cp gateway.yaml.example gateway.yaml
# Edit gateway.yaml with your upstream services

# 4. Run
docker run -d \
  --name seqr-gateway \
  -p 443:443 \
  -v $(pwd)/gateway.yaml:/etc/seqr/gateway.yaml \
  -v $(pwd)/certs:/certs \
  -e LICENSE_KEY=your-license-key \
  seqrlabs/gateway:latest

# 5. Verify
curl https://your-domain/health
# Response includes: {"pqc_algorithm": "X25519Kyber768", "status": "ok"}

# 6. Update your DNS to point to the gateway
# A record: your-api.company.com → gateway IP

# Total time to deploy: 15 minutes
```


---

## COMPLETE DOCKERFILE

```dockerfile
# Dockerfile — full multi-stage build

# ─── Stage 1: Build oqs-provider + OpenSSL 3.x ───────────────────────────────
FROM ubuntu:24.04 AS oqs-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential cmake ninja-build \
    libssl-dev zlib1g-dev \
    git curl wget python3 \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs
WORKDIR /build
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
RUN cmake -S liboqs -B liboqs/build \
    -DOQS_DIST_BUILD=ON \
    -DCMAKE_INSTALL_PREFIX=/opt/oqs \
    -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --install liboqs/build

# Build oqs-provider (OpenSSL 3.x plugin for PQC)
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/oqs-provider.git
RUN cmake -S oqs-provider -B oqs-provider/build \
    -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs \
    -DCMAKE_INSTALL_PREFIX=/opt/oqs-provider && \
    cmake --build oqs-provider/build --parallel 4 && \
    cmake --install oqs-provider/build

# ─── Stage 2: Build NGINX with OpenSSL 3.x ───────────────────────────────────
FROM ubuntu:24.04 AS nginx-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential libpcre3-dev zlib1g-dev libgd-dev \
    wget && rm -rf /var/lib/apt/lists/*

ARG NGINX_VERSION=1.26.2
WORKDIR /build

RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar xzf nginx-${NGINX_VERSION}.tar.gz

# Copy OpenSSL from stage 1
COPY --from=oqs-builder /usr/lib/x86_64-linux-gnu/libssl* /usr/lib/x86_64-linux-gnu/
COPY --from=oqs-builder /usr/lib/x86_64-linux-gnu/libcrypto* /usr/lib/x86_64-linux-gnu/
COPY --from=oqs-builder /usr/include/openssl /usr/include/openssl

RUN cd nginx-${NGINX_VERSION} && \
    ./configure \
        --prefix=/usr/local/nginx \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-http_realip_module && \
    make -j4 && make install

# ─── Stage 3: Python management API ──────────────────────────────────────────
FROM python:3.12-slim AS mgmt-api
WORKDIR /app
COPY management-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY management-api/ .

# ─── Stage 4: Final runtime image ────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-pip supervisor \
    libpcre3 zlib1g libgd3 \
    && rm -rf /var/lib/apt/lists/*

# Copy NGINX
COPY --from=nginx-builder /usr/local/nginx /usr/local/nginx

# Copy oqs-provider
COPY --from=oqs-builder /opt/oqs /opt/oqs
COPY --from=oqs-builder /opt/oqs-provider /opt/oqs-provider

# Copy management API + Python deps
COPY --from=mgmt-api /app /management-api
COPY --from=mgmt-api /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=mgmt-api /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=mgmt-api /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# OpenSSL oqs-provider config
COPY nginx/oqs-provider.conf /opt/oqs-provider/oqs-provider.conf

# NGINX config template (rendered on startup by management API)
COPY nginx/ /etc/seqr/nginx-templates/

# Scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

# Supervisord
COPY supervisord.conf /etc/supervisor/conf.d/seqr.conf

EXPOSE 443 9090 9091

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/seqr.conf"]
```

---

## supervisord.conf

```ini
[supervisord]
nodaemon=true
logfile=/var/log/seqr/supervisord.log
logfile_maxbytes=10MB
pidfile=/var/run/supervisord.pid

[program:management-api]
command=uvicorn main:app --host 127.0.0.1 --port 9090
directory=/management-api
autostart=true
autorestart=true
stdout_logfile=/var/log/seqr/mgmt-api.log
stderr_logfile=/var/log/seqr/mgmt-api-error.log
priority=1

[program:nginx]
command=/usr/local/nginx/sbin/nginx -g "daemon off;"
autostart=false                         ; management API starts nginx after config generation
autorestart=true
stdout_logfile=/var/log/seqr/nginx-access.log
stderr_logfile=/var/log/seqr/nginx-error.log
priority=2

[program:nginx-config-generator]
command=python3 /management-api/startup.py   ; generates nginx.conf from gateway.yaml, starts nginx via supervisorctl
autostart=true
autorestart=false
startsecs=0
priority=0
```

---

## oqs-provider.conf (OpenSSL config)

```ini
# /opt/oqs-provider/oqs-provider.conf
# Loaded by OpenSSL via OPENSSL_CONF env var

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
module = /opt/oqs-provider/lib/oqsprovider.so
activate = 1
```

---

## HELM TEMPLATES (Core)

```yaml
# helm/seqr-gateway/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "seqr-gateway.fullname" . }}
  labels:
    {{- include "seqr-gateway.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "seqr-gateway.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "seqr-gateway.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: https
              containerPort: 443
              protocol: TCP
            - name: management
              containerPort: 9090
              protocol: TCP
            - name: metrics
              containerPort: 9091
              protocol: TCP
          env:
            - name: LICENSE_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "seqr-gateway.fullname" . }}-secret
                  key: licenseKey
          volumeMounts:
            - name: gateway-config
              mountPath: /etc/seqr/gateway.yaml
              subPath: gateway.yaml
            - name: tls-certs
              mountPath: /certs
              readOnly: true
            - name: logs
              mountPath: /var/log/seqr
          livenessProbe:
            httpGet:
              path: /health
              port: 9090
              host: 127.0.0.1
            initialDelaySeconds: 30
            periodSeconds: 10
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: gateway-config
          configMap:
            name: {{ include "seqr-gateway.fullname" . }}-config
        - name: tls-certs
          secret:
            secretName: {{ .Values.tls.secretName }}
        - name: logs
          emptyDir: {}
```

```yaml
# helm/seqr-gateway/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "seqr-gateway.fullname" . }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: 443
      targetPort: https
      protocol: TCP
      name: https
  selector:
    {{- include "seqr-gateway.selectorLabels" . | nindent 4 }}
```

```yaml
# helm/seqr-gateway/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "seqr-gateway.fullname" . }}-config
data:
  gateway.yaml: |
    {{- toYaml .Values.gateway.config | nindent 4 }}
```

---

## MUTUAL TLS (mTLS) CONFIG

```yaml
# In gateway.yaml — per-upstream service config for mTLS
upstream_services:
  - name: internal-payments-service
    listen_port: 9443
    upstream_url: https://payments-internal:8443
    upstream_tls: true
    upstream_tls_verify: true
    upstream_ca_cert: /certs/internal-ca.pem    # CA that signed internal service cert

    # mTLS: gateway presents its own cert to upstream
    mutual_tls:
      enabled: true
      client_cert: /certs/gateway-client.pem
      client_key: /certs/gateway-client-key.pem

    # Restrict: only allow clients with valid client certificates
    require_client_cert: true
    client_ca_cert: /certs/client-ca.pem
```

```nginx
# Generated NGINX block for mTLS upstream
server {
    listen 9443 ssl;

    ssl_certificate /certs/server-mldsa.pem;
    ssl_certificate_key /certs/server-mldsa-key.pem;
    ssl_client_certificate /certs/client-ca.pem;
    ssl_verify_client on;

    location / {
        proxy_pass https://payments-internal:8443;
        proxy_ssl_certificate /certs/gateway-client.pem;
        proxy_ssl_certificate_key /certs/gateway-client-key.pem;
        proxy_ssl_trusted_certificate /certs/internal-ca.pem;
        proxy_ssl_verify on;
        proxy_ssl_protocols TLSv1.3;
    }
}
```

---

## MANAGEMENT API requirements.txt

```txt
# management-api/requirements.txt
fastapi==0.115.0
uvicorn==0.30.6
pydantic==2.9.2
pydantic-settings==2.5.2
pyyaml==6.0.2
jinja2==3.1.4          # for rendering nginx.conf template
httpx==0.27.2          # for upstream health checks
prometheus-client==0.21.0
```

