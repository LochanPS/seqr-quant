# SeQr Discovery Agent

Read-only, plugin-driven inventory of **internal** cryptography the external scanner cannot see
(cert stores, TLS listeners on reverse proxies / load balancers, HSM slots). It pushes
Ed25519-signed observations into the SeQr spine — live over HTTPS, or as a signed air-gap file
with zero network egress. Implements PRD `docs/15_Discovery_Agent_Design.md`. **It never changes
customer infrastructure** (migration stays bundle + runbook) and **never extracts private keys**.

## Layout

```
deploy/agent/
  seqr_agent/
    config.py        # JSON/YAML config loader (+ env overrides for secrets)
    signing.py       # Ed25519 key mgmt + canonical signing (mirrors app/spine/agent_sig.py)
    observation.py   # AssetObservation → platform AgentObservationIn shape
    uploader.py      # connected POST /agent/observations + air-gap envelope build/verify
    runtime.py       # load config → run plugins → deliver
    cli.py           # seqr-agent {run,collect,export,verify}
    plugins/
      base.py        # SourcePlugin contract
      tls_probe.py   # live TLS endpoint probe (cert + kex)
      cert_store.py  # filesystem PEM/DER + OS trust store
      proxy_conf.py  # NGINX / HAProxy TLS config parse (+ referenced certs)
      pkcs11.py      # HSM slot/mechanism inventory (public objects only)
  agent.example.yaml # copy → agent.yaml
  Dockerfile         # slim runtime image
  seqr-agent.spec    # PyInstaller single-binary build
  discovery_agent.py # back-compat env-driven TLS-only entrypoint
  tests/
```

## Plugins

| key          | source                                    | emits (`location_type`) |
|--------------|-------------------------------------------|-------------------------|
| `tls`        | live TLS handshake to configured targets  | `tls_cert`, `tls_kex`   |
| `cert_store` | cert files on disk + OS trust store       | `cert_store`            |
| `proxy_conf` | NGINX/HAProxy configs (regex, read-only)  | `tls_config`, `cert_store` |
| `pkcs11`     | HSM over PKCS#11 (needs PyKCS11 + module)  | `hsm_key`, `hsm_token`  |

Each plugin is skipped cleanly when unavailable (no targets, missing lib), and a failing plugin
never aborts the run.

## Run — connected

```bash
export AGENT_KEY=sq_live_xxxxxxxx        # agent-scoped credential (never in the config file)
python -m seqr_agent.cli run --config agent.yaml
```

First run enrols the agent's public key trust-on-first-use; every later batch is signature-verified
server-side. Idempotent — safe to retry/resume.

## Run — air-gapped (zero egress)

Set `mode: airgap` in the config, then:

```bash
python -m seqr_agent.cli export --config agent.yaml     # writes seqr-agent-export.json (signed)
python -m seqr_agent.cli verify --config agent.yaml -e seqr-agent-export.json   # self-check → VALID
```

Transfer the file across the gap. An org admin uploads it to `POST /api/v1/agent/import`; the
platform verifies the signature against the enrolled key before ingest. The one-time key
enrolment (PEM) is printed by `export`.

## Dry run

```bash
python -m seqr_agent.cli collect --config agent.yaml    # prints observations as JSON, delivers nothing
```

## Packaging (Slice 3)

**Docker** (recommended):

```bash
docker build -t seqrlabs/seqr-agent:0.1.0 deploy/agent
docker run --rm -e AGENT_KEY=sq_live_xxx \
  -v $PWD/agent.yaml:/etc/seqr/agent.yaml:ro \
  -v seqr-agent-state:/var/lib/seqr \
  seqrlabs/seqr-agent:0.1.0 run --config /etc/seqr/agent.yaml
```

**Single binary** (PyInstaller):

```bash
pip install pyinstaller && pyinstaller --clean --noconfirm seqr-agent.spec
dist/seqr-agent run --config agent.yaml
```

## Security

- Read-only everywhere; PKCS#11 inventory only, **no key extraction**.
- Every batch Ed25519-signed; the private key lives in `AGENT_KEYFILE` (0600), never in config.
- Secrets come from `AGENT_KEY`, not the config file.
- Air-gap mode makes zero network calls.

## Tests

```bash
cd deploy/agent && python -m pytest tests/ -q
```

Covers each collector, config loading, signing, and an air-gap round-trip verified against the
**platform's own** `agent_sig` verifier (the exact `/agent/import` check) so both sides stay
byte-compatible.
