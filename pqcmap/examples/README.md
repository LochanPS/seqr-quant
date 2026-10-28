# pqcmap examples

Runnable, self-contained demos of the framework drop-ins. These are **not** shipped in
the wheel — they live here as copy-paste starting points.

| Example | What it shows |
|---|---|
| [`worked_migration/`](worked_migration/) | **Start here.** Full loop: `seqr scan code` finds vulns → fix with pqcmap → re-scan clean. |
| [`cookbook_recipes.py`](cookbook_recipes.py) | Every before→after recipe in [`../docs/COOKBOOK.md`](../docs/COOKBOOK.md), executed for real. |
| [`fastapi_auth.py`](fastapi_auth.py) | A FastAPI service issuing + verifying ML-DSA JWTs. |
| [`tls_client.py`](tls_client.py) | PQC-hybrid TLS capability report + optional fetch. |

## `worked_migration/` — find it, fix it, prove it clean

The end-to-end migration story on a small auth service. See
[`worked_migration/README.md`](worked_migration/README.md) for the captured output.

```bash
pip install seqr pqcmap
python examples/worked_migration/run_migration.py
```

## `cookbook_recipes.py` — every cookbook recipe, run for real

```bash
python examples/cookbook_recipes.py
```

## `fastapi_auth.py` — ML-DSA JWT auth

A FastAPI service where `POST /login` mints an ML-DSA-signed JWT and a dependency on
`GET /me` verifies it. The only crypto change from a stock PyJWT app is the import
(`import pqcmap.jwt as jwt`) and the key type.

```bash
pip install fastapi uvicorn
python -m uvicorn examples.fastapi_auth:app --reload

# then, in another shell:
curl -s -XPOST localhost:8000/login \
     -H 'content-type: application/json' \
     -d '{"username":"alice","password":"password"}'
curl -s localhost:8000/me -H "authorization: Bearer <token-from-login>"
```

## `tls_client.py` — PQC-hybrid TLS capability report + fetch

Prints what PQC-hybrid TLS this machine can actually do, and optionally fetches a URL
over the pqcmap TLS context.

```bash
python -m examples.tls_client                        # capability report only
python -m examples.tls_client https://example.com    # fetch over the pqcmap context
```

> **MTU caveat:** an ML-KEM ClientHello (~1.2 KB) fragments across packets. Mainstream
> stacks cope; test a real handshake against your endpoints before production rollout.
