# seqr-scan-demo

Standalone FastAPI service that powers the "try it live" custom-domain scan on the
landing page. Wraps the real `NetworkScanner` from `shared-scanner/` with rate
limiting (5 req/IP/hour) and SSRF protection. No auth, no Postgres, no Celery —
intentionally separate from `audit/backend`.

## Deploy on Render (manual — most reliable path)

1. New → Web Service → connect the `SeQr-Labs` GitHub repo.
2. **Root Directory**: leave blank (repo root) — the Dockerfile needs `shared-scanner/`
   as a sibling, so the build context must be the repo root, not this folder.
3. **Runtime**: Docker.
4. **Dockerfile Path**: `scan-demo-service/Dockerfile`
5. **Region**: Singapore (closest to India, lowest latency for ap-south-1-adjacent demo).
6. **Plan**: Starter (free tier cold-starts ~30s, which the TryItLive loading
   animation can absorb, but Starter avoids cold-start during a live demo).
7. Env var: `FRONTEND_ORIGINS=https://seqrlabs.com,https://www.seqrlabs.com` (add your
   actual Vercel domain(s), comma-separated, no spaces).
8. Health check path: `/health`.
9. Deploy. Note the resulting URL, e.g. `https://seqr-scan-demo.onrender.com`.

Alternatively, `render.yaml` in this folder is a Blueprint you can point Render at
directly (New → Blueprint), though the manual path above is less likely to hit
Render schema-version drift.

## Wire it to the frontend

On Vercel, set:

```
BACKEND_URL=https://seqr-scan-demo.onrender.com
```

`src/app/api/scan/route.ts` already proxies to `${BACKEND_URL}/api/v1/public/scan` —
no frontend code change needed once this env var points at the deployed service.

## Local test

```
cd seqr-labs
pip install -e shared-scanner[code]
pip install -r scan-demo-service/requirements.txt
uvicorn main:app --app-dir scan-demo-service --reload --port 8000
curl -X POST localhost:8000/api/v1/public/scan -H "Content-Type: application/json" -d '{"domain":"razorpay.com"}'
```
