# Deploying the SeQr backend + frontend (free tier)

Goal: live sign-in / dashboard / blog. Stack: **Render** (backend, free) + **Render
Postgres** (free) + **Upstash Redis** (free) + **Vercel** (frontend, free). Total cost: ₹0.

The code is already deploy-ready: scanner installs from source in `Dockerfile.render`,
`asyncpg` added, migrations cover all tables, and `CELERY_ALWAYS_EAGER` lets one web
service run scans without a paid worker.

> Free-tier caveats (fine for demos / first customers):
> - Render free web service **sleeps after ~15 min idle**; first request after sleep takes ~50 s.
> - Render **free Postgres is deleted after 30 days** — when you have revenue, upgrade
>   ($7/mo) or move to Neon. Until then, re-create it if it lapses.
> - Scans run **inline** (eager), so triggering a fresh scan blocks ~30–60 s. Pre-run
>   scans load instantly. Add a paid worker later and set `CELERY_ALWAYS_EAGER=false`.

---

## 1. Redis — Upstash (2 min)
1. console.upstash.com → sign in with GitHub → **Create Database** (Redis), region Singapore.
2. Copy the connection string that starts `rediss://...` (TLS). Keep it for step 3.

## 2. Backend + Postgres — Render (10 min)
1. dashboard.render.com → sign in with GitHub → grant access to the `SeQr-Labs` repo.
2. **New + → Blueprint** → pick `LochanPS/SeQr-Labs`. Render reads `render.yaml`
   (at the repo root) and proposes **seqr-backend** (web) + **seqr-db** (Postgres).
   Click **Apply**. The first Docker build takes ~5–8 min.
3. Open **seqr-db** → copy its **Internal Database URL** (looks like
   `postgresql://seqr:...@dpg-xxxx/seqr`). Change the scheme to `postgresql+asyncpg://`
   (i.e. `postgresql+asyncpg://seqr:...@dpg-xxxx/seqr`).
   *(Internal URL has no SSL params, so the same string works for both the async and sync
   engines — don't use the External URL here.)*
4. Open **seqr-backend → Environment** and fill the `sync:false` secrets:
   - `DATABASE_URL` = the `postgresql+asyncpg://...` from step 3
   - `REDIS_URL` = the `rediss://...` from Upstash (step 1)
   - `OPERATOR_EMAILS` = your email (e.g. `you@gmail.com`) — gives you admin-console access
   - `FRONTEND_URL` = leave a placeholder for now; set it in step 4 once Vercel is live
   (`SECRET_KEY` is auto-generated; `ENVIRONMENT`, `DEPLOYMENT_MODE=saas`,
   `USE_FAKE_REDIS=false`, `CELERY_ALWAYS_EAGER=true` come from the blueprint.)
5. **Manual Deploy → Deploy latest commit.** When live, check
   `https://seqr-backend-xxxx.onrender.com/api/v1/health` → `{"status":"ok"}`.
   Note this base URL.

## 3. Frontend — Vercel (5 min)
1. vercel.com → New Project → import `SeQr-Labs` → **Root Directory: `audit/frontend`**.
2. Environment Variable: `NEXT_PUBLIC_API_URL` =
   `https://seqr-backend-xxxx.onrender.com/api/v1` (your Render base URL + `/api/v1`).
3. Deploy. Note the Vercel URL (e.g. `https://seqr-labs.vercel.app`).

## 4. Wire CORS (1 min)
Back in Render → seqr-backend → Environment → set `FRONTEND_URL` = your Vercel URL
(no trailing slash). Save → it redeploys. Sign-in will now work (CORS was the
"Failed to fetch").

## 5. Create your operator account
1. On the live site → Register (creates your org + user).
2. Because your email is in `OPERATOR_EMAILS`, you get the admin console at `/admin`
   (orgs, plans, suspend) and `/admin/blog` (CMS).

## 6. Verify (smoke test)
- Register → log in → add an asset → run a scan (allow ~30–60 s, eager) → view CBOM →
  download PDF report → open `/admin`. If all work, the platform is live.

---

## Custom domain (later, when you buy seqrlabs.com)
- Vercel: Project → Domains → add `app.seqrlabs.com` → set the CNAME at your registrar.
- Render: seqr-backend → Settings → Custom Domain → `api.seqrlabs.com` → CNAME.
- Then update `NEXT_PUBLIC_API_URL` → `https://api.seqrlabs.com/api/v1` and
  `FRONTEND_URL` → `https://app.seqrlabs.com`.

## Upgrade path (when paying customers arrive)
1. Render Postgres → paid ($7/mo, persistent + backups), or move to Neon.
2. Add a **Background Worker** service (celery_worker.Dockerfile) and set
   `CELERY_ALWAYS_EAGER=false` → scans run async with live WebSocket progress.
3. Render web service → paid plan to stop idle-sleep.
