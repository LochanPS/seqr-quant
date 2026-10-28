# SeQr laptop bridge — live backend at ₹0, no card, no cloud host

A stop-gap for while the Oracle Always-Free VM is blocked on card verification. Runs the
**full production stack** on your machine and exposes it to the internet through a free
**Cloudflare Tunnel**. You get a real `https://api.seqrlabs.com` for customer-discovery
demos today; switch to Oracle later for always-on.

**What this is / isn't**
- ✅ Same backend image, same `alembic upgrade head`, same Postgres/Redis as Oracle — a true preview.
- ✅ ₹0, no credit card, data stays on your machine in India (residency satisfied).
- ⚠ Only reachable while your machine is awake **and** the tunnel is running. Fine for scheduled demos; not for 24/7. Oracle is still the endgame.

---

## Prerequisites (one time)
- **Docker Desktop** (Windows/Mac) — https://www.docker.com/products/docker-desktop/ . No card.
- **cloudflared** — Cloudflare's tunnel client. No card.
  - Windows: `winget install --id Cloudflare.cloudflared`
  - Mac: `brew install cloudflared`
  - Linux: https://pkg.cloudflare.com/

---

## 1. Start the stack (from the repo root)
```bash
cp deploy/local/.env.local.example deploy/local/.env
# set a real SECRET_KEY (ENVIRONMENT=production refuses the dev value):
openssl rand -hex 32          # paste into deploy/local/.env as SECRET_KEY
nano deploy/local/.env        # also confirm FRONTEND_URL + OPERATOR_EMAILS

docker compose -f docker-compose.local.yml up -d --build
docker compose -f docker-compose.local.yml logs -f backend   # watch "alembic upgrade head" + startup
```
Confirm it's healthy locally:
```bash
curl http://localhost:8000/api/v1/health      # -> {"status":"ok"}
```
First boot seeds `demo@seqrlabs.com / demodemo123` (`SEED_DEMO_ON_BOOT=true`).

---

## 2A. Quick tunnel — one-off test (no account, random URL)
Fastest way to prove it works from the outside. The URL changes every run.
```bash
cloudflared tunnel --url http://localhost:8000
```
It prints a `https://<random>.trycloudflare.com` URL. Test:
```bash
curl https://<random>.trycloudflare.com/api/v1/health
```
Good for a smoke test or a quick share. For a stable demo URL, use 2B.

## 2B. Named tunnel — stable `api.seqrlabs.com` (free Cloudflare account, still no card)
Do this once; afterwards `www.seqrlabs.com` can point at it unchanged.

1. Create a free Cloudflare account and add the `seqrlabs.com` zone (Cloudflare becomes your
   DNS — you'll repoint the domain's nameservers at Cloudflare per their wizard). No card.
2. Authenticate + create the tunnel:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create seqr-bridge
   cloudflared tunnel route dns seqr-bridge api.seqrlabs.com
   ```
3. Write `~/.cloudflared/config.yml` (the `create` step prints the tunnel UUID + credentials path):
   ```yaml
   tunnel: <TUNNEL_UUID>
   credentials-file: /home/<you>/.cloudflared/<TUNNEL_UUID>.json
   ingress:
     - hostname: api.seqrlabs.com
       service: http://localhost:8000
     - service: http_404
   ```
4. Run it (keep this process up while demoing):
   ```bash
   cloudflared tunnel run seqr-bridge
   ```
   To keep it alive as a background service: `cloudflared service install` (Win/Mac/Linux).
5. Verify over the real hostname:
   ```bash
   curl https://api.seqrlabs.com/api/v1/health
   ```

---

## 3. Point the frontend at it
Vercel → project → Settings → Environment → `NEXT_PUBLIC_API_URL=https://api.seqrlabs.com/api/v1`
→ **redeploy** (build-time var). Then log in on `www.seqrlabs.com` in real Chrome and confirm
dashboard + graph load. (Quick-tunnel URLs change each run, so only wire the frontend to the
**named** tunnel.)

---

## CI-4 hosted GitHub App on the bridge (optional)
The webhook works over the tunnel like any other route. To try zero-config PR scanning:
1. Register the App (see `docs/GITHUB_APP_OPERATIONS.md` §1), webhook URL
   `https://api.seqrlabs.com/api/v1/github/webhook`.
2. Fill the `GITHUB_APP_*` block in `deploy/local/.env`, set `GITHUB_APP_ENABLED=true`, restart backend.
3. Link an install to your org:
   ```bash
   docker compose -f docker-compose.local.yml exec backend \
     python -m app.github_app.link set --installation-id <N> --org-email you@org.com
   ```
Note: the App only reacts while the bridge + tunnel are running — a PR opened while your
laptop is off gets scanned when GitHub retries or on the next `synchronize`.

---

## Stop / clean up
```bash
docker compose -f docker-compose.local.yml down          # stop (keeps data volumes)
docker compose -f docker-compose.local.yml down -v       # stop + wipe db/redis volumes
```
Ctrl-C the `cloudflared` process (or `cloudflared service uninstall`).

## When Oracle unblocks
Follow `deploy/oracle/DEPLOY_ORACLE.md`. Migrate data with the same dump `backup.sh` makes:
```bash
docker compose -f docker-compose.local.yml exec -T db pg_dump -U seqr seqr | gzip > seqr_bridge.sql.gz
# ...restore into the Oracle db per DEPLOY_ORACLE.md §7.
```
