# Migrating SeQr backend + DB to Oracle Cloud Always Free (Mumbai)

**Goal:** move the backend, Postgres, and Redis off **Render Singapore** onto one
**Oracle Ampere A1 Always-Free VM in Mumbai (`ap-mumbai-1`)**. Frontend stays on Vercel.

**Why this move (fixes 3 things at once):**
- **Data residency** — DB + compute now in India. Kills the "sell sovereignty, host in Singapore" contradiction (`docs/12` §4.1).
- **No 30-day deletion** — Postgres runs on a persistent block volume we own, not Render's free PG.
- **No cold-start** — the VM is always on (Render free slept after 15 min, ~50s wake).
- **Cost ₹0** — Always Free tier, indefinitely.

**Spec you get free:** 1× Ampere A1 = up to **4 OCPU / 24 GB RAM**, 200 GB block storage, 1 public IP.
Massive overkill for this stack — headroom for the async worker later.

> ⚠ **Capacity caveat (the one real gotcha):** Always-Free A1 in Indian regions is often
> "Out of capacity." If instance-create fails, retry (different AD, or off-peak), or use the
> capacity-retry trick in §2.4. Do **not** switch to AMD Micro (1 GB RAM) — too small for this stack.

---

## 0. What you do vs what's automated
- **You (account + provisioning, browser):** create the Oracle account, launch the VM, add DNS records. Account creation and any card-on-file step are yours — I don't do those.
- **Automated (scripts in this folder):** Docker install + firewall (`bootstrap.sh`), the whole stack (`docker-compose.oracle.yml` + `Caddyfile`), nightly backups (`backup.sh`).

---

## 1. Oracle account (you, ~10 min)
1. cloud.oracle.com → **Sign up**. Pick **Home Region = India South (Mumbai)** — this is permanent, get it right.
2. Card is asked for identity verification; Always-Free resources don't charge. Stay on the "Always Free" resources only.

## 2. Launch the VM (you, ~10 min)
1. Console → **Compute → Instances → Create instance**.
2. **Image:** Canonical **Ubuntu 22.04** (ARM-compatible). **Shape:** change to **Ampere / VM.Standard.A1.Flex**, set **4 OCPU / 24 GB** (all still Always Free).
3. **Networking:** create/keep a VCN with a public subnet, **Assign a public IPv4**.
4. **SSH keys:** upload your public key (or let it generate — save the private key). You'll SSH as user `ubuntu`.
5. Create. Note the **public IP**.

### 2.4 If "Out of host capacity"
Retry Create every few minutes, or switch **Availability Domain** in the form. Off-peak (late night IST) has better luck. Some people script the retry; a manual retry loop is usually enough within a day.

## 3. Open ports in the cloud firewall (you, ~3 min)
Console → **Networking → VCN → your subnet → Security List → Add Ingress Rules**:
- Source `0.0.0.0/0`, TCP **80**
- Source `0.0.0.0/0`, TCP **443**
(22 is open by default. `bootstrap.sh` opens 80/443 at the OS-firewall layer too — Oracle Ubuntu blocks them there as well.)

## 4. Provision the box (automated, ~8 min)
SSH in and run bootstrap:
```bash
ssh ubuntu@<PUBLIC_IP>
git clone https://github.com/LochanPS/SeQr-Labs.git
cd SeQr-Labs
bash deploy/oracle/bootstrap.sh
# log out + back in so the docker group applies
exit
ssh ubuntu@<PUBLIC_IP>
cd SeQr-Labs
```

## 5. Point DNS (you, ~2 min + propagation)
At your `seqrlabs.com` registrar, add an **A record**:
- `api.seqrlabs.com` → `<PUBLIC_IP>`
Wait until `dig api.seqrlabs.com` returns the IP before starting Caddy (it needs DNS to issue the TLS cert).

## 6. Configure + launch the stack (automated, ~8 min first build)
```bash
cp deploy/oracle/.env.oracle.example deploy/oracle/.env
# generate secrets:
echo "SECRET_KEY=$(openssl rand -hex 32)"   # paste into .env
echo "DB_PASSWORD=$(openssl rand -hex 24)"  # paste into .env
nano deploy/oracle/.env                      # set FRONTEND_URL + OPERATOR_EMAILS too

# --env-file makes ${DB_PASSWORD} substitution in the compose file resolve.
docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml up -d --build
docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml logs -f backend
```
Verify:
```bash
curl https://api.seqrlabs.com/api/v1/health   # -> {"status":"ok"}
```
`SEED_DEMO_ON_BOOT=true` seeds `demo@seqrlabs.com / demodemo123` on first boot.

## 7. Nightly backups (automated — self-hosting means you own these now)
```bash
chmod +x deploy/oracle/backup.sh
( crontab -l 2>/dev/null; echo "30 19 * * * /home/ubuntu/SeQr-Labs/deploy/oracle/backup.sh >> /home/ubuntu/backup.log 2>&1" ) | crontab -
```
(19:30 UTC = 01:00 IST daily; keeps 14 gzip dumps in `~/seqr-backups`.) Restore:
`gunzip -c seqr_YYYYMMDD.sql.gz | docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml exec -T db psql -U seqr seqr`

## 8. Repoint the frontend (you, ~3 min)
Vercel → project → Environment → set `NEXT_PUBLIC_API_URL=https://api.seqrlabs.com/api/v1` → **redeploy**
(it's build-time). Confirm login → posture → graph on `www.seqrlabs.com`.

## 9. Decommission Render (you, after 24–48 h of the new box being green)
Keep Render running until Oracle is verified in real Chrome. Then Render → suspend/delete
`seqr-backend` + `seqr-db`. Upstash Redis is no longer used (local Redis replaces it) — delete it too.

---

## Cutover checklist
- [ ] Oracle A1 VM up in Mumbai, public IP noted
- [ ] Ingress 80/443 open (cloud security list) + `bootstrap.sh` ran (host firewall)
- [ ] `api.seqrlabs.com` A record resolves to the IP
- [ ] `docker compose ... up -d --build` green; `/api/v1/health` → ok over HTTPS
- [ ] Demo login + graph verified in real Chrome (not just the embed browser)
- [ ] `NEXT_PUBLIC_API_URL` repointed on Vercel + redeployed; www.seqrlabs.com works
- [ ] Nightly backup cron installed, first dump present in `~/seqr-backups`
- [ ] Render + Upstash decommissioned

## Later (when revenue / scale)
- Uncomment the `worker` service in `docker-compose.oracle.yml`, set `CELERY_ALWAYS_EAGER=false` → async scans + live WS progress. The 24 GB box has room.
- Off-box backups: `rsync` the dumps to Oracle Object Storage (10 GB Always Free) or a second region.
