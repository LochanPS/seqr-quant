# Deploying the whole SeQr product on one AWS EC2 box (ap-south-1 / Mumbai)

**Goal:** run the entire product — API, async scan worker, Postgres, Redis, the Next.js
frontend, and the public "Try It Live" demo — on **one Graviton EC2 instance** in
**ap-south-1 (Mumbai)**, fronted by Caddy for automatic HTTPS on `www.seqrlabs.com` and
`api.seqrlabs.com`. Everything on-box, one bill, no managed RDS/ElastiCache/ALB/NAT — to
stay inside the free AWS credits.

**Why AWS Mumbai (replaces the Oracle plan):** ap-south-1 keeps data at rest in India, so it
satisfies the same CERT-In / DPDP residency requirement the Oracle move was for — without
Oracle's Always-Free capacity lottery. The Oracle path (`deploy/oracle/`) is now retired.

**Region is mandatory:** `ap-south-1` only. Data residency (see `CLAUDE.md` → Indian sovereign cloud).

---

## 0. What you do vs. what's automated
- **You (browser + account):** create/keep the AWS account, launch the instance, allocate the
  Elastic IP, set the security group, add DNS records. Account creation, billing, and any
  card-on-file step are yours — I can't create accounts or enter payment.
- **Automated (scripts in this folder):** swap + Docker install (`bootstrap.sh`), the whole
  stack (`docker-compose.prod.yml` + `Caddyfile`), nightly backups (`deploy/backup/pg_backup.sh`).

---

## 1. Launch the instance (you, ~10 min)
1. EC2 → **Launch instance**, Region **Asia Pacific (Mumbai) ap-south-1**.
2. **AMI:** Ubuntu Server 24.04 LTS, **arm64**.
3. **Type:** **t4g.medium** (2 vCPU / 4 GB, Graviton). *(t4g.large if you want zero build-RAM worry.)*
4. **Key pair:** create/select one; save the `.pem` — you SSH as user `ubuntu`.
5. **Storage:** 30 GB **gp3**.
6. **Network:** default VPC, a **public subnet**, **Auto-assign public IP = Enable** (temporary; the Elastic IP replaces it).
7. Launch.

## 2. Elastic IP — a stable address (you, ~2 min)
EC2 → **Elastic IPs → Allocate** → **Associate** to the instance.
(Free while associated with a running instance.) Note this IP — DNS points at it.

## 3. Security group — inbound only (you, ~3 min)
Allow inbound:
- TCP **22** from **your IP only** (SSH; not `0.0.0.0/0`).
- TCP **80** from `0.0.0.0/0` (HTTP → Caddy; needed for the Let's Encrypt challenge + redirect).
- TCP **443** from `0.0.0.0/0` (HTTPS).

Outbound: leave default (all). No NAT gateway — the box has a public IP.

## 4. Provision the box (automated, ~5 min)
```bash
ssh -i your-key.pem ubuntu@<ELASTIC_IP>
git clone https://github.com/LochanPS/SeQr-Labs.git && cd SeQr-Labs
bash deploy/aws/bootstrap.sh          # adds 4GB swap + installs Docker
exit                                   # log out/in so the docker group applies
ssh -i your-key.pem ubuntu@<ELASTIC_IP>
cd SeQr-Labs
```

## 5. Configure secrets (you on the box, ~3 min)
```bash
cp deploy/aws/.env.aws.example deploy/aws/.env
echo "SECRET_KEY=$(openssl rand -hex 32)"    # paste into .env
echo "DB_PASSWORD=$(openssl rand -hex 24)"   # paste into .env
nano deploy/aws/.env
```
Confirm in `.env`: `FRONTEND_URL=https://www.seqrlabs.com`, the two `NEXT_PUBLIC_*` URLs,
and `OPERATOR_EMAILS`. Production **refuses to boot** with a localhost `FRONTEND_URL` or the
default `SECRET_KEY` (that's `validate_production()` doing its job).

## 6. Point DNS (you, ~2 min + propagation) — BEFORE bringing Caddy up
At the `seqrlabs.com` registrar, add **A records** → the Elastic IP:
- `api.seqrlabs.com`  → `<ELASTIC_IP>`
- `www.seqrlabs.com`  → `<ELASTIC_IP>`
- `seqrlabs.com` (apex) → `<ELASTIC_IP>`  *(some registrars use `@`; use ALIAS/ANAME if apex A isn't allowed)*

Wait until all three resolve before the next step — Caddy needs DNS live to issue TLS:
```bash
dig +short api.seqrlabs.com www.seqrlabs.com seqrlabs.com
```

## 7. Build + launch the stack (automated, ~10–15 min first build)
```bash
docker compose -f deploy/aws/docker-compose.prod.yml --env-file deploy/aws/.env up -d --build
docker compose -f deploy/aws/docker-compose.prod.yml --env-file deploy/aws/.env ps
docker compose -f deploy/aws/docker-compose.prod.yml --env-file deploy/aws/.env logs -f backend
```
(First build compiles liboqs/OpenSSL and builds Next.js — the swap from `bootstrap.sh` covers the RAM spike.)

## 8. Verify (you, ~5 min)
```bash
curl -fsS https://api.seqrlabs.com/api/v1/health         # -> {"status":"ok"}
```
Then in **real Chrome** (not the embed browser):
- `https://www.seqrlabs.com` loads, dark/light works.
- Log in `demo@seqrlabs.com / demodemo123` (seeded by `SEED_DEMO_ON_BOOT=true`).
- Run a scan → live WS progress advances (proves the async worker + `wss://api...` path).
- CBOM + graph render; PDF report downloads.
- Public **"Try It Live"** on the landing page returns a CycloneDX 1.6 CBOM. *(This is task #2 — it ships as part of this same stack, no separate host.)*

## 9. Nightly backups (automated — self-hosting means you own these)
```bash
# optional off-box copies: create an S3 bucket in ap-south-1 and set BACKUP_S3_URI in .env
chmod +x deploy/backup/pg_backup.sh
( crontab -l 2>/dev/null; echo "30 19 * * * cd /home/ubuntu/SeQr-Labs && DATABASE_URL=postgresql://seqr:\$DB_PASSWORD@localhost:5432/seqr deploy/backup/pg_backup.sh >> /home/ubuntu/backup.log 2>&1" ) | crontab -
```
(19:30 UTC = 01:00 IST daily; keeps 14 gzip custom-format dumps + SHA-256. Restore drill: `deploy/backup/pg_restore.sh --verify`.)
Simplest path is to exec `pg_dump` inside the `db` container; see `deploy/backup/README.md`.

## 10. Decommission the old hosting (you, after 24–48 h green)
Once Chrome-verified and stable: delete the Render `seqr-backend` + `seqr-db`, the Upstash
Redis, and any Vercel frontend project (the frontend now lives on this box). Cancel the Oracle
plan if a VM was ever created.

---

## A4 — Bedrock AgentCore (deploy after the box is live)
The migration-analyst agent (`audit/agentcore/`, Haiku 4.5, 4 tools over the live APIs) deploys
separately via `audit/agentcore/deploy/deploy.py`. It's serverless + pay-per-call, so it doesn't
add to the always-on box cost.

**Residency gate — confirm first:** verify **Bedrock AgentCore + Claude Haiku 4.5 are available
in ap-south-1**. If they are not, running the agent in another region (e.g. us-east-1) would send
migration-analysis data out of India and break the residency pitch — in that case **defer A4**
rather than compromise residency. Do not deploy the agent outside ap-south-1.

---

## Credit-lean notes
- **One box, all containers.** No RDS/ElastiCache (Postgres + Redis are containers on the EBS volume).
- **No ALB, no NAT gateway** (each is ~$16–32/mo of pure overhead) — Caddy on the box does TLS; the public IP replaces NAT.
- **Graviton (t4g)** is the cheapest per-perf family. Worker concurrency is capped at 2 for the 4 GB box.
- **Elastic IP** is free while attached. **DNS at the registrar** avoids a Route 53 hosted-zone charge.
- **S3** backups cost pennies. Est. all-in: ~$27/mo on t4g.medium.

## Cutover checklist
- [ ] t4g.medium (arm64) up in ap-south-1; Elastic IP associated
- [ ] SG: 22 (your IP), 80, 443 (world) inbound
- [ ] `bootstrap.sh` ran (swap + Docker); logged out/in
- [ ] `deploy/aws/.env` filled; strong `SECRET_KEY` + `DB_PASSWORD`; `FRONTEND_URL=https://www.seqrlabs.com`
- [ ] `api` + `www` + apex A records resolve to the Elastic IP
- [ ] `docker compose ... up -d --build` green; `/api/v1/health` ok over HTTPS
- [ ] Chrome: login → scan (live WS) → CBOM/graph → PDF; "Try It Live" returns a CBOM
- [ ] Nightly backup cron installed; first dump present
- [ ] Old Render + Upstash + Vercel decommissioned
- [ ] A4 AgentCore: ap-south-1 availability confirmed, then deployed (or deferred)
