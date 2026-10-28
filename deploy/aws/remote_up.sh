#!/usr/bin/env bash
# Runs ON the fresh EC2 Ubuntu box. Installs Docker, writes demo .env, brings the
# stack up on :8000. Idempotent-ish; safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root (script lives in deploy/aws/)

echo "==> [1/3] Installing Docker Engine + compose plugin"
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl git openssl
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

echo "==> [2/3] Writing demo env (deploy/oracle/.env) if absent"
ENV_FILE=deploy/oracle/.env
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 24)
FRONTEND_URL=http://localhost:3000,http://127.0.0.1:3000
OPERATOR_EMAILS=pokkalilochan@gmail.com
SEED_DEMO_ON_BOOT=true
ALLOW_DEMO_RESEED=true
EOF
  echo "    wrote $ENV_FILE"
else
  echo "    $ENV_FILE exists, keeping it"
fi

echo "==> [3/3] Building + starting stack (this builds the backend image, ~5-10 min first time)"
sudo docker compose --env-file "$ENV_FILE" -f deploy/aws/docker-compose.demo.yml up -d --build

echo
echo "==> Up. Containers:"
sudo docker compose --env-file "$ENV_FILE" -f deploy/aws/docker-compose.demo.yml ps
echo "==> Backend health (may need ~30s for migrations to finish):"
sleep 5
curl -fsS http://localhost:8000/api/v1/health || echo "    (not ready yet — check: sudo docker compose -f deploy/aws/docker-compose.demo.yml logs backend)"
