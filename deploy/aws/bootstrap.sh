#!/usr/bin/env bash
# One-time setup for the SeQr PRODUCTION stack on AWS EC2 (Ubuntu 24.04, arm64 / t4g).
# Run as the default 'ubuntu' user after SSHing into a fresh instance:
#   git clone https://github.com/LochanPS/SeQr-Labs.git && cd SeQr-Labs
#   bash deploy/aws/bootstrap.sh
# Then log out/in (docker group) and run the compose up line it prints.
set -euo pipefail

echo "==> [1/3] Adding swap (t4g.medium = 4GB; the backend/frontend image builds need headroom)"
# liboqs + OpenSSL 3.5 + the Next.js build can OOM a 4GB box during `up --build`.
# 4GB swap makes the first build reliable; it's harmless once images are built.
if ! swapon --show | grep -q '/swapfile'; then
  sudo fallocate -l 4G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=4096
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
  echo "    4GB swap enabled"
else
  echo "    swap already present, skipping"
fi

echo "==> [2/3] Installing Docker Engine + compose plugin"
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl git openssl
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker "$USER"
  echo "    docker installed"
else
  echo "    docker already installed, skipping"
fi

# NOTE: AWS security groups handle inbound firewalling — no host iptables rules needed
# (unlike Oracle images). Ensure the SG allows inbound 22, 80, 443.

echo
echo "==> [3/3] Next steps:"
echo "    cp deploy/aws/.env.aws.example deploy/aws/.env"
echo "    echo \"SECRET_KEY=\$(openssl rand -hex 32)\"    # paste into .env"
echo "    echo \"DB_PASSWORD=\$(openssl rand -hex 24)\"   # paste into .env"
echo "    nano deploy/aws/.env                            # verify FRONTEND_URL + NEXT_PUBLIC_* + OPERATOR_EMAILS"
echo
echo "    # (log out/in first so the docker group applies, then:)"
echo "    docker compose -f deploy/aws/docker-compose.prod.yml --env-file deploy/aws/.env up -d --build"
echo
echo "    # Point DNS (api/www/apex -> this box's Elastic IP) BEFORE Caddy can issue TLS."
