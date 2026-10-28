#!/usr/bin/env bash
# One-time VM setup for the SeQr stack on Oracle Cloud Always Free (Ubuntu 22.04 ARM).
# Run as the default 'ubuntu' user AFTER SSHing into the fresh instance:
#   curl -fsSL <raw-url>/bootstrap.sh | bash     # or scp + bash bootstrap.sh
set -euo pipefail

echo "==> Installing Docker Engine + compose plugin"
sudo apt-get update
sudo apt-get install -y ca-certificates curl git ufw
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

echo "==> Opening HTTP/HTTPS on the host firewall (Oracle images ship with iptables locked down)"
# Ubuntu on Oracle blocks 80/443 at the OS level even after the cloud security list is open.
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save || (sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save)

echo
echo "==> Done. Log out and back in (so docker group applies), then:"
echo "    git clone https://github.com/LochanPS/SeQr-Labs.git && cd SeQr-Labs"
echo "    cp deploy/oracle/.env.oracle.example deploy/oracle/.env && nano deploy/oracle/.env"
echo "    # --env-file is REQUIRED — the compose file's \${DB_PASSWORD} reads it, not env_file:"
echo "    docker compose --env-file deploy/oracle/.env -f docker-compose.oracle.yml up -d --build"
