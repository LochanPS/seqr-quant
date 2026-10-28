#!/usr/bin/env bash
# Runs ON the EC2 box. Installs Node, builds the Next.js frontend pointed at the
# public backend, and serves it on :3000 (0.0.0.0) as a public demo URL.
set -euo pipefail
cd "$(dirname "$0")/../.."          # repo root
cd audit/frontend

# Point the frontend at the stable public backend domain (TLS), NOT an ephemeral
# instance IP. Override with SEQR_API_BASE only for a throwaway box.
#   SEQR_API_BASE — https origin of the backend (default: https://api.seqrlabs.com)
#   SEQR_WS_BASE  — wss origin for live scan progress (default: derived from API base)
API_BASE="${SEQR_API_BASE:-https://api.seqrlabs.com}"
WS_BASE="${SEQR_WS_BASE:-${API_BASE/https:/wss:}}"

echo "==> [1/4] Node"
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
node --version

echo "==> [2/4] Frontend env (baked at build time)"
cat > .env.local <<EOF
NEXT_PUBLIC_API_URL=${API_BASE}/api/v1
NEXT_PUBLIC_WS_URL=${WS_BASE}
BACKEND_URL=${API_BASE}
EOF
cat .env.local

echo "==> [3/4] Install + build (~3-5 min)"
npm install --no-audit --no-fund
npm run build

echo "==> [4/4] Start on :3000"
sudo fuser -k 3000/tcp 2>/dev/null || true
pkill -f next-server 2>/dev/null || true
sleep 3
setsid bash -c 'npx next start -p 3000 -H 0.0.0.0 > $HOME/frontend.log 2>&1' < /dev/null &
disown || true
sleep 8
echo "--- frontend.log ---"; tail -n 12 ~/frontend.log
echo "--- local check ---"; curl -s -o /dev/null -w "HTTP %{http_code}\n" --max-time 30 http://localhost:3000/login || echo "warming..."
