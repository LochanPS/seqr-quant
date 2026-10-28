#!/usr/bin/env bash
# Wire the GitHub App credentials into the running SeQr stack and enable it.
#
# Usage (run ON the AWS box, from the repo root ~/SeQr-Labs):
#   bash deploy/aws/configure_github_app.sh <APP_ID> <path-to-private-key.pem>
#
# Defaults to the AWS EC2 PRODUCTION stack (deploy/aws/docker-compose.prod.yml +
# deploy/aws/.env), the current live path (Caddy auto-TLS → https://api.seqrlabs.com;
# backend is internal-only, so the health/webhook probes go through the public host).
#
# GITHUB_WEBHOOK_SECRET must already be in deploy/aws/.env before running this (the
# register step in docs/GITHUB_APP_OPERATIONS.md §1 produces it). DNS + TLS for
# api.seqrlabs.com must be live first, or GitHub can't reach the webhook.
#
# Override for the laptop-bridge stack instead:
#   COMPOSE_FILE=docker-compose.local.yml ENV=deploy/local/.env COMPOSE_ARGS="" \
#     SUDO= SERVICE=backend HEALTH_URL=http://localhost:8000/api/v1/health \
#     WEBHOOK_URL=http://localhost:8000/api/v1/github/webhook \
#     bash deploy/aws/configure_github_app.sh <APP_ID> <pem>
set -euo pipefail
cd "$(dirname "$0")/../.."

APP_ID="${1:?APP_ID required}"
PEM_PATH="${2:?private-key .pem path required}"

# --- target stack (AWS prod by default; override via env) ---
COMPOSE_FILE="${COMPOSE_FILE:-deploy/aws/docker-compose.prod.yml}"
ENV="${ENV:-deploy/aws/.env}"
SERVICE="${SERVICE:-backend worker}"                 # both re-read the env_file
SUDO="${SUDO:-sudo}"                                 # box docker usually needs sudo
COMPOSE_ARGS="${COMPOSE_ARGS:---env-file deploy/aws/.env}"   # required for ${..} interpolation
HEALTH_URL="${HEALTH_URL:-https://api.seqrlabs.com/api/v1/health}"
WEBHOOK_URL="${WEBHOOK_URL:-https://api.seqrlabs.com/api/v1/github/webhook}"

[ -f "$PEM_PATH" ]     || { echo "ERROR: pem not found: $PEM_PATH" >&2; exit 1; }
[ -f "$ENV" ]          || { echo "ERROR: env file not found: $ENV (start the stack first)" >&2; exit 1; }
[ -f "$COMPOSE_FILE" ] || { echo "ERROR: compose file not found: $COMPOSE_FILE" >&2; exit 1; }

if ! grep -qE '^GITHUB_WEBHOOK_SECRET=.+' "$ENV"; then
  echo "ERROR: GITHUB_WEBHOOK_SECRET is not set in $ENV." >&2
  echo "       Use the SAME value you entered in the GitHub App's 'Webhook secret' field:" >&2
  echo "         echo 'GITHUB_WEBHOOK_SECRET=<that-secret>' >> $ENV" >&2
  exit 1
fi

# Flatten PEM newlines to literal \n (github_app.client.restore_pem restores them at load).
KEY=$(awk 'BEGIN{ORS="\\n"}{print}' "$PEM_PATH")

# Remove any prior values, then append fresh.
grep -vE '^GITHUB_APP_ID=|^GITHUB_APP_PRIVATE_KEY=|^GITHUB_APP_ENABLED=' "$ENV" > "$ENV.tmp" || true
mv "$ENV.tmp" "$ENV"
{
  echo "GITHUB_APP_ID=$APP_ID"
  echo "GITHUB_APP_PRIVATE_KEY=$KEY"
  echo "GITHUB_APP_ENABLED=true"
} >> "$ENV"

echo "== restarting: $SERVICE ($COMPOSE_FILE) =="
# shellcheck disable=SC2086
$SUDO docker compose $COMPOSE_ARGS -f "$COMPOSE_FILE" up -d $SERVICE
sleep 15

echo "== health ($HEALTH_URL) =="; curl -fsS "$HEALTH_URL" && echo
echo "== webhook (App now ENABLED → expect HTTP 401 for an unsigned POST, NOT 404) =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_URL" -H 'X-GitHub-Event: ping' -d '{}')
echo "  HTTP $code"
if [ "$code" = "401" ]; then
  echo "  OK — route live and signature-gated (unsigned rejected)."
elif [ "$code" = "404" ]; then
  echo "  FAIL — still 404: GITHUB_APP_ENABLED did not take effect (check $ENV + restart)." >&2
  exit 1
else
  echo "  WARN — unexpected $code; check backend logs / DNS+TLS." >&2
fi
echo "GitHub App configured + enabled."
