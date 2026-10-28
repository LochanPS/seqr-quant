#!/usr/bin/env bash
# Nightly Postgres backup. Self-hosting means WE own backups now (Render did this
# for you). Install as a cron job — see DEPLOY_ORACLE.md §7.
#   Keeps 14 daily dumps in ~/seqr-backups, gzipped.
set -euo pipefail

BACKUP_DIR="${HOME}/seqr-backups"
KEEP=14
STAMP="$(date +%Y%m%d_%H%M)"
mkdir -p "$BACKUP_DIR"

COMPOSE="docker compose --env-file ${HOME}/SeQr-Labs/deploy/oracle/.env -f ${HOME}/SeQr-Labs/docker-compose.oracle.yml"
$COMPOSE exec -T db pg_dump -U seqr seqr | gzip > "${BACKUP_DIR}/seqr_${STAMP}.sql.gz"

# prune old
ls -1t "${BACKUP_DIR}"/seqr_*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup written: ${BACKUP_DIR}/seqr_${STAMP}.sql.gz"
