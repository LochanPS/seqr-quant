#!/usr/bin/env bash
# SeQr Postgres backup — portable, object-storage-aware (A5 enterprise table-stakes).
#
# Self-hosting (on-prem / Oracle / AWS) means WE own backups. This dumps the SeQr
# database in Postgres custom format (-Fc, supports parallel + selective restore),
# gzips it, records a SHA-256 checksum, optionally uploads to object storage, and
# prunes old local copies.
#
# Config (env vars; falls back to sensible defaults):
#   DATABASE_URL        postgres://user:pass@host:port/db  (preferred — parsed for the rest)
#     …or discrete:     PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
#   BACKUP_DIR          local dir for dumps          (default: $HOME/seqr-backups)
#   BACKUP_KEEP         local dumps to retain        (default: 14)
#   BACKUP_S3_URI       s3://bucket/prefix           (optional — upload target; needs awscli)
#                       (any s3-compatible endpoint via AWS_ENDPOINT_URL, e.g. Oracle/MinIO)
#
# Install as a cron job — see README.md.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-${HOME}/seqr-backups}"
KEEP="${BACKUP_KEEP:-14}"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# --- Resolve connection: DATABASE_URL wins, else PG* env vars ------------------
if [[ -n "${DATABASE_URL:-}" ]]; then
  # Strip async/driver suffixes SeQr uses (postgresql+asyncpg://) → libpq form.
  export _URL="${DATABASE_URL/postgresql+asyncpg:/postgresql:}"
  export _URL="${_URL/postgres+asyncpg:/postgres:}"
  CONN=(--dbname="${_URL}")
  DBNAME="$(basename "${_URL%%\?*}")"
else
  DBNAME="${PGDATABASE:-seqr}"
  CONN=()  # pg_dump reads PGHOST/PGUSER/… from the environment
fi

OUT="${BACKUP_DIR}/seqr_${STAMP}.dump.gz"

echo "[backup] dumping ${DBNAME} -> ${OUT}"
# -Fc custom format on stdout, gzipped. --no-owner/--no-privileges keep the dump
# portable across role names between environments.
pg_dump "${CONN[@]}" -Fc --no-owner --no-privileges | gzip -9 > "${OUT}"

# Checksum for integrity verification on restore.
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${OUT}" | awk '{print $1}' > "${OUT}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${OUT}" | awk '{print $1}' > "${OUT}.sha256"
fi

SIZE="$(du -h "${OUT}" | awk '{print $1}')"
echo "[backup] wrote ${OUT} (${SIZE})"

# --- Optional: upload to object storage ---------------------------------------
if [[ -n "${BACKUP_S3_URI:-}" ]]; then
  if command -v aws >/dev/null 2>&1; then
    EP=()
    [[ -n "${AWS_ENDPOINT_URL:-}" ]] && EP=(--endpoint-url "${AWS_ENDPOINT_URL}")
    echo "[backup] uploading to ${BACKUP_S3_URI%/}/"
    aws "${EP[@]}" s3 cp "${OUT}" "${BACKUP_S3_URI%/}/$(basename "${OUT}")"
    [[ -f "${OUT}.sha256" ]] && aws "${EP[@]}" s3 cp "${OUT}.sha256" "${BACKUP_S3_URI%/}/$(basename "${OUT}").sha256"
    echo "[backup] upload complete"
  else
    echo "[backup] WARNING: BACKUP_S3_URI set but 'aws' CLI not found — skipping upload" >&2
  fi
fi

# --- Prune old local dumps ----------------------------------------------------
ls -1t "${BACKUP_DIR}"/seqr_*.dump.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "${old}" "${old}.sha256"
  echo "[backup] pruned ${old}"
done

echo "[backup] done"
