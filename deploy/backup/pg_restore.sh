#!/usr/bin/env bash
# SeQr Postgres restore + restore-drill verification (A5 enterprise table-stakes).
#
# Usage:
#   ./pg_restore.sh <dump.gz> [--target-db NAME] [--force]
#   ./pg_restore.sh <dump.gz> --verify        # non-destructive drill (see below)
#
# Modes:
#   default   Restore the dump into the live database. REFUSES unless --force, because
#             it drops and recreates the target schema (destructive).
#   --verify  Restore into a fresh scratch database, run sanity checks (key tables
#             exist and are queryable), then drop the scratch DB. Proves the dump is
#             actually restorable WITHOUT touching production. This is the drill you
#             run on a schedule / after every backup change.
#
# Config: same connection resolution as pg_backup.sh (DATABASE_URL or PG* env vars).
# The checksum sidecar (<dump>.sha256), if present, is verified before restore.
set -euo pipefail

DUMP="${1:-}"
[[ -z "${DUMP}" ]] && { echo "usage: $0 <dump.gz> [--target-db NAME] [--force|--verify]" >&2; exit 2; }
shift || true

MODE="restore"
TARGET_DB_OVERRIDE=""
FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) MODE="verify" ;;
    --force) FORCE=1 ;;
    --target-db) TARGET_DB_OVERRIDE="${2:-}"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[[ -f "${DUMP}" ]] || { echo "no such dump: ${DUMP}" >&2; exit 1; }

# --- Connection resolution ----------------------------------------------------
if [[ -n "${DATABASE_URL:-}" ]]; then
  URL="${DATABASE_URL/postgresql+asyncpg:/postgresql:}"
  URL="${URL/postgres+asyncpg:/postgres:}"
  DBNAME="$(basename "${URL%%\?*}")"
  # Admin connection to the maintenance 'postgres' db (needed to create/drop DBs).
  ADMIN_URL="${URL%/*}/postgres"
  PSQL_ADMIN=(psql --dbname="${ADMIN_URL}" -v ON_ERROR_STOP=1 -q)
  RESTORE_CONN() { echo "--dbname=${URL%/*}/$1"; }
else
  DBNAME="${PGDATABASE:-seqr}"
  PSQL_ADMIN=(psql -d postgres -v ON_ERROR_STOP=1 -q)
  RESTORE_CONN() { echo "--dbname=$1"; }
fi

# --- Integrity: verify checksum sidecar if present ----------------------------
if [[ -f "${DUMP}.sha256" ]]; then
  echo "[restore] verifying checksum"
  want="$(cat "${DUMP}.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "${DUMP}" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "${DUMP}" | awk '{print $1}')"
  fi
  [[ "${want}" == "${got}" ]] || { echo "[restore] CHECKSUM MISMATCH — refusing" >&2; exit 1; }
  echo "[restore] checksum OK"
fi

_pg_restore_into() {  # $1 = target db name
  local target="$1"
  # shellcheck disable=SC2046
  gunzip -c "${DUMP}" | pg_restore $(RESTORE_CONN "${target}") --no-owner --no-privileges --clean --if-exists
}

if [[ "${MODE}" == "verify" ]]; then
  SCRATCH="seqr_verify_$(date -u +%s)"
  echo "[verify] creating scratch db ${SCRATCH}"
  "${PSQL_ADMIN[@]}" -c "CREATE DATABASE ${SCRATCH};"
  cleanup() { "${PSQL_ADMIN[@]}" -c "DROP DATABASE IF EXISTS ${SCRATCH};" >/dev/null 2>&1 || true; }
  trap cleanup EXIT

  echo "[verify] restoring dump into scratch"
  # pg_restore may emit non-fatal warnings; capture status explicitly.
  if ! _pg_restore_into "${SCRATCH}"; then
    echo "[verify] restore reported errors" >&2; exit 1
  fi

  echo "[verify] running sanity checks"
  # Core tables must exist and be queryable. Add/adjust as the schema evolves.
  for tbl in organisations users assets audit_events; do
    n="$(psql $(RESTORE_CONN "${SCRATCH}") -tAc "SELECT count(*) FROM ${tbl};" 2>/dev/null || echo FAIL)"
    [[ "${n}" == "FAIL" ]] && { echo "[verify] FAILED: table ${tbl} missing/unqueryable" >&2; exit 1; }
    echo "[verify]   ${tbl}: ${n} rows"
  done
  echo "[verify] PASS — dump is restorable"
  exit 0
fi

# --- Destructive live restore -------------------------------------------------
TARGET="${TARGET_DB_OVERRIDE:-${DBNAME}}"
if [[ "${FORCE}" -ne 1 ]]; then
  echo "[restore] REFUSING: this drops and recreates schema in '${TARGET}'." >&2
  echo "[restore] Re-run with --force once you are sure, or use --verify for a safe drill." >&2
  exit 1
fi
echo "[restore] restoring ${DUMP} into ${TARGET} (destructive)"
_pg_restore_into "${TARGET}"
echo "[restore] done"
