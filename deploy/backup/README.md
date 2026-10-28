# SeQr — Postgres Backup & Restore

Enterprise table-stakes (A5): a documented, scripted, **verified** backup/restore for the
SeQr Postgres database. Self-hosting (on-prem, Oracle Mumbai, AWS) means SeQr owns backups —
these scripts are portable across all three and any S3-compatible object store.

> The older `deploy/oracle/backup.sh` is a compose-specific plain-SQL dump kept for the
> Oracle box. These scripts supersede it: custom-format dumps, checksums, object-storage
> upload, and a non-destructive restore drill. Point new deployments here.

## Files

| Script | Purpose |
|---|---|
| `pg_backup.sh` | Dump (`pg_dump -Fc`) → gzip → SHA-256 checksum → optional S3 upload → prune. |
| `pg_restore.sh` | Restore a dump, **or** run a non-destructive verify drill into a scratch DB. |

## Configuration

Both scripts resolve the connection from **`DATABASE_URL`** (preferred — the same var the
app uses; `postgresql+asyncpg://` driver suffixes are stripped automatically) or discrete
`PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `PGDATABASE`.

Backup-only knobs:

| Env | Default | Meaning |
|---|---|---|
| `BACKUP_DIR` | `$HOME/seqr-backups` | Local dump directory. |
| `BACKUP_KEEP` | `14` | Local dumps to retain (older pruned). |
| `BACKUP_S3_URI` | _(unset)_ | `s3://bucket/prefix` upload target (needs `awscli`). |
| `AWS_ENDPOINT_URL` | _(unset)_ | S3-compatible endpoint (Oracle Object Storage, MinIO, …). |

## Take a backup

```bash
export DATABASE_URL='postgresql://seqr:***@db:5432/seqr'
export BACKUP_S3_URI='s3://seqr-backups/prod'   # optional
deploy/backup/pg_backup.sh
```

Writes `seqr_YYYYMMDD_HHMMSS.dump.gz` (+ `.sha256`) to `BACKUP_DIR`, uploads if configured,
prunes to `BACKUP_KEEP`.

### Schedule it (cron, nightly 02:30 UTC)

```cron
30 2 * * * DATABASE_URL='postgresql://seqr:***@db:5432/seqr' BACKUP_S3_URI='s3://seqr-backups/prod' /opt/seqr/deploy/backup/pg_backup.sh >> /var/log/seqr-backup.log 2>&1
```

## Verify a backup (restore drill — run this regularly)

Non-destructive: restores into a throwaway scratch database, checks the core tables are
present and queryable, then drops the scratch DB. **Never touches production.**

```bash
deploy/backup/pg_restore.sh ~/seqr-backups/seqr_20260921_023000.dump.gz --verify
```

Expected tail:

```
[verify]   organisations: N rows
[verify]   users: N rows
[verify]   assets: N rows
[verify]   audit_events: N rows
[verify] PASS — dump is restorable
```

The drill needs privileges to `CREATE DATABASE` / `DROP DATABASE` (the `DATABASE_URL` role
or a maintenance role). Wire it into cron weekly, or into CI against a staging dump — a
backup you have never restored is not a backup.

## Restore for real (destructive)

```bash
# into the live DB (drops & recreates schema — hence --force):
deploy/backup/pg_restore.sh seqr_20260921_023000.dump.gz --force

# or into a named alternate DB (e.g. a recovery instance):
deploy/backup/pg_restore.sh seqr_20260921_023000.dump.gz --target-db seqr_recovery --force
```

The checksum sidecar (`<dump>.sha256`), if present, is verified before any restore; a
mismatch aborts.

## Notes

- **Format:** custom (`-Fc`) supports parallel and selective restore; `--no-owner
  --no-privileges` keep dumps portable across role names between environments.
- **Data residency:** keep `BACKUP_S3_URI` in an India region (AWS `ap-south-1` / Oracle
  Mumbai) to honour DPDP / CERT-In residency (see root `CLAUDE.md`).
- **Encryption:** enable bucket-side SSE (or pipe through `age`/`gpg` before upload) for
  backups leaving the host. Object-store encryption is the minimum for regulated buyers.
