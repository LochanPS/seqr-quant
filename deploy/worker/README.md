# Async scan workers (A6)

Moves scans off the request thread onto a real Celery worker pool. The API enqueues
a job and returns immediately; the worker runs the scan and streams live progress
back over the WebSocket channel the frontend already listens on.

## What's here

| File | Purpose |
|---|---|
| `Dockerfile` | Worker image — shared scanner + OpenSSL 3.5, entrypoint `celery … worker`. |
| `docker-compose.yml` | Full stack: Postgres + Redis + API + worker, `CELERY_ALWAYS_EAGER=false`. |
| `loadtest.py` | Fires a ~100-asset batch scan and reports throughput + peak concurrency. |

## Run

From the **repo root** (`seqr-labs/`), so images can install `shared-scanner/`:

```bash
docker compose -f deploy/worker/docker-compose.yml up --build
```

Scale the pool:

```bash
docker compose -f deploy/worker/docker-compose.yml up --scale worker=3
```

## How scaling / fairness works

- **Global throughput** — the worker's `--concurrency` (`SCAN_WORKER_CONCURRENCY`,
  default 8) sets how many scans run in parallel per worker process. Add more worker
  containers (`--scale worker=N`) for more.
- **Per-org fairness** — each scan claims a per-org slot in Redis before running
  (`MAX_CONCURRENT_SCANS_PER_ORG`, default 3). A tenant that queues 500 assets gets at
  most 3 running at once; the rest wait in the queue so other tenants aren't starved.
  Over-cap tasks are re-queued with jittered backoff (Celery `retry`), freeing the
  worker slot immediately.
- **Reliability** — `prefetch_multiplier=1` + `task_acks_late` (set in `app.tasks`):
  a worker reserves one task at a time and only acks after finishing, so a crash
  mid-scan redelivers the job instead of losing it. The per-org counter has a TTL
  (`SCAN_ORG_INFLIGHT_TTL`, 900s) so a dead worker can't wedge an org permanently.

## Live progress

The worker publishes to Redis channel `scan:{scan_id}`; the API relays it on
`/ws/scans/{scan_id}` (org-boundary checked — a token may only subscribe to its own
org's scans). Message shapes the frontend consumes:

```json
{"type": "step", "step": "Probing TLS configuration…"}
{"type": "finding", "algorithm": "RSA-2048", "location_detail": "…", "quantum_status": "vulnerable"}
{"type": "complete", "components": 2}
{"type": "failed", "error": "…"}
```

## Batch scan

`POST /api/v1/assets/scan-all` (authenticated, org-scoped) enqueues one job per asset
in the caller's org and returns the queued job ids immediately.

## Load test

Against a running stack:

```bash
pip install httpx
python deploy/worker/loadtest.py --api http://localhost:8000 --count 100
```

It registers a throwaway org, creates 100 assets, fires one batch scan, and reports:
enqueue latency (should be ms — proves non-blocking), peak concurrent running scans
(bounded by the per-org cap — raise `MAX_CONCURRENT_SCANS_PER_ORG` to see more), and
total wall time. `TARGETS=host1,host2` overrides the hosts scanned.
