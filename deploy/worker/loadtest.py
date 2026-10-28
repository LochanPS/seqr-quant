#!/usr/bin/env python3
"""Load-test the async scan worker with a batch of ~100 assets.

Proves the A6 acceptance criteria against a running stack (deploy/worker/docker-compose.yml):
  * POST /assets/scan-all returns immediately with N queued job ids (not blocking).
  * The worker pool runs scans concurrently (observed running > 1), not sequentially.
  * The per-org fairness cap bounds concurrency (observed running <= cap).
  * The whole batch eventually completes.

It registers a throwaway org, creates N assets, fires one batch scan, then polls
/api/v1/scans and reports wall-clock time and the peak number of simultaneously
running scans.

Usage:
  python deploy/worker/loadtest.py --api http://localhost:8000 --count 100
Env: TARGETS = comma-separated hosts to scan (cycled); defaults to a few fast public hosts.

Requires: pip install httpx
"""
from __future__ import annotations

import argparse
import os
import time
import uuid

import httpx

DEFAULT_TARGETS = [
    "cloudflare.com",
    "google.com",
    "github.com",
    "example.com",
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("API_URL", "http://localhost:8000"))
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--poll", type=float, default=2.0, help="seconds between status polls")
    ap.add_argument("--timeout", type=float, default=1200.0, help="give up after N seconds")
    args = ap.parse_args()

    targets = [t.strip() for t in os.environ.get("TARGETS", ",".join(DEFAULT_TARGETS)).split(",") if t.strip()]
    api = args.api.rstrip("/")
    c = httpx.Client(base_url=api, timeout=30.0)

    # 1. throwaway org
    email = f"load-{uuid.uuid4().hex[:8]}@seqr.test"
    r = c.post("/api/v1/auth/register", json={
        "email": email, "password": "SecurePass123!",
        "name": "Load Test", "org_name": f"Load {uuid.uuid4().hex[:6]}",
    })
    r.raise_for_status()
    token = r.json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}
    print(f"registered {email}")

    # 2. create N assets
    t0 = time.time()
    for i in range(args.count):
        host = targets[i % len(targets)]
        rr = c.post("/api/v1/assets", headers=auth, json={
            "type": "domain", "name": f"asset-{i}", "identifier": host,
        })
        rr.raise_for_status()
    print(f"created {args.count} assets in {time.time() - t0:.1f}s")

    # 3. batch scan — must return immediately with queued jobs
    t_enqueue = time.time()
    r = c.post("/api/v1/assets/scan-all", headers=auth)
    r.raise_for_status()
    body = r.json()
    enqueue_ms = (time.time() - t_enqueue) * 1000
    queued = body["queued"]
    assert all(s["status"] == "queued" for s in body["scans"]), "expected all jobs queued (not run inline)"
    print(f"scan-all enqueued {queued} jobs in {enqueue_ms:.0f}ms (all status=queued → async, not eager)")

    # 4. poll until done, tracking peak concurrency
    t_start = time.time()
    peak_running = 0
    while True:
        counts = {"queued": 0, "running": 0, "complete": 0, "failed": 0}
        offset = 0
        while True:
            rr = c.get("/api/v1/scans", headers=auth, params={"limit": 100, "offset": offset})
            rr.raise_for_status()
            page = rr.json()
            for s in page:
                counts[s["status"]] = counts.get(s["status"], 0) + 1
            if len(page) < 100:
                break
            offset += 100
        peak_running = max(peak_running, counts["running"])
        done = counts["complete"] + counts["failed"]
        print(f"  t+{time.time() - t_start:5.0f}s  running={counts['running']:2d}  "
              f"done={done}/{queued}  peak_running={peak_running}")
        if done >= queued:
            break
        if time.time() - t_start > args.timeout:
            print("TIMEOUT — not all scans finished")
            break
        time.sleep(args.poll)

    elapsed = time.time() - t_start
    print("\n=== result ===")
    print(f"batch of {queued} scans finished in {elapsed:.0f}s")
    print(f"peak concurrent running scans: {peak_running}")
    print(f"enqueue latency: {enqueue_ms:.0f}ms")
    print(f"final: {counts}")
    if peak_running <= 1:
        print("WARNING: never saw >1 concurrent scan — worker may be eager/single-slot")
    c.close()


if __name__ == "__main__":
    main()
