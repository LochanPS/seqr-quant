"""Per-org concurrency fairness for the scan worker pool.

Global throughput is bounded by the worker's ``--concurrency`` (process/thread
slots). That alone is not fair: one tenant queuing 500 assets would occupy every
slot and starve everyone else. So each scan task also claims a per-org slot from a
Redis counter before it runs, and releases it when done. When an org is already at
its cap the task is re-queued (Celery ``retry``) instead of running, leaving the
worker slot free for another tenant.

Pure functions here take an explicit Redis client so they unit-test with fakeredis;
the task wires them to the real broker client (see ``scan_tasks``).
"""
from __future__ import annotations

_KEY = "scan:inflight:{org_id}"


def org_key(org_id: str) -> str:
    return _KEY.format(org_id=org_id)


def acquire_org_slot(client, org_id: str, cap: int, ttl: int) -> bool:
    """Try to claim one in-flight scan slot for ``org_id``.

    Returns True if the org was below ``cap`` (slot claimed), False otherwise.
    The counter carries a TTL so a crashed worker that never releases can only
    wedge an org for ``ttl`` seconds, not forever.
    """
    if cap <= 0:
        return True
    key = org_key(org_id)
    n = client.incr(key)
    if n == 1:
        client.expire(key, ttl)
    if n > cap:
        client.decr(key)
        return False
    return True


def release_org_slot(client, org_id: str) -> None:
    """Release one in-flight slot for ``org_id`` (never drops below zero)."""
    key = org_key(org_id)
    try:
        v = client.decr(key)
    except Exception:
        return
    if v is not None and v < 0:
        client.set(key, 0)


def inflight(client, org_id: str) -> int:
    """Current in-flight scan count for ``org_id`` (0 if unset)."""
    v = client.get(org_key(org_id))
    if v is None:
        return 0
    return int(v)
