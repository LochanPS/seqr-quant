"""
Shared rate limiter — Redis-backed when available, in-memory fallback otherwise.

Per-process in-memory counters do not work behind multiple workers (each worker
has its own dict), so a determined client gets N×limit. When real Redis is
configured (USE_FAKE_REDIS=False) we use an atomic INCR + EXPIRE fixed window
shared across all workers; otherwise we fall back to the in-memory sliding window
(fine for single-process dev / tests).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict

from app.config import settings

_mem: dict[str, list[float]] = defaultdict(list)
_mem_lock = threading.Lock()

_redis_client = None
_redis_tried = False


def _get_redis():
    global _redis_client, _redis_tried
    if settings.USE_FAKE_REDIS:
        return None
    if _redis_tried:
        return _redis_client
    _redis_tried = True
    try:
        import redis
        _redis_client = redis.from_url(settings.REDIS_URL, socket_timeout=1)
        _redis_client.ping()
    except Exception:
        _redis_client = None
    return _redis_client


def hit(key: str, max_hits: int, window_seconds: int) -> tuple[bool, int]:
    """
    Record one hit for `key`. Returns (exceeded, retry_after_seconds).

    `exceeded` is True once the number of hits in the window passes `max_hits`.
    """
    r = _get_redis()
    if r is not None:
        try:
            full = f"ratelimit:{key}"
            n = r.incr(full)
            if n == 1:
                r.expire(full, window_seconds)
            if n > max_hits:
                ttl = r.ttl(full)
                return True, (ttl if isinstance(ttl, int) and ttl > 0 else window_seconds)
            return False, 0
        except Exception:
            pass  # fall through to in-memory

    now = time.time()
    with _mem_lock:
        hits = [t for t in _mem[key] if now - t < window_seconds]
        hits.append(now)
        _mem[key] = hits
        if len(hits) > max_hits:
            retry = int(window_seconds - (now - hits[0])) + 1
            return True, max(1, retry)
    return False, 0
