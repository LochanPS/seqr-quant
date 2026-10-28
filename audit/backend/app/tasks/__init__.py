from app.config import settings

if settings.USE_FAKE_REDIS:
    from celery import Celery

    celery_app = Celery("seqr")
    celery_app.config_from_object({
        "broker_url": "memory://",
        "result_backend": "cache+memory://",
        "task_always_eager": True,
        "task_eager_propagates": True,
        "task_serializer": "json",
        "result_serializer": "json",
    })
    celery_app.conf.include = ["app.tasks.scan_tasks", "app.github_app.tasks"]
else:
    from celery import Celery

    celery_app = Celery(
        "seqr",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
        include=["app.tasks.scan_tasks", "app.github_app.tasks"],
    )
    celery_app.conf.task_serializer = "json"
    celery_app.conf.result_serializer = "json"
    # Fairness + reliability for the shared worker pool:
    #  - prefetch=1: a worker reserves one task at a time, so a burst of one org's
    #    tasks isn't hoarded in a single worker's prefetch buffer (works with the
    #    per-org cap to keep tenants from starving each other).
    #  - acks_late: a task is acked only after it finishes, so a worker that dies
    #    mid-scan has its task redelivered rather than silently lost.
    celery_app.conf.worker_prefetch_multiplier = 1
    celery_app.conf.task_acks_late = True
    # Single-service deploy (no dedicated worker): run tasks inline. Real Redis is
    # still used for the WS pub/sub channel and rate limiting; only the queue is bypassed.
    if settings.CELERY_ALWAYS_EAGER:
        celery_app.conf.task_always_eager = True
        celery_app.conf.task_eager_propagates = True
