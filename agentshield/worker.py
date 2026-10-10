from __future__ import annotations

import os

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded

TASK_HARD_LIMIT = 240
TASK_SOFT_LIMIT = 210
RUN_LOCK_TIMEOUT = TASK_HARD_LIMIT + 30
BROKER_VISIBILITY_TIMEOUT = RUN_LOCK_TIMEOUT + 30

broker_url = os.environ.get("AGENTSHIELD_REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("agentshield", broker=broker_url)
celery_app.conf.update(
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=TASK_HARD_LIMIT,
    task_soft_time_limit=TASK_SOFT_LIMIT,
    broker_transport_options={"visibility_timeout": BROKER_VISIBILITY_TIMEOUT},
    task_default_delivery_mode=2,
    beat_schedule={
        "dispatch-agentshield-outbox": {
            "task": "agentshield.dispatch_outbox",
            "schedule": 10.0,
        },
    },
)


@celery_app.task(bind=True, name="agentshield.evaluate", max_retries=5, acks_late=True)
def run_evaluation(self, run_id: str) -> None:
    from redis import Redis
    from .app import _connect, _execute_run_from_id, _now

    redis = Redis.from_url(broker_url, socket_connect_timeout=3, socket_timeout=3)
    lock = redis.lock(f"agentshield:run:{run_id}", timeout=RUN_LOCK_TIMEOUT, blocking_timeout=RUN_LOCK_TIMEOUT + 10)
    acquired = False
    try:
        acquired = lock.acquire(blocking=True)
        if not acquired:
            return
        _execute_run_from_id(run_id)
    except Exception as exc:
        if self.request.retries >= self.max_retries:
            with _connect() as db:
                db.execute("UPDATE runs SET status='failed', completed_at=?, error=? WHERE id=?", (_now(), type(exc).__name__, run_id))
                db.execute("DELETE FROM job_outbox WHERE run_id=?", (run_id,))
            raise
        raise self.retry(exc=exc, countdown=min(2 ** (self.request.retries + 1), 30))
    finally:
        if acquired:
            try:
                lock.release()
            except Exception:
                pass
        redis.close()


@celery_app.task(name="agentshield.dispatch_outbox")
def dispatch_outbox() -> None:
    from .app import _connect, _now

    with _connect() as db:
        pending = db.execute("SELECT run_id FROM job_outbox WHERE sent_at IS NULL ORDER BY created_at LIMIT 100").fetchall()
    for row in pending:
        try:
            run_evaluation.delay(row["run_id"])
            with _connect() as db:
                db.execute("UPDATE job_outbox SET sent_at=? WHERE run_id=? AND sent_at IS NULL", (_now(), row["run_id"]))
        except Exception:
            return
