"""
Celery application wired to Redis as broker + result backend.

Workers pull tasks from the queue, execute agent logic in isolated
processes, and append results back to the Redis result stream.
"""

from celery import Celery

from app.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    "red_team_engine",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,   # one task at a time per worker
    task_acks_late=True,            # ack after execution for crash safety
)

# Auto-discover tasks inside app.tasks
celery_app.autodiscover_tasks(["app"])
