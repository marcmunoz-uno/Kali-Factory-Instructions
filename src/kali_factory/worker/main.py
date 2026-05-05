"""RQ worker entrypoint. Pulls jobs from the `kali-factory` queue."""

from __future__ import annotations

import os

import structlog
from redis import Redis
from rq import Queue, Worker

log = structlog.get_logger()


def run() -> None:
    redis_url = os.environ.get("KALI_FACTORY_REDIS_URL", "redis://localhost:6379/0")
    queue_name = "kali-factory"

    log.info("worker.start", redis_url=redis_url, queue=queue_name)
    redis_conn = Redis.from_url(redis_url)
    worker = Worker([Queue(queue_name, connection=redis_conn)], connection=redis_conn)
    worker.work(with_scheduler=False)
