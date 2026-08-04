from __future__ import annotations

import argparse
import json
import signal
import socket
import time
from uuid import uuid4

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService

_STOP = False


def _mark_stop(*_args) -> None:
    global _STOP
    _STOP = True


def _worker_id() -> str:
    return f"{socket.gethostname()}-{uuid4().hex}"


def _service() -> RdfOutboxService:
    settings = FederationSettings.from_env()
    if not settings.enabled or not settings.database_url:
        raise RuntimeError("Federation must be enabled for the RDF worker.")
    db = Database.from_url(settings.database_url)
    return RdfOutboxService(db, settings)


def run_once(*, limit: int) -> dict[str, int]:
    service = _service()
    return service.process_pending_jobs(limit=limit, worker_id=_worker_id(), lease_seconds=service.settings.rdf_outbox_lease_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Process federation RDF outbox jobs.")
    parser.add_argument("--once", action="store_true", help="Process a single batch and exit.")
    parser.add_argument("--limit", type=int, default=25, help="Maximum jobs per batch.")
    parser.add_argument("--idle-sleep-seconds", type=float, default=1.0, help="Initial idle backoff between polls.")
    parser.add_argument("--max-idle-sleep-seconds", type=float, default=15.0, help="Maximum idle backoff between polls.")
    args = parser.parse_args()

    try:
        service = _service()
    except RuntimeError:
        return 0

    signal.signal(signal.SIGINT, _mark_stop)
    signal.signal(signal.SIGTERM, _mark_stop)

    worker_id = _worker_id()
    if args.once:
        result = service.process_pending_jobs(limit=args.limit, worker_id=worker_id, lease_seconds=service.settings.rdf_outbox_lease_seconds)
        print(json.dumps(result))
        return 0

    idle_sleep = max(0.1, args.idle_sleep_seconds)
    while not _STOP:
        result = service.process_pending_jobs(limit=args.limit, worker_id=worker_id, lease_seconds=service.settings.rdf_outbox_lease_seconds)
        if result["claimed"] > 0:
            idle_sleep = max(0.1, args.idle_sleep_seconds)
            continue
        time.sleep(idle_sleep)
        idle_sleep = min(args.max_idle_sleep_seconds, idle_sleep * 2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
