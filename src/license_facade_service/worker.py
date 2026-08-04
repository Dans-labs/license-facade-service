from __future__ import annotations

import signal
import time

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.inbound import FederationInboundSyncService

_STOP = False


def _mark_stop(*_args) -> None:
    global _STOP
    _STOP = True


def main() -> int:
    settings = FederationSettings.from_env()
    if not settings.enabled or not settings.inbound_enabled or not settings.database_url:
        return 0
    db = Database.from_url(settings.database_url)
    service = FederationInboundSyncService(db, settings)
    signal.signal(signal.SIGINT, _mark_stop)
    signal.signal(signal.SIGTERM, _mark_stop)
    while not _STOP:
        service.sync_all_trusted_peers_once(max_seconds_per_peer=settings.worker_max_sync_seconds)
        slept = 0
        while slept < settings.worker_interval_seconds and not _STOP:
            time.sleep(1)
            slept += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
