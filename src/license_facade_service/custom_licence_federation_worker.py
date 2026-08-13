from __future__ import annotations

import logging
import os
import signal
import socket
import time
from uuid import uuid4

from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.services.custom_licence_federation_publication import (
    CustomLicenceFederationPublicationService,
)

logger = logging.getLogger(__name__)

_STOP = False


def _mark_stop(*_args) -> None:
    global _STOP
    _STOP = True


def _worker_id() -> str:
    host = socket.gethostname() or "worker"
    return f"custom-licence-federation-worker:{host}:{uuid4().hex[:8]}"


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except (ValueError, TypeError):
        raise ValueError(f"{name} must be an integer, got: {raw!r}")
    if value <= 0:
        raise ValueError(f"{name} must be > 0, got: {value}")
    return value


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    custom_settings = CustomLicenceRegistrationSettings.from_env()
    federation_settings = FederationSettings.from_env()

    if custom_settings.database_url is None:
        logger.error("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL is not configured; worker cannot start")
        return 1

    if not federation_settings.enabled:
        logger.error("FEDERATION_ENABLED is not true; custom-licence federation worker cannot start")
        return 1

    if federation_settings.validation_errors:
        logger.error(
            "Federation configuration has validation errors: %s",
            "; ".join(federation_settings.validation_errors),
        )
        return 1

    try:
        lease_seconds = _parse_positive_int("CUSTOM_LICENCE_FEDERATION_LEASE_SECONDS", 60)
        batch_size = _parse_positive_int("CUSTOM_LICENCE_FEDERATION_BATCH_SIZE", 25)
        interval_seconds = _parse_positive_int("CUSTOM_LICENCE_FEDERATION_WORKER_INTERVAL_SECONDS", 5)
    except ValueError as exc:
        logger.error("Invalid worker configuration: %s", exc)
        return 1

    db = Database.from_url(custom_settings.database_url)
    try:
        service = CustomLicenceFederationPublicationService(
            db=db,
            custom_settings=custom_settings,
            federation_settings=federation_settings,
            federation_ready=True,
        )
        signal.signal(signal.SIGINT, _mark_stop)
        signal.signal(signal.SIGTERM, _mark_stop)

        worker_id = _worker_id()
        logger.info("Custom-licence federation worker started: %s", worker_id)

        while not _STOP:
            try:
                result = service.process_batch(
                    limit=batch_size,
                    lease_seconds=lease_seconds,
                    worker_id=worker_id,
                )
                if result["claimed"] > 0:
                    logger.info(
                        "Processed %d/%d jobs; %d remaining",
                        result["processed"],
                        result["claimed"],
                        result["remaining"],
                    )
            except Exception as exc:
                error_class = type(exc).__name__
                logger.warning(
                    "Batch processing error (%s); backing off %ds before retry",
                    error_class,
                    interval_seconds,
                )
                slept = 0
                while slept < interval_seconds and not _STOP:
                    time.sleep(1)
                    slept += 1
                continue

            if _STOP:
                break
            if result["claimed"] == 0:
                slept = 0
                while slept < interval_seconds and not _STOP:
                    time.sleep(1)
                    slept += 1

        logger.info("Custom-licence federation worker shutting down cleanly: %s", worker_id)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
