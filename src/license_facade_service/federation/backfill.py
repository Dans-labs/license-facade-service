from __future__ import annotations

import argparse
import json

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.outbound import FederationBackfillService, FederationError


def run_backfill(*, apply_changes: bool, confirm_write: bool, batch_size: int) -> dict[str, int]:
    settings = FederationSettings.from_env()
    if not settings.enabled or not settings.database_url:
        raise FederationError("federation-disabled", "Federation must be enabled for backfill.")
    db = Database.from_url(settings.database_url)
    service = FederationBackfillService(db, settings)
    return service.backfill_missing_events(
        apply_changes=apply_changes,
        confirm_write=confirm_write,
        batch_size=batch_size,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill authoritative federation change events.")
    parser.add_argument("--write", action="store_true", help="Apply inserts. Default is dry-run.")
    parser.add_argument("--confirm", action="store_true", help="Required with --write.")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    try:
        result = run_backfill(
            apply_changes=args.write,
            confirm_write=args.confirm,
            batch_size=args.batch_size,
        )
    except FederationError as exc:
        print(json.dumps({"error": exc.code, "detail": exc.detail}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
