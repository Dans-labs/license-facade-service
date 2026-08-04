from __future__ import annotations

import argparse
import json

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.outbound import FederationError
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService


def _service() -> RdfOutboxService:
    settings = FederationSettings.from_env()
    if not settings.enabled or not settings.database_url:
        raise FederationError("federation-disabled", "Federation must be enabled.")
    db = Database.from_url(settings.database_url)
    return RdfOutboxService(db, settings)


def run_process(*, limit: int) -> dict[str, int]:
    service = _service()
    return service.process_pending_jobs(limit=limit, lease_seconds=service.settings.rdf_outbox_lease_seconds)


def run_retry(*, limit: int) -> int:
    service = _service()
    return service.retry_failed_jobs(limit=limit)


def run_requeue(*, limit: int) -> int:
    service = _service()
    return service.requeue_dead_lettered_jobs(limit=limit)


def run_rebuild(*, dry_run: bool, confirm: bool, limit: int) -> dict[str, int]:
    service = _service()
    return service.rebuild_all(dry_run=dry_run, confirm=confirm, limit=limit)


def run_reconcile(*, dry_run: bool, confirm: bool, limit: int) -> dict[str, int]:
    service = _service()
    return service.reconcile(dry_run=dry_run, confirm=confirm, limit=limit)


def main() -> int:
    parser = argparse.ArgumentParser(description="Federation RDF maintenance commands.")
    sub = parser.add_subparsers(dest="command", required=True)

    process = sub.add_parser("process", help="Process pending RDF outbox jobs.")
    process.add_argument("--limit", type=int, default=25)

    retry = sub.add_parser("retry", help="Retry failed RDF jobs.")
    retry.add_argument("--limit", type=int, default=100)

    requeue = sub.add_parser("requeue", help="Requeue dead-lettered RDF jobs.")
    requeue.add_argument("--limit", type=int, default=100)

    rebuild = sub.add_parser("rebuild", help="Rebuild RDF graphs from PostgreSQL.")
    rebuild.add_argument("--write", action="store_true", help="Apply the rebuild instead of dry-run.")
    rebuild.add_argument("--confirm", action="store_true")
    rebuild.add_argument("--limit", type=int, default=1000)

    reconcile = sub.add_parser("reconcile", help="Reconcile RDF graph state with Fuseki.")
    reconcile.add_argument("--write", action="store_true", help="Apply reconciliation instead of dry-run.")
    reconcile.add_argument("--confirm", action="store_true")
    reconcile.add_argument("--limit", type=int, default=1000)

    args = parser.parse_args()
    try:
        if args.command == "process":
            result = run_process(limit=args.limit)
        elif args.command == "retry":
            result = {"retried": run_retry(limit=args.limit)}
        elif args.command == "requeue":
            result = {"requeued": run_requeue(limit=args.limit)}
        elif args.command == "rebuild":
            result = run_rebuild(dry_run=not args.write, confirm=args.confirm, limit=args.limit)
        elif args.command == "reconcile":
            result = run_reconcile(dry_run=not args.write, confirm=args.confirm, limit=args.limit)
        else:
            raise AssertionError(args.command)
    except FederationError as exc:
        print(json.dumps({"error": exc.code, "detail": exc.detail}))
        return 2
    except ValueError as exc:
        print(json.dumps({"error": "invalid-request", "detail": str(exc)}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
