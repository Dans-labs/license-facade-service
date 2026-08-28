from __future__ import annotations

import random
import signal
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from sqlalchemy import select, text

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import FederationWorkerHeartbeat
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.audit import (
    AuditAction,
    AuditActorType,
    AuditOutcome,
    AuditTargetType,
    AuditValidationError,
    WorkerStatus,
    WorkerType,
    write_audit_row_sync,
)
from src.license_facade_service.federation.inbound import FederationInboundSyncService
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.local_key_lifecycle import (
    LocalKeyError,
    LocalKeyErrorCode,
    SigningKeyLifecycleService,
)

_STOP = False
_MISSING_MATERIAL_RETRY_LIMIT = 3
_SLEEP_GRANULARITY_SECONDS = 0.5

_ROTATION_NOOP_CODES = frozenset(
    {"rotation_idle_no_due", "rotation_deferred_not_due", "rotation_no_longer_due", "rotation_canceled"}
)
_ROTATION_PERMANENT_CODES = {
    LocalKeyErrorCode.MATERIAL_MISMATCH,
    LocalKeyErrorCode.KEY_MALFORMED,
    LocalKeyErrorCode.KEY_NOT_ED25519,
    LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
    LocalKeyErrorCode.KEY_PATH_ESCAPE,
    LocalKeyErrorCode.KEY_NOT_REGULAR_FILE,
    LocalKeyErrorCode.KEY_EMPTY,
    LocalKeyErrorCode.COLLISION,
    LocalKeyErrorCode.TRANSITION_FORBIDDEN,
    LocalKeyErrorCode.SCHEDULE_CONFLICT,
    LocalKeyErrorCode.ACTIVE_KEY_MISSING,
    LocalKeyErrorCode.AMBIGUOUS_ACTIVE_KEY,
}
_LIFECYCLE_SELF_AUDITED_CODES = {
    LocalKeyErrorCode.KEY_NOT_FOUND,
    LocalKeyErrorCode.KEY_NOT_REGULAR_FILE,
    LocalKeyErrorCode.KEY_UNREADABLE,
    LocalKeyErrorCode.KEY_EMPTY,
    LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
    LocalKeyErrorCode.KEY_PATH_ESCAPE,
    LocalKeyErrorCode.KEY_MALFORMED,
    LocalKeyErrorCode.KEY_NOT_ED25519,
    LocalKeyErrorCode.INVALID_KID,
    LocalKeyErrorCode.MATERIAL_MISMATCH,
    LocalKeyErrorCode.AUDIT_FAILED,
}


@dataclass(frozen=True)
class _RotationCandidate:
    kid: str
    scheduled_at: datetime
    due: bool


@dataclass(frozen=True)
class _RotationPassResult:
    code: str
    retryable: bool = False
    permanent: bool = False
    degraded: bool = False
    kid: str | None = None

    @property
    def is_error(self) -> bool:
        return self.retryable or self.permanent or self.degraded

    @property
    def is_noop(self) -> bool:
        return self.code in _ROTATION_NOOP_CODES

    @property
    def activation_succeeded(self) -> bool:
        return self.code == "rotation_activation_succeeded"


@dataclass
class _RotationBackoffState:
    candidate_kid: str | None = None
    consecutive_failures: int = 0
    missing_material_failures: int = 0
    next_attempt_monotonic: float = 0.0

    def reset_for_candidate(self, candidate_kid: str | None) -> None:
        if self.candidate_kid != candidate_kid:
            self.candidate_kid = candidate_kid
            self.consecutive_failures = 0
            self.missing_material_failures = 0


def _mark_stop(*_args) -> None:
    global _STOP
    _STOP = True


def _resolve_worker_instance_id(settings: FederationSettings) -> uuid.UUID:
    if settings.worker_instance_id:
        return uuid.UUID(settings.worker_instance_id)
    return uuid.uuid4()


def _bounded_error_class(value: str | None) -> str | None:
    if not value:
        return None
    return value[:64]


def _safe_worker_audit(
    db: Database,
    *,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: str,
    instance_id: uuid.UUID,
    reason: str,
    details: dict[str, str] | None,
    outcome: AuditOutcome,
) -> bool:
    try:
        with db.transaction() as session:
            write_audit_row_sync(
                session,
                actor_type=AuditActorType.WORKER,
                action=action,
                target_type=target_type,
                target_id=target_id,
                outcome=outcome,
                actor_id=str(instance_id),
                reason=reason,
                details=details,
            )
        return True
    except Exception:
        return False


def _safe_heartbeat(
    db: Database,
    *,
    instance_id: uuid.UUID,
    hostname: str | None,
    status: WorkerStatus,
    last_error_class: str | None,
    mark_success: bool,
) -> bool:
    try:
        with db.transaction() as session:
            now = session.execute(text("SELECT now()")).scalar_one()
            row = session.execute(
                select(FederationWorkerHeartbeat).where(
                    FederationWorkerHeartbeat.worker_type == WorkerType.SYNC.value,
                    FederationWorkerHeartbeat.instance_id == instance_id,
                )
            ).scalar_one_or_none()
            if row is None:
                row = FederationWorkerHeartbeat(
                    worker_type=WorkerType.SYNC.value,
                    instance_id=instance_id,
                    hostname=hostname,
                    started_at=now,
                    last_heartbeat_at=now,
                    status=status.value,
                    last_error_class=_bounded_error_class(last_error_class),
                    updated_at=now,
                )
                if mark_success:
                    row.last_success_at = now
                session.add(row)
                return True
            row.hostname = hostname
            row.last_heartbeat_at = now
            row.status = status.value
            row.last_error_class = _bounded_error_class(last_error_class)
            row.updated_at = now
            if mark_success:
                row.last_success_at = now
        return True
    except Exception:
        return False


def _next_rotation_candidate(db: Database) -> _RotationCandidate | None:
    from sqlalchemy import select, text
    from src.license_facade_service.db.models.federation import FederationSigningKey
    from src.license_facade_service.federation.local_key_lifecycle import LocalKeyState

    with db.transaction() as session:
        now = session.execute(text("SELECT now()")).scalar_one()
        row = session.execute(
            select(FederationSigningKey.kid, FederationSigningKey.rotation_scheduled_at)
            .where(
                FederationSigningKey.status == LocalKeyState.STAGED.value,
                FederationSigningKey.rotation_scheduled_at.is_not(None),
            )
            .order_by(FederationSigningKey.rotation_scheduled_at.asc(), FederationSigningKey.kid.asc())
            .limit(1)
        ).first()
    if row is None or row[1] is None:
        return None
    return _RotationCandidate(kid=row[0], scheduled_at=row[1], due=row[1] <= now)


def _is_audit_validation_failure(error: LocalKeyError) -> bool:
    cause = error.__cause__
    return isinstance(cause, AuditValidationError)


def _classify_rotation_error(error: LocalKeyError, backoff: _RotationBackoffState) -> _RotationPassResult:
    if error.code == LocalKeyErrorCode.EXPECTED_STATE_MISMATCH:
        return _RotationPassResult(code="rotation_no_longer_due")
    if error.code == LocalKeyErrorCode.AUDIT_FAILED:
        if _is_audit_validation_failure(error):
            return _RotationPassResult(code="rotation_blocked_audit_failure", permanent=True)
        return _RotationPassResult(code="rotation_retry_audit_unavailable", retryable=True)
    if error.code == LocalKeyErrorCode.KEY_NOT_FOUND:
        if backoff.missing_material_failures < _MISSING_MATERIAL_RETRY_LIMIT:
            return _RotationPassResult(code="rotation_retry_missing_material", retryable=True)
        return _RotationPassResult(code="rotation_blocked_missing_material", permanent=True)
    if error.code in _ROTATION_PERMANENT_CODES:
        return _RotationPassResult(code="rotation_blocked_operator", permanent=True)
    if error.code == LocalKeyErrorCode.KEY_UNREADABLE:
        return _RotationPassResult(code="rotation_failed_retrying", retryable=True)
    return _RotationPassResult(code="rotation_dependency_failure", retryable=True)


def _write_supplemental_failure_audit(
    db: Database,
    *,
    instance_id: uuid.UUID,
    candidate: _RotationCandidate,
    result: _RotationPassResult,
    error: LocalKeyError,
) -> bool:
    if result.is_noop or result.code in {"rotation_blocked_audit_failure", "rotation_canceled"}:
        return True
    if error.code in _LIFECYCLE_SELF_AUDITED_CODES:
        return True
    details = {
        "kid": candidate.kid,
        "resultCode": result.code,
        "attemptClassification": "retryable" if result.retryable else "permanent",
        "scheduledAt": candidate.scheduled_at.isoformat(),
        "workerInstanceId": str(instance_id),
    }
    return _safe_worker_audit(
        db,
        action=AuditAction.LOCAL_KEY_ACTIVATION_FAILED,
        target_type=AuditTargetType.SIGNING_KEY,
        target_id=candidate.kid,
        instance_id=instance_id,
        reason=error.code.value,
        details=details,
        outcome=AuditOutcome.FAILED if result.retryable else AuditOutcome.BLOCKED,
    )


def _run_rotation_pass(
    *,
    lifecycle: SigningKeyLifecycleService,
    signing: SigningKeyService,
    db: Database,
    instance_id: uuid.UUID,
    backoff: _RotationBackoffState,
    should_cancel: Callable[[], bool] | None = None,
) -> _RotationPassResult:
    candidate = _next_rotation_candidate(db)
    if candidate is None:
        backoff.reset_for_candidate(None)
        return _RotationPassResult(code="rotation_idle_no_due")
    backoff.reset_for_candidate(candidate.kid)
    if not candidate.due:
        return _RotationPassResult(code="rotation_deferred_not_due", kid=candidate.kid)
    try:
        activation = lifecycle.activate_due_scheduled(
            reason="worker-scheduled-activation",
            actor_id=str(instance_id),
            should_cancel=should_cancel or (lambda: _STOP),
        )
    except LocalKeyError as error:
        result = _classify_rotation_error(error, backoff)
        result = _RotationPassResult(
            code=result.code,
            retryable=result.retryable,
            permanent=result.permanent,
            degraded=result.degraded,
            kid=candidate.kid,
        )
        if error.code != LocalKeyErrorCode.AUDIT_FAILED and not result.is_noop:
            try:
                ok = _write_supplemental_failure_audit(
                    db,
                    instance_id=instance_id,
                    candidate=candidate,
                    result=result,
                    error=error,
                )
            except Exception:
                ok = False
            if not ok:
                return _RotationPassResult(
                    code="rotation_degraded_audit_persist_failure",
                    degraded=True,
                    kid=candidate.kid,
                )
        return result
    if activation is None:
        return _RotationPassResult(code="rotation_no_longer_due", kid=candidate.kid)
    if activation.reason_code == "activation-canceled":
        return _RotationPassResult(code="rotation_canceled", kid=activation.kid)
    if activation.reason_code in {"activated", "already-active"}:
        try:
            signing.ensure_runtime_active_key()
            signing.sign_bytes(b"rotation-worker-readiness-check")
        except LocalKeyError:
            return _RotationPassResult(code="rotation_post_commit_verify_failed", degraded=True, kid=activation.kid)
        return _RotationPassResult(code="rotation_activation_succeeded", kid=activation.kid)
    return _RotationPassResult(code="rotation_no_longer_due", kid=activation.kid)


def _compute_rotation_backoff_seconds(settings: FederationSettings, *, failures: int) -> float:
    exponent = max(failures - 1, 0)
    duration = float(settings.rotation_failure_backoff_min_seconds * (2 ** min(exponent, 10)))
    duration = min(float(settings.rotation_failure_backoff_max_seconds), duration)
    if settings.rotation_backoff_jitter_enabled:
        duration *= random.uniform(0.75, 1.25)
    return min(float(settings.rotation_failure_backoff_max_seconds), max(1.0, duration))


def _advance_rotation_backoff(
    *,
    settings: FederationSettings,
    backoff: _RotationBackoffState,
    result: _RotationPassResult,
    now_monotonic: float,
) -> None:
    if result.activation_succeeded or result.is_noop:
        backoff.consecutive_failures = 0
        backoff.missing_material_failures = 0
        backoff.next_attempt_monotonic = now_monotonic + float(settings.rotation_poll_interval_seconds)
        return
    if result.retryable:
        backoff.consecutive_failures += 1
        if result.code == "rotation_retry_missing_material":
            backoff.missing_material_failures += 1
        delay = _compute_rotation_backoff_seconds(settings, failures=backoff.consecutive_failures)
        backoff.next_attempt_monotonic = now_monotonic + delay
        return
    if result.permanent:
        backoff.consecutive_failures += 1
        if result.code == "rotation_blocked_missing_material":
            backoff.missing_material_failures = _MISSING_MATERIAL_RETRY_LIMIT
        backoff.next_attempt_monotonic = now_monotonic + float(settings.rotation_failure_backoff_max_seconds)
        return
    backoff.next_attempt_monotonic = now_monotonic + float(settings.rotation_poll_interval_seconds)


def _sync_error_class(sync_results: list[tuple[uuid.UUID, object]]) -> str | None:
    statuses: list[str] = []
    for _, item in sync_results:
        status = getattr(item, "status", None)
        if isinstance(status, str):
            statuses.append(status)
    if any(status in {"failed", "partial"} for status in statuses):
        return "sync_failed"
    return None


def _sleep_interruptibly(
    duration_seconds: float,
    *,
    monotonic_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
) -> None:
    if duration_seconds <= 0:
        return
    deadline = monotonic_fn() + duration_seconds
    while not _STOP:
        remaining = deadline - monotonic_fn()
        if remaining <= 0:
            return
        sleep_fn(min(_SLEEP_GRANULARITY_SECONDS, remaining))


def _worker_loop(
    *,
    db: Database,
    settings: FederationSettings,
    instance_id: uuid.UUID,
    hostname: str,
    sync_service: FederationInboundSyncService | None,
    signing_service: SigningKeyService | None,
    rotation_service: SigningKeyLifecycleService | None,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    sync_enabled = sync_service is not None
    rotation_enabled = signing_service is not None and rotation_service is not None and settings.rotation_worker_enabled
    now = monotonic_fn()
    next_sync = now if sync_enabled else float("inf")
    backoff = _RotationBackoffState(next_attempt_monotonic=now if rotation_enabled else float("inf"))

    while not _STOP:
        now = monotonic_fn()
        ran_sync = False
        ran_rotation = False
        sync_error_code: str | None = None
        sync_success = False
        rotation_result = _RotationPassResult(code="rotation_idle_no_due")

        if sync_enabled and now >= next_sync:
            ran_sync = True
            try:
                sync_results = sync_service.sync_all_trusted_peers_once(max_seconds_per_peer=settings.worker_max_sync_seconds)
                sync_error_code = _sync_error_class(sync_results)
                sync_success = sync_error_code is None
            except Exception:
                sync_error_code = "sync_exception"
                sync_success = False
            next_sync = monotonic_fn() + float(settings.worker_interval_seconds)

        if rotation_enabled and now >= backoff.next_attempt_monotonic:
            ran_rotation = True
            try:
                rotation_result = _run_rotation_pass(
                    lifecycle=rotation_service,
                    signing=signing_service,
                    db=db,
                    instance_id=instance_id,
                    backoff=backoff,
                    should_cancel=lambda: _STOP,
                )
            except Exception:
                rotation_result = _RotationPassResult(code="rotation_unexpected_failure", retryable=True)
            _advance_rotation_backoff(
                settings=settings,
                backoff=backoff,
                result=rotation_result,
                now_monotonic=monotonic_fn(),
            )

        if ran_sync or ran_rotation:
            heartbeat_status = WorkerStatus.RUNNING
            last_error_class: str | None = None
            mark_success = sync_success or rotation_result.activation_succeeded

            if sync_error_code:
                heartbeat_status = WorkerStatus.ERROR
                last_error_class = sync_error_code
            elif rotation_result.is_error:
                heartbeat_status = WorkerStatus.ERROR
                last_error_class = rotation_result.code
            elif ran_rotation and rotation_result.is_noop and not sync_success:
                heartbeat_status = WorkerStatus.IDLE
                last_error_class = None

            _safe_heartbeat(
                db,
                instance_id=instance_id,
                hostname=hostname,
                status=heartbeat_status,
                last_error_class=last_error_class,
                mark_success=mark_success,
            )

        next_wake = min(next_sync, backoff.next_attempt_monotonic)
        if next_wake == float("inf"):
            _sleep_interruptibly(1.0, monotonic_fn=monotonic_fn, sleep_fn=sleep_fn)
            continue
        wait_seconds = max(0.0, next_wake - monotonic_fn())
        _sleep_interruptibly(wait_seconds, monotonic_fn=monotonic_fn, sleep_fn=sleep_fn)


def main() -> int:
    global _STOP
    _STOP = False

    settings = FederationSettings.from_env()
    if not settings.enabled or not settings.database_url:
        return 0
    if settings.validation_errors:
        return 2

    run_sync = settings.inbound_enabled
    run_rotation = settings.rotation_worker_enabled
    if not run_sync and not run_rotation:
        return 0

    db = Database.from_url(settings.database_url)
    sync_service = FederationInboundSyncService(db, settings) if run_sync else None
    signing_service = SigningKeyService(db, settings) if run_rotation else None
    rotation_service = (
        SigningKeyLifecycleService(db, signing_service.provider) if signing_service is not None else None
    )
    if signing_service is not None:
        try:
            signing_service.ensure_runtime_active_key()
        except LocalKeyError:
            return 2

    instance_id = _resolve_worker_instance_id(settings)
    hostname = socket.gethostname()

    signal.signal(signal.SIGINT, _mark_stop)
    signal.signal(signal.SIGTERM, _mark_stop)

    _safe_heartbeat(
        db,
        instance_id=instance_id,
        hostname=hostname,
        status=WorkerStatus.RUNNING,
        last_error_class=None,
        mark_success=False,
    )
    _safe_worker_audit(
        db,
        action=AuditAction.WORKER_STARTED,
        target_type=AuditTargetType.WORKER,
        target_id=str(instance_id),
        instance_id=instance_id,
        reason="worker-started",
        details={"workerType": WorkerType.SYNC.value},
        outcome=AuditOutcome.SUCCESS,
    )

    try:
        _worker_loop(
            db=db,
            settings=settings,
            instance_id=instance_id,
            hostname=hostname,
            sync_service=sync_service,
            signing_service=signing_service,
            rotation_service=rotation_service,
        )
    finally:
        _safe_heartbeat(
            db,
            instance_id=instance_id,
            hostname=hostname,
            status=WorkerStatus.STOPPED,
            last_error_class=None,
            mark_success=False,
        )
        _safe_worker_audit(
            db,
            action=AuditAction.WORKER_STOPPED,
            target_type=AuditTargetType.WORKER,
            target_id=str(instance_id),
            instance_id=instance_id,
            reason="worker-stopped",
            details={"workerType": WorkerType.SYNC.value},
            outcome=AuditOutcome.SUCCESS,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
