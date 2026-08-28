from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text

from src.license_facade_service.db.models.federation import (
    FederationNodeIdentityState,
    FederationSigningKey,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.audit import (
    AuditAction,
    AuditActorType,
    AuditOutcome,
    AuditTargetType,
    write_audit_row_sync,
)

_KID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MAX_REASON_LEN = 1024
_MAX_ACTOR_ID_LEN = 256
_INVALID_IDENTIFIER_AUDIT_TARGET = "invalid-signing-key-identifier"


class LocalKeyState(str, Enum):
    STAGED = "staged"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class LocalKeyErrorCode(str, Enum):
    INVALID_KID = "invalid-kid"
    KEY_NOT_FOUND = "key-not-found"
    KEY_NOT_REGULAR_FILE = "key-not-regular-file"
    KEY_UNREADABLE = "key-unreadable"
    KEY_EMPTY = "key-empty"
    KEY_UNSAFE_PERMISSIONS = "key-unsafe-permissions"
    KEY_PATH_ESCAPE = "key-path-escape"
    KEY_MALFORMED = "key-malformed"
    KEY_NOT_ED25519 = "key-not-ed25519"
    MATERIAL_MISMATCH = "material-mismatch"
    AMBIGUOUS_ACTIVE_KEY = "ambiguous-active-key"
    ACTIVE_KEY_MISSING = "active-key-missing"
    EXPECTED_STATE_MISMATCH = "expected-state-mismatch"
    SCHEDULE_CONFLICT = "schedule-conflict"
    TRANSITION_FORBIDDEN = "transition-forbidden"
    COLLISION = "key-collision"
    SUCCESSOR_REQUIRED = "successor-required"
    AUDIT_FAILED = "audit-failed"
    INVALID_ACTIVATION_TIME = "invalid-activation-time"
    INVALID_REASON = "invalid-reason"
    INVALID_ACTOR_ID = "invalid-actor-id"


class LocalKeyError(RuntimeError):
    def __init__(self, code: LocalKeyErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LoadedPrivateKeyMaterial:
    kid: str
    private_key: Ed25519PrivateKey
    public_x: str
    fingerprint: str


@dataclass(frozen=True)
class LocalKeyLifecycleResult:
    kid: str
    status: LocalKeyState
    reason_code: str
    rotation_scheduled_at: datetime | None = None
    rotated_to_kid: str | None = None


@dataclass(frozen=True)
class LocalKeyInspectionResult:
    kid: str
    public_x: str
    fingerprint: str
    reason_code: str


class PrivateKeyProvider(Protocol):
    def load_private_key(self, kid: str) -> LoadedPrivateKeyMaterial:
        ...


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fingerprint_for_x(x_b64url: str) -> str:
    return hashlib.sha256(b64url_decode(x_b64url)).hexdigest()


def constant_time_x_match(expected_x: str, actual_x: str) -> bool:
    return hmac.compare_digest(expected_x.encode("ascii"), actual_x.encode("ascii"))


def _validate_kid(kid: str) -> None:
    if not kid or not _KID_PATTERN.fullmatch(kid):
        raise LocalKeyError(LocalKeyErrorCode.INVALID_KID, "Signing key identifier is invalid.")
    if any(ch in kid for ch in ("/", "\\", "\x00")):
        raise LocalKeyError(LocalKeyErrorCode.INVALID_KID, "Signing key identifier is invalid.")
    if ".." in kid:
        raise LocalKeyError(LocalKeyErrorCode.INVALID_KID, "Signing key identifier is invalid.")
    if not kid.isascii():
        raise LocalKeyError(LocalKeyErrorCode.INVALID_KID, "Signing key identifier is invalid.")


def _safe_parse_ed25519_pem(*, kid: str, pem_data: bytes) -> LoadedPrivateKeyMaterial:
    if not pem_data:
        raise LocalKeyError(LocalKeyErrorCode.KEY_EMPTY, "Signing key material is empty.")
    try:
        decoded = pem_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalKeyError(LocalKeyErrorCode.KEY_MALFORMED, "Signing key material is malformed.") from exc
    if "BEGIN PRIVATE KEY" not in decoded:
        raise LocalKeyError(LocalKeyErrorCode.KEY_MALFORMED, "Signing key material is malformed.")
    try:
        key = serialization.load_pem_private_key(pem_data, password=None)
    except Exception as exc:
        raise LocalKeyError(LocalKeyErrorCode.KEY_MALFORMED, "Signing key material is malformed.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_ED25519, "Signing key type is not supported.")
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = b64url_encode(public_bytes)
    return LoadedPrivateKeyMaterial(
        kid=kid,
        private_key=key,
        public_x=x,
        fingerprint=hashlib.sha256(public_bytes).hexdigest(),
    )


class DirectoryPrivateKeyProvider:
    def __init__(self, root_dir: str, *, enforce_permissions: bool = True) -> None:
        self._root_dir = Path(root_dir)
        self._enforce_permissions = enforce_permissions

    def _resolved_root(self) -> Path:
        try:
            root = self._root_dir.resolve(strict=True)
        except FileNotFoundError as exc:
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key material is unavailable.") from exc
        if not root.is_dir():
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key material is unavailable.")
        return root

    def _enforce_file_permissions(self, path: Path) -> None:
        if not self._enforce_permissions:
            return
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise LocalKeyError(
                LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
                "Signing key material has unsafe file permissions.",
            )

    def load_private_key(self, kid: str) -> LoadedPrivateKeyMaterial:
        _validate_kid(kid)
        root = self._resolved_root()
        candidate = root / f"{kid}.pem"
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key material is unavailable.") from exc
        if not resolved.is_relative_to(root):
            raise LocalKeyError(LocalKeyErrorCode.KEY_PATH_ESCAPE, "Signing key material is unavailable.")
        if not resolved.is_file():
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_REGULAR_FILE, "Signing key material is unavailable.")
        if not os.access(resolved, os.R_OK):
            raise LocalKeyError(LocalKeyErrorCode.KEY_UNREADABLE, "Signing key material is unavailable.")
        self._enforce_file_permissions(resolved)
        try:
            content = resolved.read_bytes()
        except OSError as exc:
            raise LocalKeyError(LocalKeyErrorCode.KEY_UNREADABLE, "Signing key material is unavailable.") from exc
        return _safe_parse_ed25519_pem(kid=kid, pem_data=content)


class SingleFilePrivateKeyProvider:
    """Bootstrap-only compatibility provider for legacy single-file key config."""

    def __init__(self, *, key_file: str, bootstrap_kid: str, enforce_permissions: bool = True) -> None:
        self._key_file = Path(key_file)
        self._bootstrap_kid = bootstrap_kid
        self._enforce_permissions = enforce_permissions

    def _enforce_file_permissions(self, path: Path) -> None:
        if not self._enforce_permissions:
            return
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise LocalKeyError(
                LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
                "Signing key material has unsafe file permissions.",
            )

    def load_private_key(self, kid: str) -> LoadedPrivateKeyMaterial:
        _validate_kid(kid)
        if kid != self._bootstrap_kid:
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key material is unavailable.")
        if self._key_file.is_symlink():
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_REGULAR_FILE, "Signing key material is unavailable.")
        try:
            resolved = self._key_file.resolve(strict=True)
        except FileNotFoundError as exc:
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key material is unavailable.") from exc
        if not resolved.is_file():
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_REGULAR_FILE, "Signing key material is unavailable.")
        if not os.access(resolved, os.R_OK):
            raise LocalKeyError(LocalKeyErrorCode.KEY_UNREADABLE, "Signing key material is unavailable.")
        self._enforce_file_permissions(resolved)
        try:
            content = resolved.read_bytes()
        except OSError as exc:
            raise LocalKeyError(LocalKeyErrorCode.KEY_UNREADABLE, "Signing key material is unavailable.") from exc
        if not content:
            raise LocalKeyError(LocalKeyErrorCode.KEY_EMPTY, "Signing key material is empty.")
        return _safe_parse_ed25519_pem(kid=kid, pem_data=content)


class SigningKeyLifecycleService:
    def __init__(self, db: Database, provider: PrivateKeyProvider) -> None:
        self.db = db
        self.provider = provider

    def inspect_candidate(self, *, kid: str, reason: str, actor_id: str | None = None) -> LocalKeyInspectionResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_INSPECT,
            actor_id=actor_value,
        )
        try:
            material = self.provider.load_private_key(validated_kid)
        except LocalKeyError as exc:
            self._audit_provider_failure_for_operation(
                action=AuditAction.LOCAL_KEY_INSPECT,
                target_id=validated_kid,
                actor_id=actor_value,
                error_code=exc.code,
            )
            raise
        self._audit_sync(
            session=None,
            action=AuditAction.LOCAL_KEY_INSPECT,
            target_id=validated_kid,
            outcome=AuditOutcome.SUCCESS,
            actor_id=actor_value,
            reason=reason_value,
            details={
                "kid": validated_kid,
                "fingerprintSha256": material.fingerprint,
                "reasonCode": "inspected",
            },
        )
        return LocalKeyInspectionResult(
            kid=material.kid,
            public_x=material.public_x,
            fingerprint=material.fingerprint,
            reason_code="inspected",
        )

    def stage_candidate(
        self,
        *,
        kid: str,
        reason: str,
        expected_state: LocalKeyState | None = None,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_STAGE,
            actor_id=actor_value,
        )
        try:
            material = self.provider.load_private_key(validated_kid)
        except LocalKeyError as exc:
            self._audit_provider_failure_for_operation(
                action=AuditAction.LOCAL_KEY_STAGE,
                target_id=validated_kid,
                actor_id=actor_value,
                error_code=exc.code,
            )
            raise
        try:
            with self.db.transaction() as session:
                row = session.execute(
                    select(FederationSigningKey).where(FederationSigningKey.kid == validated_kid).with_for_update()
                ).scalar_one_or_none()
                if row is None:
                    now = session.execute(text("SELECT now()")).scalar_one()
                    row = FederationSigningKey(
                        id=uuid.uuid4(),
                        kid=validated_kid,
                        alg="EdDSA",
                        kty="OKP",
                        crv="Ed25519",
                        x=material.public_x,
                        is_active=False,
                        status=LocalKeyState.STAGED.value,
                        valid_from=now,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                    outcome_code = "staged-created"
                else:
                    if expected_state is not None and row.status != expected_state.value:
                        raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
                    if not constant_time_x_match(row.x, material.public_x):
                        raise LocalKeyError(LocalKeyErrorCode.COLLISION, "Signing key public material does not match existing key identifier.")
                    if row.status == LocalKeyState.STAGED.value:
                        outcome_code = "staged-idempotent"
                    elif row.status == LocalKeyState.ACTIVE.value:
                        raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Active keys cannot be staged.")
                    elif row.status == LocalKeyState.RETIRED.value:
                        raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Retired keys cannot be staged.")
                    elif row.status == LocalKeyState.REVOKED.value:
                        raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Revoked keys cannot be staged.")
                    else:
                        raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Current key state cannot be staged.")
                self._audit_sync(
                    session=session,
                    action=AuditAction.LOCAL_KEY_STAGE,
                    target_id=validated_kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_value,
                    reason=reason_value,
                    details={"kid": validated_kid, "fingerprintSha256": material.fingerprint, "outcomeCode": outcome_code},
                )
                return LocalKeyLifecycleResult(kid=validated_kid, status=LocalKeyState.STAGED, reason_code=outcome_code)
        except LocalKeyError as exc:
            if exc.code == LocalKeyErrorCode.COLLISION:
                self._audit_failure(
                    action=AuditAction.LOCAL_KEY_MATERIAL_MISMATCH,
                    target_id=validated_kid,
                    actor_id=actor_value,
                    reason_code=exc.code.value,
                    details={"kid": validated_kid, "reasonCode": exc.code.value},
                    outcome=AuditOutcome.REJECTED,
                )
            elif exc.code in {LocalKeyErrorCode.TRANSITION_FORBIDDEN, LocalKeyErrorCode.EXPECTED_STATE_MISMATCH}:
                self._audit_failure(
                    action=AuditAction.LOCAL_KEY_STAGE,
                    target_id=validated_kid,
                    actor_id=actor_value,
                    reason_code=exc.code.value,
                    details={"kid": validated_kid, "reasonCode": exc.code.value},
                    outcome=AuditOutcome.REJECTED,
                )
            raise

    def schedule_activation(
        self,
        *,
        kid: str,
        activate_at: datetime,
        reason: str,
        expected_state: LocalKeyState = LocalKeyState.STAGED,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_SCHEDULE,
            actor_id=actor_value,
        )
        if activate_at.tzinfo is None or activate_at.utcoffset() is None:
            raise LocalKeyError(LocalKeyErrorCode.INVALID_ACTIVATION_TIME, "activation timestamp must include timezone information.")
        with self.db.transaction() as session:
            row = session.execute(
                select(FederationSigningKey).where(FederationSigningKey.kid == validated_kid).with_for_update()
            ).scalar_one_or_none()
            if row is None:
                raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
            if row.status != expected_state.value:
                raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
            now = session.execute(text("SELECT now()")).scalar_one()
            if row.rotation_scheduled_at == activate_at:
                self._audit_sync(
                    session=session,
                    action=AuditAction.LOCAL_KEY_SCHEDULE,
                    target_id=validated_kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_value,
                    reason=reason_value,
                    details={"kid": validated_kid, "activateAt": activate_at.isoformat(), "outcomeCode": "scheduled-idempotent"},
                )
                return LocalKeyLifecycleResult(
                    kid=validated_kid,
                    status=LocalKeyState.STAGED,
                    reason_code="scheduled-idempotent",
                    rotation_scheduled_at=row.rotation_scheduled_at,
                )
            already = session.execute(
                select(FederationSigningKey.kid).where(
                    FederationSigningKey.rotation_scheduled_at.is_not(None),
                    FederationSigningKey.kid != validated_kid,
                ).with_for_update()
            ).first()
            if already is not None:
                raise LocalKeyError(LocalKeyErrorCode.SCHEDULE_CONFLICT, "Another key already has a scheduled activation.")
            row.rotation_scheduled_at = activate_at
            row.updated_at = now
            outcome_code = "scheduled"
            if activate_at <= now:
                outcome_code = "scheduled-immediate"
            self._audit_sync(
                session=session,
                action=AuditAction.LOCAL_KEY_SCHEDULE,
                target_id=validated_kid,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor_value,
                reason=reason_value,
                details={"kid": validated_kid, "activateAt": activate_at.isoformat(), "outcomeCode": outcome_code},
            )
            return LocalKeyLifecycleResult(
                kid=validated_kid,
                status=LocalKeyState.STAGED,
                reason_code=outcome_code,
                rotation_scheduled_at=row.rotation_scheduled_at,
            )

    def cancel_schedule(
        self,
        *,
        kid: str,
        reason: str,
        expected_state: LocalKeyState = LocalKeyState.STAGED,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_SCHEDULE_CANCEL,
            actor_id=actor_value,
        )
        with self.db.transaction() as session:
            row = session.execute(
                select(FederationSigningKey).where(FederationSigningKey.kid == validated_kid).with_for_update()
            ).scalar_one_or_none()
            if row is None:
                raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
            if row.status != expected_state.value:
                raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
            was_scheduled = row.rotation_scheduled_at is not None
            row.rotation_scheduled_at = None
            row.updated_at = session.execute(text("SELECT now()")).scalar_one()
            outcome_code = "schedule-cancelled" if was_scheduled else "schedule-already-unscheduled"
            self._audit_sync(
                session=session,
                action=AuditAction.LOCAL_KEY_SCHEDULE_CANCEL,
                target_id=validated_kid,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor_value,
                reason=reason_value,
                details={"kid": validated_kid, "reasonCode": outcome_code},
            )
            return LocalKeyLifecycleResult(kid=validated_kid, status=LocalKeyState.STAGED, reason_code=outcome_code)

    def activate_staged_key(
        self,
        *,
        kid: str,
        reason: str,
        expected_state: LocalKeyState = LocalKeyState.STAGED,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_ACTIVATION_FAILED,
            actor_id=actor_value,
        )
        try:
            material = self.provider.load_private_key(validated_kid)
            return self._activate_material(
                material=material,
                reason=reason_value,
                expected_state=expected_state,
                actor_id=actor_value,
                required_due_schedule=False,
            )
        except LocalKeyError as exc:
            self._audit_activation_failure(kid=validated_kid, actor_id=actor_value, error_code=exc.code)
            raise

    def activate_due_scheduled(
        self,
        *,
        reason: str,
        actor_id: str | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> LocalKeyLifecycleResult | None:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        with self.db.transaction() as session:
            now = session.execute(text("SELECT now()")).scalar_one()
            candidate = session.execute(
                select(FederationSigningKey.kid)
                .where(
                    FederationSigningKey.status == LocalKeyState.STAGED.value,
                    FederationSigningKey.rotation_scheduled_at.is_not(None),
                    FederationSigningKey.rotation_scheduled_at <= now,
                )
                .order_by(FederationSigningKey.rotation_scheduled_at.asc(), FederationSigningKey.kid.asc())
                .limit(1)
            ).scalar_one_or_none()
        if candidate is None:
            return None
        try:
            material = self.provider.load_private_key(candidate)
            if should_cancel is not None and should_cancel():
                return LocalKeyLifecycleResult(
                    kid=candidate,
                    status=LocalKeyState.STAGED,
                    reason_code="activation-canceled",
                )
            return self._activate_material(
                material=material,
                reason=reason_value,
                expected_state=LocalKeyState.STAGED,
                actor_id=actor_value,
                required_due_schedule=True,
            )
        except LocalKeyError as exc:
            self._audit_activation_failure(kid=candidate, actor_id=actor_value, error_code=exc.code)
            raise

    def retire_staged_key(
        self,
        *,
        kid: str,
        reason: str,
        expected_state: LocalKeyState | None = None,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_kid = self._validate_kid_with_safe_audit(
            kid,
            action=AuditAction.LOCAL_KEY_RETIRE,
            actor_id=actor_value,
        )
        with self.db.transaction() as session:
            row = session.execute(
                select(FederationSigningKey).where(FederationSigningKey.kid == validated_kid).with_for_update()
            ).scalar_one_or_none()
            if row is None:
                raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
            if expected_state and row.status != expected_state.value:
                raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
            if row.status == LocalKeyState.ACTIVE.value:
                raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Active key can only retire during successor activation.")
            if row.status == LocalKeyState.REVOKED.value:
                raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Revoked key cannot be retired.")
            if row.status == LocalKeyState.RETIRED.value:
                self._audit_sync(
                    session=session,
                    action=AuditAction.LOCAL_KEY_RETIRE,
                    target_id=validated_kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_value,
                    reason=reason_value,
                    details={"kid": validated_kid, "reasonCode": "already-retired"},
                )
                return LocalKeyLifecycleResult(kid=validated_kid, status=LocalKeyState.RETIRED, reason_code="already-retired")
            row.status = LocalKeyState.RETIRED.value
            row.is_active = False
            row.rotation_scheduled_at = None
            row.updated_at = session.execute(text("SELECT now()")).scalar_one()
            self._audit_sync(
                session=session,
                action=AuditAction.LOCAL_KEY_RETIRE,
                target_id=validated_kid,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor_value,
                reason=reason_value,
                details={"kid": validated_kid, "fromState": LocalKeyState.STAGED.value, "toState": LocalKeyState.RETIRED.value},
            )
            return LocalKeyLifecycleResult(kid=validated_kid, status=LocalKeyState.RETIRED, reason_code="retired")

    def emergency_revoke_with_successor(
        self,
        *,
        active_kid: str,
        successor_kid: str,
        reason: str,
        expected_active_state: LocalKeyState = LocalKeyState.ACTIVE,
        expected_successor_state: LocalKeyState = LocalKeyState.STAGED,
        actor_id: str | None = None,
    ) -> LocalKeyLifecycleResult:
        reason_value = self._validate_reason(reason)
        actor_value = self._validate_actor_id(actor_id)
        validated_active_kid = self._validate_kid_with_safe_audit(
            active_kid,
            action=AuditAction.LOCAL_KEY_REVOKE,
            actor_id=actor_value,
        )
        validated_successor_kid = self._validate_kid_with_safe_audit(
            successor_kid,
            action=AuditAction.LOCAL_KEY_ACTIVATION_FAILED,
            actor_id=actor_value,
        )
        try:
            successor_material = self.provider.load_private_key(validated_successor_kid)
        except LocalKeyError as exc:
            self._audit_activation_failure(kid=validated_successor_kid, actor_id=actor_value, error_code=exc.code)
            raise
        try:
            with self.db.transaction() as session:
                identity = session.execute(
                    select(FederationNodeIdentityState).where(FederationNodeIdentityState.id == 1).with_for_update()
                ).scalar_one()
                _ = identity
                active = session.execute(
                    select(FederationSigningKey).where(FederationSigningKey.kid == validated_active_kid).with_for_update()
                ).scalar_one_or_none()
                successor = session.execute(
                    select(FederationSigningKey).where(FederationSigningKey.kid == validated_successor_kid).with_for_update()
                ).scalar_one_or_none()
                if active is None or successor is None:
                    raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
                if active.status != expected_active_state.value:
                    raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
                if successor.status != expected_successor_state.value:
                    raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
                if active.status != LocalKeyState.ACTIVE.value:
                    raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Only the active key can be emergency revoked.")
                if successor.status != LocalKeyState.STAGED.value:
                    raise LocalKeyError(LocalKeyErrorCode.SUCCESSOR_REQUIRED, "Emergency revocation requires a staged successor.")
                if not constant_time_x_match(successor.x, successor_material.public_x):
                    raise LocalKeyError(LocalKeyErrorCode.MATERIAL_MISMATCH, "Successor key material does not match staged public key.")
                now = session.execute(text("SELECT now()")).scalar_one()
                active.status = LocalKeyState.REVOKED.value
                active.is_active = False
                active.rotation_scheduled_at = None
                active.rotated_to_kid = successor.kid
                active.valid_until = now
                active.updated_at = now
                session.flush()
                successor.status = LocalKeyState.ACTIVE.value
                successor.is_active = True
                successor.rotation_scheduled_at = None
                successor.valid_from = now
                successor.updated_at = now
                self._audit_sync(
                    session=session,
                    action=AuditAction.LOCAL_KEY_REVOKE,
                    target_id=active.kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_value,
                    reason=reason_value,
                    details={
                        "kid": active.kid,
                        "previousKid": active.kid,
                        "successorKid": successor.kid,
                        "fromState": LocalKeyState.ACTIVE.value,
                        "toState": LocalKeyState.REVOKED.value,
                        "reasonCode": "emergency-successor-activation",
                    },
                )
                self._audit_sync(
                    session=session,
                    action=AuditAction.LOCAL_KEY_ACTIVATE,
                    target_id=successor.kid,
                    outcome=AuditOutcome.SUCCESS,
                    actor_id=actor_value,
                    reason=reason_value,
                    details={
                        "kid": successor.kid,
                        "previousKid": active.kid,
                        "successorKid": successor.kid,
                        "fromState": LocalKeyState.STAGED.value,
                        "toState": LocalKeyState.ACTIVE.value,
                        "reasonCode": "emergency-successor-activation",
                    },
                )
                return LocalKeyLifecycleResult(
                    kid=active.kid,
                    status=LocalKeyState.REVOKED,
                    reason_code="revoked-with-successor",
                    rotated_to_kid=successor.kid,
                )
        except LocalKeyError as exc:
            if exc.code == LocalKeyErrorCode.MATERIAL_MISMATCH:
                self._audit_failure(
                    action=AuditAction.LOCAL_KEY_MATERIAL_MISMATCH,
                    target_id=validated_successor_kid,
                    actor_id=actor_value,
                    reason_code=exc.code.value,
                    details={"kid": validated_successor_kid, "reasonCode": exc.code.value},
                    outcome=AuditOutcome.REJECTED,
                )
            raise

    def _activate_material(
        self,
        *,
        material: LoadedPrivateKeyMaterial,
        reason: str,
        expected_state: LocalKeyState,
        actor_id: str | None,
        required_due_schedule: bool,
    ) -> LocalKeyLifecycleResult:
        with self.db.transaction() as session:
            _identity = session.execute(
                select(FederationNodeIdentityState).where(FederationNodeIdentityState.id == 1).with_for_update()
            ).scalar_one()
            _ = _identity
            candidate = session.execute(
                select(FederationSigningKey).where(FederationSigningKey.kid == material.kid).with_for_update()
            ).scalar_one_or_none()
            if candidate is None:
                raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
            if candidate.status != expected_state.value:
                raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Current key state does not match expected state.")
            now = session.execute(text("SELECT now()")).scalar_one()
            if required_due_schedule:
                if candidate.rotation_scheduled_at is None or candidate.rotation_scheduled_at > now:
                    raise LocalKeyError(LocalKeyErrorCode.EXPECTED_STATE_MISMATCH, "Key is no longer due for scheduled activation.")
                scheduled_count = session.execute(
                    select(text("count(*)")).select_from(FederationSigningKey).where(FederationSigningKey.rotation_scheduled_at.is_not(None))
                ).scalar_one()
                if int(scheduled_count) > 1:
                    raise LocalKeyError(LocalKeyErrorCode.SCHEDULE_CONFLICT, "Scheduled activation state is inconsistent.")
            if not constant_time_x_match(candidate.x, material.public_x):
                raise LocalKeyError(LocalKeyErrorCode.MATERIAL_MISMATCH, "Signing key material does not match staged public key.")
            active = session.execute(
                select(FederationSigningKey)
                .where(FederationSigningKey.status == LocalKeyState.ACTIVE.value, FederationSigningKey.is_active.is_(True))
                .with_for_update()
            ).scalar_one_or_none()
            if active is None:
                raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "Activation requires an existing active key.")
            if active.kid == candidate.kid:
                return LocalKeyLifecycleResult(kid=candidate.kid, status=LocalKeyState.ACTIVE, reason_code="already-active")
            active.status = LocalKeyState.RETIRED.value
            active.is_active = False
            active.rotation_scheduled_at = None
            active.rotated_to_kid = candidate.kid
            active.valid_until = now
            active.updated_at = now
            session.flush()
            candidate.status = LocalKeyState.ACTIVE.value
            candidate.is_active = True
            candidate.rotation_scheduled_at = None
            candidate.valid_from = now
            candidate.updated_at = now
            self._audit_sync(
                session=session,
                action=AuditAction.LOCAL_KEY_ACTIVATE,
                target_id=candidate.kid,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor_id,
                reason=reason,
                details={
                    "kid": candidate.kid,
                    "previousKid": active.kid,
                    "successorKid": candidate.kid,
                    "fromState": LocalKeyState.STAGED.value,
                    "toState": LocalKeyState.ACTIVE.value,
                    "reasonCode": "activation",
                },
            )
            return LocalKeyLifecycleResult(kid=candidate.kid, status=LocalKeyState.ACTIVE, reason_code="activated")

    def _audit_activation_failure(
        self,
        *,
        kid: str,
        actor_id: str | None,
        error_code: LocalKeyErrorCode,
    ) -> None:
        if error_code == LocalKeyErrorCode.MATERIAL_MISMATCH:
            self._audit_failure(
                action=AuditAction.LOCAL_KEY_MATERIAL_MISMATCH,
                target_id=kid,
                actor_id=actor_id,
                reason_code=error_code.value,
                details={"kid": kid, "reasonCode": error_code.value},
                outcome=AuditOutcome.REJECTED,
            )
            return
        if error_code in {
            LocalKeyErrorCode.KEY_NOT_FOUND,
            LocalKeyErrorCode.KEY_NOT_REGULAR_FILE,
            LocalKeyErrorCode.KEY_UNREADABLE,
            LocalKeyErrorCode.KEY_EMPTY,
            LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
            LocalKeyErrorCode.KEY_PATH_ESCAPE,
            LocalKeyErrorCode.KEY_MALFORMED,
            LocalKeyErrorCode.KEY_NOT_ED25519,
            LocalKeyErrorCode.INVALID_KID,
        }:
            self._audit_failure(
                action=AuditAction.LOCAL_KEY_ACTIVATION_FAILED,
                target_id=kid,
                actor_id=actor_id,
                reason_code=error_code.value,
                details={"kid": kid, "reasonCode": error_code.value},
                outcome=AuditOutcome.REJECTED,
            )

    def _validate_reason(self, reason: str) -> str:
        trimmed = reason.strip()
        if not trimmed:
            raise LocalKeyError(LocalKeyErrorCode.INVALID_REASON, "Operation reason is required.")
        if len(trimmed) > _MAX_REASON_LEN:
            raise LocalKeyError(
                LocalKeyErrorCode.INVALID_REASON,
                f"Operation reason exceeds {_MAX_REASON_LEN} characters.",
            )
        return trimmed

    def _validate_actor_id(self, actor_id: str | None) -> str | None:
        if actor_id is None:
            return None
        trimmed = actor_id.strip()
        if not trimmed:
            raise LocalKeyError(LocalKeyErrorCode.INVALID_ACTOR_ID, "Actor identifier is invalid.")
        if len(trimmed) > _MAX_ACTOR_ID_LEN:
            raise LocalKeyError(
                LocalKeyErrorCode.INVALID_ACTOR_ID,
                f"Actor identifier exceeds {_MAX_ACTOR_ID_LEN} characters.",
            )
        return trimmed

    def _validate_kid_with_safe_audit(
        self,
        kid: str,
        *,
        action: AuditAction,
        actor_id: str | None,
    ) -> str:
        try:
            _validate_kid(kid)
            return kid
        except LocalKeyError as exc:
            if exc.code != LocalKeyErrorCode.INVALID_KID:
                raise
            self._audit_failure(
                action=action,
                target_id=_INVALID_IDENTIFIER_AUDIT_TARGET,
                actor_id=actor_id,
                reason_code=exc.code.value,
                details={"reasonCode": exc.code.value},
                outcome=AuditOutcome.REJECTED,
            )
            raise

    def _audit_provider_failure_for_operation(
        self,
        *,
        action: AuditAction,
        target_id: str,
        actor_id: str | None,
        error_code: LocalKeyErrorCode,
    ) -> None:
        self._audit_failure(
            action=action,
            target_id=target_id,
            actor_id=actor_id,
            reason_code=error_code.value,
            details={"kid": target_id, "reasonCode": error_code.value},
            outcome=AuditOutcome.REJECTED,
        )

    def _audit_failure(
        self,
        *,
        action: AuditAction,
        target_id: str,
        actor_id: str | None,
        reason_code: str,
        details: dict[str, str],
        outcome: AuditOutcome,
    ) -> None:
        self._audit_sync(
            session=None,
            action=action,
            target_id=target_id,
            outcome=outcome,
            actor_id=actor_id,
            reason=reason_code,
            details=details,
        )

    def _audit_sync(
        self,
        *,
        session,
        action: AuditAction,
        target_id: str,
        outcome: AuditOutcome,
        actor_id: str | None,
        reason: str,
        details: dict[str, str],
    ) -> None:
        try:
            if session is None:
                with self.db.transaction() as local_session:
                    write_audit_row_sync(
                        local_session,
                        actor_type=AuditActorType.HUMAN_OPERATOR if actor_id else AuditActorType.SYSTEM,
                        action=action,
                        target_type=AuditTargetType.SIGNING_KEY,
                        target_id=target_id,
                        outcome=outcome,
                        actor_id=actor_id,
                        reason=reason,
                        details=details,
                    )
                return
            write_audit_row_sync(
                session,
                actor_type=AuditActorType.HUMAN_OPERATOR if actor_id else AuditActorType.SYSTEM,
                action=action,
                target_type=AuditTargetType.SIGNING_KEY,
                target_id=target_id,
                outcome=outcome,
                actor_id=actor_id,
                reason=reason,
                details=details,
            )
        except Exception as exc:
            raise LocalKeyError(LocalKeyErrorCode.AUDIT_FAILED, "Operational audit write failed.") from exc
