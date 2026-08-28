from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import case, select, text
from sqlalchemy.orm import Session

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationNodeIdentityState,
    FederationSigningKey,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.local_key_lifecycle import (
    DirectoryPrivateKeyProvider,
    LoadedPrivateKeyMaterial,
    LocalKeyError,
    LocalKeyErrorCode,
    LocalKeyState,
    PrivateKeyProvider,
    SingleFilePrivateKeyProvider,
    b64url_decode,
    constant_time_x_match,
)
from src.license_facade_service.federation.models import JwkKey, JwksResponse, SignatureEnvelope


@dataclass(frozen=True)
class ActiveSigningKey:
    kid: str
    public_x: str


@dataclass(frozen=True)
class _ActiveSnapshot:
    id: uuid.UUID
    kid: str
    x: str
    status: str
    is_active: bool
    updated_at: datetime


def _same_snapshot(first: _ActiveSnapshot, second: _ActiveSnapshot) -> bool:
    return (
        first.id == second.id
        and first.kid == second.kid
        and hmac.compare_digest(first.x.encode("ascii"), second.x.encode("ascii"))
        and first.status == second.status
        and first.is_active == second.is_active
        and first.updated_at == second.updated_at
    )


class SigningKeyService:
    def __init__(self, db: Database, settings: FederationSettings, *, provider: PrivateKeyProvider | None = None) -> None:
        self.db = db
        self.settings = settings
        self.provider = provider or self._build_provider()

    def _build_provider(self) -> PrivateKeyProvider:
        if self.settings.signing_key_dir:
            return DirectoryPrivateKeyProvider(
                self.settings.signing_key_dir,
                enforce_permissions=self.settings.signing_key_enforce_permissions,
            )
        key_file = self.settings.signing_key_path or self.settings.signing_key_secret_path
        if key_file and self.settings.active_kid:
            return SingleFilePrivateKeyProvider(
                key_file=key_file,
                bootstrap_kid=self.settings.active_kid,
                enforce_permissions=self.settings.signing_key_enforce_permissions,
            )
        raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "Signing key configuration is incomplete.")

    def _query_active_rows(self, session: Session) -> list[FederationSigningKey]:
        return (
            session.execute(
                select(FederationSigningKey)
                .where(
                    FederationSigningKey.status == LocalKeyState.ACTIVE.value,
                    FederationSigningKey.is_active.is_(True),
                )
                .order_by(
                    FederationSigningKey.updated_at.desc(),
                    FederationSigningKey.created_at.desc(),
                    FederationSigningKey.kid.asc(),
                )
                .limit(2)
            )
            .scalars()
            .all()
        )

    def _load_exact_active(self, session: Session) -> FederationSigningKey | None:
        rows = self._query_active_rows(session)
        if not rows:
            return None
        if len(rows) > 1:
            raise LocalKeyError(LocalKeyErrorCode.AMBIGUOUS_ACTIVE_KEY, "Signing key state is inconsistent.")
        return rows[0]

    def _load_material_for_row(self, row: FederationSigningKey) -> LoadedPrivateKeyMaterial:
        material = self.provider.load_private_key(row.kid)
        if not constant_time_x_match(row.x, material.public_x):
            raise LocalKeyError(LocalKeyErrorCode.MATERIAL_MISMATCH, "Signing key material does not match active public key.")
        return material

    def _active_snapshot(self) -> _ActiveSnapshot:
        with self.db.transaction() as session:
            row = self._load_exact_active(session)
            if row is None:
                raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "No active signing key is available.")
            return _ActiveSnapshot(
                id=row.id,
                kid=row.kid,
                x=row.x,
                status=row.status,
                is_active=row.is_active,
                updated_at=row.updated_at,
            )

    def _bootstrap_when_missing(self) -> None:
        if not self.settings.active_kid:
            raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "No active signing key is available.")
        material = self.provider.load_private_key(self.settings.active_kid)
        with self.db.transaction() as session:
            _identity = session.execute(
                select(FederationNodeIdentityState).where(FederationNodeIdentityState.id == 1).with_for_update()
            ).scalar_one()
            _ = _identity
            active = self._load_exact_active(session)
            if active is not None:
                return
            row = session.execute(
                select(FederationSigningKey).where(FederationSigningKey.kid == self.settings.active_kid).with_for_update()
            ).scalar_one_or_none()
            now = session.execute(text("SELECT now()")).scalar_one()
            if row is None:
                row = FederationSigningKey(
                    id=uuid.uuid4(),
                    kid=self.settings.active_kid,
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=material.public_x,
                    is_active=True,
                    status=LocalKeyState.ACTIVE.value,
                    valid_from=now,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
                return
            if row.status == LocalKeyState.REVOKED.value:
                raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Revoked key cannot be activated by bootstrap.")
            if row.status == LocalKeyState.RETIRED.value:
                raise LocalKeyError(LocalKeyErrorCode.TRANSITION_FORBIDDEN, "Retired key cannot be activated by bootstrap.")
            if not constant_time_x_match(row.x, material.public_x):
                raise LocalKeyError(LocalKeyErrorCode.COLLISION, "Signing key public material mismatch for configured key identifier.")
            row.status = LocalKeyState.ACTIVE.value
            row.is_active = True
            row.rotation_scheduled_at = None
            if row.valid_from is None:
                row.valid_from = now
            row.updated_at = now

    def ensure_runtime_active_key(self) -> ActiveSigningKey:
        with self.db.transaction() as session:
            active = self._load_exact_active(session)
        if active is None:
            self._bootstrap_when_missing()
            with self.db.transaction() as session:
                active = self._load_exact_active(session)
        if active is None:
            raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "No active signing key is available.")
        self._load_material_for_row(active)
        return ActiveSigningKey(kid=active.kid, public_x=active.x)

    def load_and_persist_active_key(self) -> ActiveSigningKey:
        # Backward-compatible method name used by runtime/tests.
        return self.ensure_runtime_active_key()

    def get_active_kid(self) -> str:
        with self.db.transaction() as session:
            active = self._load_exact_active(session)
        if active is None:
            raise LocalKeyError(LocalKeyErrorCode.ACTIVE_KEY_MISSING, "No active signing key is available.")
        return active.kid

    def sign_bytes(self, payload: bytes) -> SignatureEnvelope:
        for _ in range(2):
            before = self._active_snapshot()
            material = self.provider.load_private_key(before.kid)
            if not constant_time_x_match(before.x, material.public_x):
                raise LocalKeyError(LocalKeyErrorCode.MATERIAL_MISMATCH, "Signing key material does not match active public key.")
            signature = material.private_key.sign(payload)
            after = self._active_snapshot()
            if _same_snapshot(before, after):
                from src.license_facade_service.federation.local_key_lifecycle import b64url_encode

                return SignatureEnvelope(kid=before.kid, value=b64url_encode(signature))
        raise LocalKeyError(LocalKeyErrorCode.MATERIAL_MISMATCH, "Signing key changed during signing; retry later.")

    def verify_bytes(self, payload: bytes, *, signature_b64url: str, kid: str) -> bool:
        with self.db.transaction() as session:
            row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == kid)).scalar_one_or_none()
        if row is None:
            return False
        try:
            public_bytes = b64url_decode(row.x)
            key = Ed25519PublicKey.from_public_bytes(public_bytes)
            key.verify(b64url_decode(signature_b64url), payload)
            return True
        except Exception:
            return False

    def jwks(self) -> JwksResponse:
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationSigningKey)
                    .where(
                        FederationSigningKey.status.in_(
                            [LocalKeyState.STAGED.value, LocalKeyState.ACTIVE.value, LocalKeyState.RETIRED.value]
                        )
                    )
                    .order_by(
                        case(
                            (FederationSigningKey.status == LocalKeyState.ACTIVE.value, 1),
                            (FederationSigningKey.status == LocalKeyState.STAGED.value, 2),
                            else_=3,
                        ),
                        FederationSigningKey.created_at.asc(),
                        FederationSigningKey.kid.asc(),
                    )
                )
                .scalars()
                .all()
            )
        return JwksResponse(
            keys=[
                JwkKey(
                    kid=row.kid,
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=row.x,
                )
                for row in rows
            ]
        )
