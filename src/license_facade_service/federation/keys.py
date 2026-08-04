from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select, update

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import FederationSigningKey
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.models import JwkKey, JwksResponse


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _read_secret_file(path: str) -> str:
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"Signing key file not found: {path}")
    return file.read_text(encoding="utf-8")


@dataclass(frozen=True)
class ActiveSigningKey:
    kid: str
    public_x: str


class SigningKeyService:
    def __init__(self, db: Database, settings: FederationSettings) -> None:
        self.db = db
        self.settings = settings

    def _load_private_key(self) -> Ed25519PrivateKey:
        key_text: str | None = None
        if self.settings.signing_key_path:
            key_text = _read_secret_file(self.settings.signing_key_path)
        elif self.settings.signing_key_secret_path:
            key_text = _read_secret_file(self.settings.signing_key_secret_path)
        if not key_text:
            raise ValueError("No signing key configured")

        key = serialization.load_pem_private_key(key_text.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Signing key must be an Ed25519 private key")
        return key

    def load_and_persist_active_key(self) -> ActiveSigningKey:
        if not self.settings.active_kid:
            raise ValueError("FEDERATION_ACTIVE_KID is required")
        private_key = self._load_private_key()
        public_key = private_key.public_key()
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Invalid Ed25519 public key")

        public_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        x = _b64url(public_bytes)
        now = datetime.now(timezone.utc)

        with self.db.transaction() as session:
            session.execute(update(FederationSigningKey).values(is_active=False, status="inactive", updated_at=now))
            row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == self.settings.active_kid)).scalar_one_or_none()
            if row is None:
                row = FederationSigningKey(
                    kid=self.settings.active_kid,
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=x,
                    is_active=True,
                    status="active",
                    valid_from=now,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.alg = "EdDSA"
                row.kty = "OKP"
                row.crv = "Ed25519"
                row.x = x
                row.is_active = True
                row.status = "active"
                if row.valid_from is None:
                    row.valid_from = now
                row.updated_at = now

        return ActiveSigningKey(kid=self.settings.active_kid, public_x=x)

    def jwks(self) -> JwksResponse:
        with self.db.transaction() as session:
            rows = session.execute(select(FederationSigningKey).order_by(FederationSigningKey.created_at)).scalars().all()
            keys = [
                JwkKey(
                    kid=row.kid,
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=row.x,
                    status=row.status,
                    validFrom=row.valid_from,
                    validUntil=row.valid_until,
                )
                for row in rows
            ]
        return JwksResponse(keys=keys)
