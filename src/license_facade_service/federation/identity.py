from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import FederationNodeIdentityState
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.digests import canonical_json_sha256_hex


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    public_base_url: str
    node_name: str
    operator_name: str
    config_fingerprint: str


def identity_fingerprint(settings: FederationSettings) -> str:
    payload: dict[str, Any] = {
        "node_id": settings.node_id,
        "public_base_url": settings.public_base_url,
        "node_name": settings.node_name,
        "operator_name": settings.operator_name,
    }
    return canonical_json_sha256_hex(payload)


class NodeIdentityService:
    def __init__(self, db: Database, settings: FederationSettings) -> None:
        self.db = db
        self.settings = settings

    def ensure_identity_state(self) -> NodeIdentity:
        assert self.settings.node_id is not None
        assert self.settings.public_base_url is not None
        assert self.settings.node_name is not None
        assert self.settings.operator_name is not None
        fingerprint = identity_fingerprint(self.settings)
        now = datetime.now(timezone.utc)

        with self.db.transaction() as session:
            row = session.execute(
                select(FederationNodeIdentityState).where(FederationNodeIdentityState.id == 1)
            ).scalar_one_or_none()
            if row is None:
                row = FederationNodeIdentityState(
                    id=1,
                    node_id=self.settings.node_id,
                    public_base_url=self.settings.public_base_url,
                    node_name=self.settings.node_name,
                    operator_name=self.settings.operator_name,
                    config_fingerprint=fingerprint,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            elif row.config_fingerprint != fingerprint:
                raise ValueError(
                    "Federation identity configuration changed after persisted publication state. "
                    "Update requires explicit migration/approval."
                )
            else:
                row.updated_at = now

        return NodeIdentity(
            node_id=self.settings.node_id,
            public_base_url=self.settings.public_base_url,
            node_name=self.settings.node_name,
            operator_name=self.settings.operator_name,
            config_fingerprint=fingerprint,
        )
