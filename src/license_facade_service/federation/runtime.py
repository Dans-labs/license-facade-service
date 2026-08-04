from __future__ import annotations

from dataclasses import dataclass, field

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.identity import NodeIdentity, NodeIdentityService
from src.license_facade_service.federation.keys import ActiveSigningKey, SigningKeyService


@dataclass
class FederationRuntimeState:
    enabled: bool
    ready: bool
    errors: list[str] = field(default_factory=list)
    node_id: str | None = None


@dataclass
class FederationRuntime:
    settings: FederationSettings
    db: Database | None = None
    identity: NodeIdentity | None = None
    active_signing_key: ActiveSigningKey | None = None

    def initialize(self) -> FederationRuntimeState:
        if not self.settings.enabled:
            return FederationRuntimeState(enabled=False, ready=True, errors=[])
        if self.settings.validation_errors:
            return FederationRuntimeState(
                enabled=True,
                ready=False,
                errors=list(self.settings.validation_errors),
                node_id=self.settings.node_id,
            )

        errors: list[str] = []
        try:
            assert self.settings.database_url is not None
            self.db = Database.from_url(self.settings.database_url)
            identity_service = NodeIdentityService(self.db, self.settings)
            self.identity = identity_service.ensure_identity_state()
            key_service = SigningKeyService(self.db, self.settings)
            self.active_signing_key = key_service.load_and_persist_active_key()
        except Exception as exc:
            errors.append(str(exc))

        return FederationRuntimeState(
            enabled=True,
            ready=not errors,
            errors=errors,
            node_id=self.settings.node_id,
        )
