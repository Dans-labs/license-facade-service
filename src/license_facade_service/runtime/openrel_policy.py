from __future__ import annotations

from dataclasses import dataclass

from src.license_facade_service.db.session import Database
from src.license_facade_service.services.openrel_client import OpenRelClient, OpenRelClientError
from src.license_facade_service.services.openrel_policy import OpenRelPolicyMode, OpenRelPolicySettings


@dataclass(frozen=True)
class OpenRelPolicyRuntimeState:
    enabled: bool
    ready: bool
    errors: tuple[str, ...]


class OpenRelPolicyRuntime:
    def __init__(self, settings: OpenRelPolicySettings) -> None:
        self.settings = settings
        self.db: Database | None = None
        self.client: OpenRelClient | None = None
        self._closed = False

    def initialize(self) -> OpenRelPolicyRuntimeState:
        if self.settings.mode == OpenRelPolicyMode.disabled and not self.settings.enabled:
            return OpenRelPolicyRuntimeState(enabled=False, ready=True, errors=())
        if self.settings.validation_errors:
            return OpenRelPolicyRuntimeState(enabled=True, ready=False, errors=self._sanitized_errors(self.settings.validation_errors))
        if self.settings.admin_runtime_validation_errors:
            return OpenRelPolicyRuntimeState(enabled=True, ready=False, errors=self._sanitized_errors(self.settings.admin_runtime_validation_errors))
        try:
            assert self.settings.database_url is not None
            self.db = Database.from_url(self.settings.database_url)
            self.client = OpenRelClient(self.settings)
            return OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=())
        except Exception:
            self.close()
            self._closed = False
            return OpenRelPolicyRuntimeState(enabled=True, ready=False, errors=("OpenREL policy runtime is unavailable.",))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.db is not None:
            self.db.close()
            self.db = None

    def _sanitized_errors(self, errors: tuple[str, ...] | None = None) -> tuple[str, ...]:
        source = self.settings.validation_errors if errors is None else errors
        sanitized: list[str] = []
        for error in source:
            lowered = error.lower()
            if "database" in lowered or "cursor secret" in lowered or "_file" in lowered:
                sanitized.append("OpenREL policy runtime configuration is invalid.")
            else:
                sanitized.append(error)
        return tuple(sanitized)


__all__ = ["OpenRelPolicyRuntime", "OpenRelPolicyRuntimeState", "OpenRelClientError"]
