from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


class OpenRelPolicyMode(str, Enum):
    disabled = "disabled"
    dry_run = "dry-run"
    active = "active"


class OpenRelLicenceClassification(str, Enum):
    new = "new"
    historical = "historical"


@dataclass(frozen=True)
class OpenRelPolicySettings:
    enabled: bool = False
    mode: OpenRelPolicyMode = OpenRelPolicyMode.disabled
    database_url: str | None = field(default=None, repr=False)
    admin_cursor_secret: str | None = field(default=None, repr=False)
    base_url: str | None = None
    approved_profile: str | None = None
    approved_version: str | None = None
    effective_date: date | None = None
    cache_ttl_seconds: int = 300
    timeout_seconds: float = 15.0
    max_response_bytes: int = 512_000
    allow_http_for_demo: bool = False
    autodiscovery_enabled: bool = False
    migration_review_required: bool = True
    mapping_authority: str = "lfs"
    validation_errors: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        mode = self.mode
        if not isinstance(mode, OpenRelPolicyMode):
            try:
                mode = OpenRelPolicyMode(str(mode).strip().lower())
            except ValueError:
                mode = OpenRelPolicyMode.disabled
        object.__setattr__(self, "mode", mode)

        errors: list[str] = []
        if not isinstance(self.cache_ttl_seconds, int) or self.cache_ttl_seconds <= 0:
            errors.append("OPENREL_CACHE_TTL_SECONDS must be a positive integer")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            errors.append("OPENREL_TIMEOUT_SECONDS must be a positive number")
        if not isinstance(self.max_response_bytes, int) or self.max_response_bytes <= 0:
            errors.append("OPENREL_MAX_RESPONSE_BYTES must be a positive integer")
        if self.base_url is not None:
            base_url = self.base_url.strip()
            if not base_url:
                errors.append("OPENREL_BASE_URL must not be empty when set")
            else:
                parsed = urlsplit(base_url)
                if not parsed.scheme:
                    errors.append("OPENREL_BASE_URL must be an absolute URL")
                elif parsed.scheme not in {"http", "https"}:
                    errors.append("OPENREL_BASE_URL must use http or https")
                elif parsed.scheme == "http" and not self.allow_http_for_demo:
                    errors.append("HTTP OpenREL provider URLs are only allowed when OPENREL_ALLOW_HTTP_FOR_DEMO=true")
                if not parsed.netloc:
                    errors.append("OPENREL_BASE_URL must include a host")
                if parsed.username or parsed.password:
                    errors.append("OPENREL_BASE_URL must not include credentials")
                if parsed.query:
                    errors.append("OPENREL_BASE_URL must not include a query string")
                if parsed.fragment:
                    errors.append("OPENREL_BASE_URL must not include a fragment")
                if parsed.scheme == "https" and parsed.hostname is not None and parsed.hostname.endswith(".invalid"):
                    # Placeholder test domains are safe and intentionally non-contactable.
                    pass

        if self.mode == OpenRelPolicyMode.active:
            if not self.enabled:
                errors.append("OPENREL policy mode=active requires enabled=True")
            if not self.base_url:
                errors.append("OPENREL policy mode=active requires a configured OPENREL_BASE_URL")
            if not self.approved_profile:
                errors.append("OPENREL policy mode=active requires an approved profile")
            if not self.approved_version:
                errors.append("OPENREL policy mode=active requires an approved version")
            if self.effective_date is None:
                errors.append("OPENREL policy mode=active requires an effective date")
            if self.autodiscovery_enabled:
                errors.append("OPENREL autodiscovery is not allowed when policy mode=active")
        elif self.mode == OpenRelPolicyMode.dry_run:
            if not self.enabled:
                errors.append("OPENREL policy mode=dry-run requires enabled=True")
        elif self.mode == OpenRelPolicyMode.disabled:
            if self.enabled:
                errors.append("OPENREL policy mode=disabled requires enabled=False")

        if self.enabled and self.mode == OpenRelPolicyMode.disabled:
            errors.append("A disabled policy must not be enabled")

        object.__setattr__(self, "validation_errors", tuple(errors))

    @property
    def admin_runtime_validation_errors(self) -> tuple[str, ...]:
        if self.mode == OpenRelPolicyMode.disabled and not self.enabled:
            return ()
        errors: list[str] = []
        database_url = None if self.database_url is None else self.database_url.strip()
        if not database_url:
            errors.append("OpenREL policy runtime requires a configured PostgreSQL database URL.")
        else:
            parsed_db = urlsplit(database_url)
            if parsed_db.scheme not in {"postgresql", "postgresql+psycopg"} or not parsed_db.hostname:
                errors.append("OpenREL policy runtime database configuration is invalid.")
        secret = None if self.admin_cursor_secret is None else self.admin_cursor_secret.strip()
        if not secret:
            errors.append("OpenREL policy runtime requires an admin cursor secret.")
        elif len(secret.encode("utf-8")) < 32:
            errors.append("OpenREL policy runtime cursor secret is invalid.")
        return tuple(errors)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "OpenRelPolicySettings":
        values = os.environ if env is None else env
        runtime_file_errors: list[str] = []

        def as_str(name: str) -> str | None:
            raw = values.get(name, "").strip()
            return raw or None

        def as_secret_str(name: str, file_name: str) -> str | None:
            inline = as_str(name)
            if inline:
                return inline
            file_path = as_str(file_name)
            if not file_path:
                return None
            path = Path(file_path)
            try:
                if not path.is_file():
                    runtime_file_errors.append(f"{file_name} is missing or unreadable")
                    return None
                value = path.read_text(encoding="utf-8").strip()
                if not value:
                    runtime_file_errors.append(f"{file_name} is empty")
                    return None
                return value
            except OSError:
                runtime_file_errors.append(f"{file_name} is missing or unreadable")
                return None

        def as_bool(name: str, default: bool) -> bool:
            raw = values.get(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "y", "on"}

        def as_int(name: str, default: int) -> int:
            raw = values.get(name, "")
            if raw is None or not raw.strip():
                return default
            try:
                return int(raw.strip())
            except ValueError:
                return default

        def as_float(name: str, default: float) -> float:
            raw = values.get(name, "")
            if raw is None or not raw.strip():
                return default
            try:
                return float(raw.strip())
            except ValueError:
                return default

        raw_mode = as_str("OPENREL_POLICY_MODE") or "disabled"
        if raw_mode == "dry-run":
            mode = OpenRelPolicyMode.dry_run
        elif raw_mode == "active":
            mode = OpenRelPolicyMode.active
        else:
            mode = OpenRelPolicyMode.disabled

        raw_effective = as_str("OPENREL_POLICY_EFFECTIVE_DATE")
        effective_date: date | None = None
        if raw_effective:
            try:
                effective_date = date.fromisoformat(raw_effective)
            except ValueError:
                effective_date = None

        settings = cls(
            enabled=as_bool("OPENREL_ENABLED", default=False),
            mode=mode,
            database_url=as_secret_str("OPENREL_POLICY_DATABASE_URL", "OPENREL_POLICY_DATABASE_URL_FILE"),
            admin_cursor_secret=as_secret_str("OPENREL_ADMIN_CURSOR_SECRET", "OPENREL_ADMIN_CURSOR_SECRET_FILE"),
            base_url=as_str("OPENREL_BASE_URL"),
            approved_profile=as_str("OPENREL_APPROVED_PROFILE"),
            approved_version=as_str("OPENREL_APPROVED_VERSION"),
            effective_date=effective_date,
            cache_ttl_seconds=as_int("OPENREL_CACHE_TTL_SECONDS", 300),
            timeout_seconds=as_float("OPENREL_TIMEOUT_SECONDS", 15.0),
            max_response_bytes=as_int("OPENREL_MAX_RESPONSE_BYTES", 512_000),
            allow_http_for_demo=as_bool("OPENREL_ALLOW_HTTP_FOR_DEMO", default=False),
            autodiscovery_enabled=as_bool("OPENREL_AUTODISCOVERY_ENABLED", default=False),
            migration_review_required=as_bool("OPENREL_MIGRATION_REVIEW_REQUIRED", default=True),
            mapping_authority=as_str("OPENREL_MAPPING_AUTHORITY") or "lfs",
        )
        if not runtime_file_errors:
            return settings
        if settings.mode == OpenRelPolicyMode.disabled and not settings.enabled:
            return settings
        return cls(
            enabled=settings.enabled,
            mode=settings.mode,
            database_url=settings.database_url,
            admin_cursor_secret=settings.admin_cursor_secret,
            base_url=settings.base_url,
            approved_profile=settings.approved_profile,
            approved_version=settings.approved_version,
            effective_date=settings.effective_date,
            cache_ttl_seconds=settings.cache_ttl_seconds,
            timeout_seconds=settings.timeout_seconds,
            max_response_bytes=settings.max_response_bytes,
            allow_http_for_demo=settings.allow_http_for_demo,
            autodiscovery_enabled=settings.autodiscovery_enabled,
            migration_review_required=settings.migration_review_required,
            mapping_authority=settings.mapping_authority,
            validation_errors=settings.validation_errors + tuple(runtime_file_errors),
        )

    @classmethod
    def placeholder(cls) -> "OpenRelPolicySettings":
        return cls(
            enabled=True,
            mode=OpenRelPolicyMode.active,
            database_url=None,
            admin_cursor_secret=None,
            base_url="https://openrel.example.invalid/openrel/api/v0.4",
            approved_profile="https://openrel.org/ns#",
            approved_version="0.4",
            effective_date=date(2026, 9, 4),
            cache_ttl_seconds=300,
            timeout_seconds=15.0,
            max_response_bytes=512_000,
            allow_http_for_demo=False,
            autodiscovery_enabled=False,
            migration_review_required=True,
            mapping_authority="lfs",
        )

    @property
    def is_active_policy_valid(self) -> bool:
        return (
            self.enabled
            and self.mode == OpenRelPolicyMode.active
            and not self.validation_errors
            and self.base_url is not None
            and self.approved_profile is not None
            and self.approved_version is not None
            and self.effective_date is not None
        )


@dataclass(frozen=True)
class OpenRelLicenceClassificationResult:
    classification: OpenRelLicenceClassification
    effective_date: date | None
    policy_mode: OpenRelPolicyMode
    policy_version: str | None
    classification_reason: str
    registration_timestamp_trusted: bool
    mutation_allowed: bool
    review_required: bool


class OpenRelPolicyAction(str, Enum):
    none = "none"
    full_replacement = "full-replacement"
    historical_mapping = "historical-mapping"


@dataclass(frozen=True)
class OpenRelCandidate:
    provider_url: str
    profile: str
    vocabulary: str
    version: str
    content: str | None = None
    href: str | None = None
    provenance: str | None = None
    mapping_profile: str | None = None
    mapping_provenance: str | None = None

    @property
    def has_usable_representation(self) -> bool:
        if (self.content or "").strip():
            return True
        return _is_safe_approved_reference_url(self.href)


@dataclass(frozen=True)
class OpenRelPolicyPlan:
    action: OpenRelPolicyAction
    classification: OpenRelLicenceClassification
    policy_version: str | None
    active_profile: str | None
    active_vocabulary: str | None
    original_profile: str | None
    mapping_profile: str | None
    mapping_provenance: str | None
    source_provider_url: str | None
    apply_allowed: bool
    review_required: bool
    reason: str


APPROVED_OPENREL_VOCABULARIES = {"https://openrel.org/ns#"}


def _is_safe_approved_reference_url(value: str | None) -> bool:
    if value is None:
        return False
    candidate = (value or "").strip()
    if not candidate:
        return False
    if candidate.startswith("//"):
        return False
    if candidate.startswith("/"):
        return False
    parsed = urlsplit(candidate)
    if not parsed.scheme or parsed.scheme.lower() != "https":
        return False
    if not parsed.netloc or not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    if parsed.query or parsed.fragment:
        return False
    return True


def _normalize_provider_url(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlsplit(candidate)
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{hostname}{port}{path}"


def _normalize_registration_date(value: date | datetime | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(timezone.utc).date()
    if isinstance(value, date):
        return value
    return None


def classify_licence_record(
    settings: OpenRelPolicySettings,
    *,
    registration_timestamp: date | datetime | None,
    imported_record: bool = False,
) -> OpenRelLicenceClassificationResult:
    policy_mode = settings.mode
    policy_version = settings.approved_version
    effective_date = settings.effective_date

    if not settings.enabled or settings.mode == OpenRelPolicyMode.disabled:
        return OpenRelLicenceClassificationResult(
            classification=OpenRelLicenceClassification.historical,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason="OpenREL policy is disabled; no mutation allowed.",
            registration_timestamp_trusted=False,
            mutation_allowed=False,
            review_required=True,
        )

    if settings.mode == OpenRelPolicyMode.dry_run:
        normalized_date = _normalize_registration_date(registration_timestamp)
        if normalized_date is not None and effective_date is not None and normalized_date >= effective_date:
            classification = OpenRelLicenceClassification.new
            reason = "Dry-run classification: new licence under effective policy date."
        elif normalized_date is not None and effective_date is not None:
            classification = OpenRelLicenceClassification.historical
            reason = "Dry-run classification: historical licence before the policy effective date."
        else:
            classification = OpenRelLicenceClassification.historical
            reason = "Dry-run classification: missing or untrustworthy registration timestamp; no mutation allowed."
        return OpenRelLicenceClassificationResult(
            classification=classification,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason=reason,
            registration_timestamp_trusted=normalized_date is not None,
            mutation_allowed=False,
            review_required=True,
        )

    if settings.mode != OpenRelPolicyMode.active:
        return OpenRelLicenceClassificationResult(
            classification=OpenRelLicenceClassification.historical,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason="OpenREL policy is not active; no mutation allowed.",
            registration_timestamp_trusted=False,
            mutation_allowed=False,
            review_required=True,
        )

    if settings.validation_errors:
        return OpenRelLicenceClassificationResult(
            classification=OpenRelLicenceClassification.historical,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason="OpenREL active policy is invalid; no mutation allowed.",
            registration_timestamp_trusted=False,
            mutation_allowed=False,
            review_required=True,
        )

    normalized_date = _normalize_registration_date(registration_timestamp)
    if normalized_date is None:
        reason = "Missing or untrustworthy registration timestamp; historical classification requires review."
        return OpenRelLicenceClassificationResult(
            classification=OpenRelLicenceClassification.historical,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason=reason,
            registration_timestamp_trusted=False,
            mutation_allowed=False,
            review_required=True,
        )

    if imported_record:
        if effective_date is not None and normalized_date >= effective_date:
            classification = OpenRelLicenceClassification.new
        else:
            classification = OpenRelLicenceClassification.historical
        return OpenRelLicenceClassificationResult(
            classification=classification,
            effective_date=effective_date,
            policy_mode=policy_mode,
            policy_version=policy_version,
            classification_reason="Imported record is non-authoritative; never auto-mutate and always require review.",
            registration_timestamp_trusted=True,
            mutation_allowed=False,
            review_required=True,
        )

    if effective_date is not None and normalized_date >= effective_date:
        classification = OpenRelLicenceClassification.new
        reason = "Registration date is on or after the configured policy effective date."
        mutation_allowed = not settings.migration_review_required
        review_required = settings.migration_review_required
    else:
        classification = OpenRelLicenceClassification.historical
        reason = "Registration date precedes the configured policy effective date; mapping is required, not destructive replacement."
        mutation_allowed = False
        review_required = True

    return OpenRelLicenceClassificationResult(
        classification=classification,
        effective_date=effective_date,
        policy_mode=policy_mode,
        policy_version=policy_version,
        classification_reason=reason,
        registration_timestamp_trusted=True,
        mutation_allowed=mutation_allowed,
        review_required=review_required,
    )


def build_openrel_policy_plan(
    settings: OpenRelPolicySettings,
    classification_result: OpenRelLicenceClassificationResult,
    candidate: OpenRelCandidate | None,
    *,
    current_profile: str | None,
    imported_record: bool = False,
) -> OpenRelPolicyPlan:
    if not settings.enabled or settings.mode == OpenRelPolicyMode.disabled:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=None,
            apply_allowed=False,
            review_required=True,
            reason="OpenREL policy is disabled; no local replacement or mapping is planned.",
        )

    if settings.mode not in {OpenRelPolicyMode.active, OpenRelPolicyMode.dry_run}:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=None,
            apply_allowed=False,
            review_required=True,
            reason="OpenREL policy is not active or dry-run; no local replacement or mapping is planned.",
        )

    if settings.validation_errors:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=None,
            apply_allowed=False,
            review_required=True,
            reason="OpenREL policy configuration is invalid; no local replacement or mapping is planned.",
        )

    if imported_record:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=None,
            apply_allowed=False,
            review_required=True,
            reason="Imported record is non-authoritative; no local replacement or mapping mutation is planned.",
        )

    if candidate is None:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=None,
            apply_allowed=False,
            review_required=True,
            reason="Candidate representation is missing; no local replacement or mapping is planned.",
        )

    if not classification_result.registration_timestamp_trusted:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Missing or untrustworthy registration timestamp prevents automatic replacement or historical mapping.",
        )

    configured_provider = _normalize_provider_url(settings.base_url)
    candidate_provider = _normalize_provider_url(candidate.provider_url)
    if candidate_provider is None or configured_provider is None or candidate_provider != configured_provider:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Candidate provider URL does not match the approved OpenREL base URL after safe normalization.",
        )

    if candidate.profile != settings.approved_profile:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Candidate profile does not exactly match the approved OpenREL profile.",
        )

    if candidate.version != settings.approved_version:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Candidate version does not exactly match the approved OpenREL version.",
        )

    if candidate.vocabulary not in APPROVED_OPENREL_VOCABULARIES:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Candidate vocabulary is not an approved current OpenREL vocabulary.",
        )

    if not candidate.has_usable_representation:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Candidate representation is unsafe or missing: provide non-empty content or a safe HTTPS href.",
        )

    if classification_result.classification == OpenRelLicenceClassification.new:
        action = OpenRelPolicyAction.full_replacement
        apply_allowed = bool(classification_result.mutation_allowed)
        review_required = bool(classification_result.review_required)
        if settings.mode == OpenRelPolicyMode.dry_run:
            apply_allowed = False
            reason = "Dry-run: full replacement would have been planned but not applied."
        else:
            reason = "Authoritative new licence qualifies for full OpenREL replacement."
        return OpenRelPolicyPlan(
            action=action,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary=candidate.vocabulary,
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=apply_allowed,
            review_required=review_required,
            reason=reason,
        )

    if current_profile is None:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=None,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Historical licence mapping requires an original profile for audit and rollback traceability.",
        )

    mapping_provenance = candidate.mapping_provenance or candidate.provenance
    if not mapping_provenance or not str(mapping_provenance).strip():
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction.none,
            classification=classification_result.classification,
            policy_version=classification_result.policy_version,
            active_profile=settings.approved_profile,
            active_vocabulary="https://openrel.org/ns#",
            original_profile=current_profile,
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url=candidate.provider_url,
            apply_allowed=False,
            review_required=True,
            reason="Historical mapping requires auditable mapping provenance; candidate.mapping_provenance or candidate.provenance is required.",
        )

    action = OpenRelPolicyAction.historical_mapping
    mapping_profile = candidate.mapping_profile or settings.approved_profile
    apply_allowed = False
    review_required = True
    if settings.mode == OpenRelPolicyMode.dry_run:
        reason = "Dry-run: historical mapping would be planned but not applied."
    else:
        reason = "Historical licence requires preservation of the original profile and mapping to the approved OpenREL profile."
    return OpenRelPolicyPlan(
        action=action,
        classification=classification_result.classification,
        policy_version=classification_result.policy_version,
        active_profile=settings.approved_profile,
        active_vocabulary=candidate.vocabulary,
        original_profile=current_profile,
        mapping_profile=mapping_profile,
        mapping_provenance=str(mapping_provenance).strip(),
        source_provider_url=candidate.provider_url,
        apply_allowed=apply_allowed,
        review_required=review_required,
        reason=reason,
    )


__all__ = [
    "OpenRelLicenceClassification",
    "OpenRelLicenceClassificationResult",
    "OpenRelPolicyAction",
    "OpenRelPolicyMode",
    "OpenRelPolicyPlan",
    "OpenRelPolicySettings",
    "OpenRelCandidate",
    "build_openrel_policy_plan",
    "classify_licence_record",
]
