from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from src.license_facade_service.services.openrel_policy import (
    OpenRelCandidate,
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelPolicyMode,
    OpenRelPolicySettings,
    build_openrel_policy_plan,
    classify_licence_record,
)


def test_openrel_policy_defaults_disabled_and_fail_closed():
    settings = OpenRelPolicySettings()
    assert settings.enabled is False
    assert settings.mode == OpenRelPolicyMode.disabled
    assert settings.database_url is None
    assert settings.admin_cursor_secret is None
    assert settings.validation_errors == ()
    assert settings.admin_runtime_validation_errors == ()

    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 4, tzinfo=timezone.utc))
    assert decision.classification == OpenRelLicenceClassification.historical
    assert decision.registration_timestamp_trusted is False
    assert decision.mutation_allowed is False
    assert decision.review_required is True


def test_active_policy_requires_complete_approval_configuration():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
    )
    assert settings.validation_errors
    assert any("approved profile" in error.lower() for error in settings.validation_errors)
    assert any("effective date" in error.lower() for error in settings.validation_errors)


def test_active_policy_rejects_unsafe_provider_url():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="http://user:pass@openrel.example.invalid/openrel/api/v0.4?x=1#frag",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    assert settings.validation_errors
    assert any("credentials" in error.lower() for error in settings.validation_errors)
    assert any("query" in error.lower() or "fragment" in error.lower() for error in settings.validation_errors)


def test_placeholder_policy_configuration_is_valid_but_not_contacted():
    settings = OpenRelPolicySettings.placeholder()
    assert settings.enabled is True
    assert settings.mode == OpenRelPolicyMode.active
    assert settings.database_url is None
    assert settings.admin_cursor_secret is None
    assert settings.base_url == "https://openrel.example.invalid/openrel/api/v0.4"
    assert settings.approved_profile == "https://openrel.org/ns#"
    assert settings.approved_version == "0.4"
    assert settings.effective_date == date(2026, 9, 4)
    assert settings.validation_errors == ()
    assert settings.is_active_policy_valid is True
    rendered = repr(settings)
    assert "postgresql" not in rendered
    assert "admin_cursor_secret" not in rendered

    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 4, tzinfo=timezone.utc))
    assert decision.classification == OpenRelLicenceClassification.new
    assert decision.registration_timestamp_trusted is True
    assert decision.mutation_allowed is not settings.migration_review_required
    assert decision.review_required == settings.migration_review_required


def test_registration_on_effective_date_is_new():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        migration_review_required=False,
    )
    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc))
    assert decision.classification == OpenRelLicenceClassification.new
    assert decision.registration_timestamp_trusted is True
    assert decision.mutation_allowed is True
    assert decision.review_required is False


def test_registration_before_effective_date_is_historical():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        migration_review_required=False,
    )
    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 3, 23, 59, tzinfo=timezone.utc))
    assert decision.classification == OpenRelLicenceClassification.historical
    assert decision.registration_timestamp_trusted is True
    assert decision.mutation_allowed is False
    assert decision.review_required is True


def test_missing_registration_timestamp_is_historical_and_requires_review():
    settings = OpenRelPolicySettings.placeholder()
    decision = classify_licence_record(settings, registration_timestamp=None)
    assert decision.classification == OpenRelLicenceClassification.historical
    assert decision.registration_timestamp_trusted is False
    assert decision.mutation_allowed is False
    assert decision.review_required is True
    assert "missing or untrustworthy registration timestamp" in decision.classification_reason.lower()


def test_timezone_naive_registration_timestamp_is_untrustworthy():
    settings = OpenRelPolicySettings.placeholder()
    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 5, 12, 0))
    assert decision.classification == OpenRelLicenceClassification.historical
    assert decision.registration_timestamp_trusted is False
    assert decision.mutation_allowed is False
    assert decision.review_required is True
    assert "untrustworthy" in decision.classification_reason.lower()


def test_date_registration_timestamp_is_trusted():
    settings = OpenRelPolicySettings.placeholder()
    decision = classify_licence_record(settings, registration_timestamp=date(2026, 9, 5))
    assert decision.classification == OpenRelLicenceClassification.new
    assert decision.registration_timestamp_trusted is True


def test_unsupported_timestamp_type_is_untrusted():
    settings = OpenRelPolicySettings.placeholder()
    decision = classify_licence_record(settings, registration_timestamp="2026-09-05")  # type: ignore[arg-type]
    assert decision.classification == OpenRelLicenceClassification.historical
    assert decision.registration_timestamp_trusted is False


def test_dry_run_classifies_without_allowing_mutation():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.dry_run,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    decision = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 5, tzinfo=timezone.utc))
    assert decision.classification == OpenRelLicenceClassification.new
    assert decision.registration_timestamp_trusted is True
    assert decision.mutation_allowed is False
    assert decision.review_required is True


def test_imported_record_is_never_automatically_mutated():
    settings = OpenRelPolicySettings.placeholder()
    decision = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, tzinfo=timezone.utc),
        imported_record=True,
    )
    assert decision.classification == OpenRelLicenceClassification.new
    assert decision.registration_timestamp_trusted is True
    assert decision.mutation_allowed is False
    assert decision.review_required is True
    assert "imported record" in decision.classification_reason.lower()


def test_classification_is_deterministic():
    settings = OpenRelPolicySettings.placeholder()
    first = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 4, 0, 0, tzinfo=timezone.utc))
    second = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 4, 0, 0, tzinfo=timezone.utc))
    assert first == second


def test_non_positive_policy_limits_are_rejected():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        cache_ttl_seconds=0,
        timeout_seconds=0,
        max_response_bytes=0,
    )
    assert settings.validation_errors
    assert any("positive" in error.lower() for error in settings.validation_errors)


def test_autodiscovery_is_rejected_for_active_policy():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        autodiscovery_enabled=True,
    )
    assert settings.validation_errors
    assert any("autodiscovery" in error.lower() for error in settings.validation_errors)


def _valid_openrel_candidate(**overrides):
    values = {
        "provider_url": "https://openrel.example.invalid/openrel/api/v0.4",
        "profile": "https://openrel.org/ns#",
        "vocabulary": "https://openrel.org/ns#",
        "version": "0.4",
        "content": "<openrel>candidate</openrel>",
        "href": "https://openrel.example.invalid/openrel/api/v0.4/licence/123",
        "provenance": "candidate provenance",
        "mapping_profile": "https://openrel.org/ns#",
        "mapping_provenance": "mapping provenance",
    }
    values.update(overrides)
    return OpenRelCandidate(**values)


def test_new_authoritative_licence_plans_full_openrel_replacement():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        migration_review_required=False,
    )
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/original-profile",
    )
    assert plan.action == OpenRelPolicyAction.full_replacement
    assert plan.classification == OpenRelLicenceClassification.new
    assert plan.active_profile == settings.approved_profile
    assert plan.active_vocabulary == "https://openrel.org/ns#"
    assert plan.original_profile == "https://example.com/original-profile"
    assert plan.apply_allowed is True
    assert plan.review_required is False


def test_historical_licence_plans_mapping_and_retains_original_profile():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/historical-profile",
    )
    assert plan.action == OpenRelPolicyAction.historical_mapping
    assert plan.classification == OpenRelLicenceClassification.historical
    assert plan.original_profile == "https://example.com/historical-profile"
    assert plan.mapping_profile == "https://openrel.org/ns#"
    assert plan.mapping_provenance == "mapping provenance"
    assert plan.apply_allowed is False
    assert plan.review_required is True


def test_historical_mapping_requires_original_profile():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile=None)
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "original profile" in plan.reason.lower()


def test_imported_record_never_plans_local_mutation():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
        imported_record=True,
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/imported-profile",
        imported_record=True,
    )
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "imported record" in plan.reason.lower()


def test_disabled_policy_produces_no_action():
    settings = OpenRelPolicySettings(enabled=False, mode=OpenRelPolicyMode.disabled)
    classification = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 5, tzinfo=timezone.utc))
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False


def test_dry_run_plans_without_allowing_apply():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.dry_run,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.full_replacement
    assert plan.apply_allowed is False
    assert "dry-run" in plan.reason.lower()


def test_missing_timestamp_forces_action_none_even_with_valid_candidate():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(settings, registration_timestamp=None)
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert classification.registration_timestamp_trusted is False
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert plan.review_required is True
    assert plan.mapping_profile is None
    assert plan.mapping_provenance is None
    assert "missing or untrustworthy registration timestamp" in plan.reason.lower()


def test_timezone_naive_timestamp_forces_action_none():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(settings, registration_timestamp=datetime(2026, 9, 5, 12, 0))
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert classification.registration_timestamp_trusted is False
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False


def test_unsupported_timestamp_type_forces_action_none():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(settings, registration_timestamp="2026-09-05")  # type: ignore[arg-type]
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert classification.registration_timestamp_trusted is False
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False


def test_mapping_provenance_cannot_override_untrusted_timestamp():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(settings, registration_timestamp=None)
    candidate = _valid_openrel_candidate(mapping_provenance="traceable provenance", provenance="candidate provenance")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/historical-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.mapping_profile is None
    assert plan.mapping_provenance is None


def test_dry_run_untrusted_timestamp_remains_action_none():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.dry_run,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    classification = classify_licence_record(settings, registration_timestamp=None)
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "missing or untrustworthy registration timestamp" in plan.reason.lower()


def test_imported_timestamp_trust_is_reported_but_action_remains_none():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=date(2026, 9, 5),
        imported_record=True,
    )
    candidate = _valid_openrel_candidate()
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/imported-profile",
        imported_record=True,
    )
    assert classification.registration_timestamp_trusted is True
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False


def test_active_policy_requires_explicit_database_url():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    assert settings.validation_errors == ()
    assert any("database" in error.lower() for error in settings.admin_runtime_validation_errors)


def test_dry_run_policy_requires_explicit_database_url():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.dry_run,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    assert settings.validation_errors == ()
    assert any("database" in error.lower() for error in settings.admin_runtime_validation_errors)


def test_disabled_policy_does_not_require_database_url():
    settings = OpenRelPolicySettings(enabled=False, mode=OpenRelPolicyMode.disabled)
    assert settings.admin_runtime_validation_errors == ()


def test_policy_database_url_rejects_unsupported_scheme():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="sqlite:///tmp/test.db",
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    assert settings.validation_errors == ()
    assert any("database configuration is invalid" in error.lower() for error in settings.admin_runtime_validation_errors)


def test_policy_database_url_file_is_supported(tmp_path):
    db_file = tmp_path / "db-url.txt"
    db_file.write_text("postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema\n", encoding="utf-8")
    settings = OpenRelPolicySettings.from_env(
        {
            "OPENREL_ENABLED": "true",
            "OPENREL_POLICY_MODE": "dry-run",
            "OPENREL_POLICY_DATABASE_URL_FILE": str(db_file),
            "OPENREL_ADMIN_CURSOR_SECRET": "x" * 32,
            "OPENREL_BASE_URL": "https://openrel.example.invalid/openrel/api/v0.4",
            "OPENREL_APPROVED_PROFILE": "https://openrel.org/ns#",
            "OPENREL_APPROVED_VERSION": "0.4",
            "OPENREL_POLICY_EFFECTIVE_DATE": "2026-09-04",
        }
    )
    assert settings.database_url == "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema"


def test_unapproved_provider_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(provider_url="https://evil.example.invalid/api/v0.4")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "provider" in plan.reason.lower()


def test_unapproved_profile_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(profile="https://example.com/other-profile")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "profile" in plan.reason.lower()


def test_unapproved_version_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(version="9.9")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "version" in plan.reason.lower()


def test_unapproved_vocabulary_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(vocabulary="https://example.com/other-vocabulary")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "vocabulary" in plan.reason.lower()


def test_candidate_without_content_or_href_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href=None)
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "content" in plan.reason.lower() or "href" in plan.reason.lower()


def test_candidate_http_href_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href="http://openrel.example.invalid/openrel/api/v0.4/licence/123")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "unsafe" in plan.reason.lower() or "https" in plan.reason.lower()


def test_candidate_relative_href_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href="/licence/123")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "unsafe" in plan.reason.lower() or "href" in plan.reason.lower()


def test_candidate_href_with_credentials_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href="https://user:pass@openrel.example.invalid/openrel/api/v0.4/licence/123")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "unsafe" in plan.reason.lower() or "credentials" in plan.reason.lower()


def test_candidate_href_with_query_or_fragment_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href="https://openrel.example.invalid/openrel/api/v0.4/licence/123?x=1")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert "unsafe" in plan.reason.lower() or "query" in plan.reason.lower() or "fragment" in plan.reason.lower()

    candidate = _valid_openrel_candidate(content="", href="https://openrel.example.invalid/openrel/api/v0.4/licence/123#frag")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False


def test_candidate_https_href_is_accepted_without_content():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(content="", href="https://openrel.example.invalid/openrel/api/v0.4/licence/123")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.full_replacement
    assert plan.apply_allowed is False
    assert plan.review_required is True


def test_candidate_content_is_accepted_without_href():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(href=None, content="<openrel>candidate</openrel>")
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert plan.action == OpenRelPolicyAction.full_replacement
    assert plan.apply_allowed is False
    assert plan.review_required is True


def test_historical_mapping_without_provenance_is_rejected():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(provenance=None, mapping_provenance=None)
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/historical-profile",
    )
    assert plan.action == OpenRelPolicyAction.none
    assert plan.apply_allowed is False
    assert plan.review_required is True
    assert "provenance" in plan.reason.lower()


def test_mapping_profile_and_provenance_are_retained():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate(
        mapping_profile="https://example.com/openrel-map",
        mapping_provenance="traceable provenance",
    )
    plan = build_openrel_policy_plan(
        settings,
        classification,
        candidate,
        current_profile="https://example.com/historical-profile",
    )
    assert plan.action == OpenRelPolicyAction.historical_mapping
    assert plan.mapping_profile == "https://example.com/openrel-map"
    assert plan.mapping_provenance == "traceable provenance"


def test_policy_plan_is_deterministic():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    first = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    second = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert first == second


def test_planner_does_not_mutate_inputs():
    settings = OpenRelPolicySettings.placeholder()
    classification = classify_licence_record(
        settings,
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
    )
    candidate = _valid_openrel_candidate()
    original_candidate = candidate
    plan = build_openrel_policy_plan(settings, classification, candidate, current_profile="https://example.com/original-profile")
    assert candidate == original_candidate
    assert candidate.provider_url == "https://openrel.example.invalid/openrel/api/v0.4"
    assert plan.source_provider_url == "https://openrel.example.invalid/openrel/api/v0.4"
