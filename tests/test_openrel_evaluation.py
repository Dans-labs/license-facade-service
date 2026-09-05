from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

from src.license_facade_service.services.openrel_evaluation import (
    OpenRelEvaluationConfigurationError,
    OpenRelEvaluationCoordinator,
    OpenRelEvaluationError,
    OpenRelEvaluationInput,
)
from src.license_facade_service.services.openrel_policy import (
    OpenRelCandidate,
    OpenRelPolicyMode,
    OpenRelPolicySettings,
)
from src.license_facade_service.services.openrel_policy_store import OpenRelPolicyStore
from tests.test_openrel_policy_store import FakeSession


class FakeClient:
    def __init__(self, *, available: bool = True, error: Exception | None = None):
        self.available = available
        self.error = error
        self.calls = 0

    def check_availability(self) -> bool:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.available


def _settings(**overrides) -> OpenRelPolicySettings:
    values = dict(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        cache_ttl_seconds=5,
        timeout_seconds=1.0,
        max_response_bytes=256,
        migration_review_required=False,
    )
    values.update(overrides)
    return OpenRelPolicySettings(**values)


def _candidate(**overrides) -> OpenRelCandidate:
    values = dict(
        provider_url="https://openrel.example.invalid/openrel/api/v0.4",
        profile="https://openrel.org/ns#",
        vocabulary="https://openrel.org/ns#",
        version="0.4",
        content="<openrel>candidate</openrel>",
        href="https://openrel.example.invalid/openrel/api/v0.4/licence/123",
        provenance="candidate provenance",
        mapping_profile="https://openrel.org/ns#",
        mapping_provenance="mapping provenance",
    )
    values.update(overrides)
    return OpenRelCandidate(**values)


def _evaluation(**overrides) -> OpenRelEvaluationInput:
    values = dict(
        canonical_license_id="lic-eval-1",
        source_kind="custom",
        source_record_ref="ref-1",
        registration_timestamp=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
        candidate_payload={"candidate": 1},
        candidate=_candidate(),
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-1",
    )
    values.update(overrides)
    return OpenRelEvaluationInput(**values)


def _coordinator(*, settings: OpenRelPolicySettings | None = None, client: FakeClient | None = None, session: FakeSession | None = None):
    fake_session = session or FakeSession()
    store = OpenRelPolicyStore(fake_session)
    return OpenRelEvaluationCoordinator(settings or _settings(), client=client, policy_store=store), fake_session


def test_disabled_mode_performs_zero_client_calls():
    client = FakeClient()
    coordinator, session = _coordinator(settings=_settings(enabled=False, mode=OpenRelPolicyMode.disabled), client=client)
    result = coordinator.evaluate(_evaluation(candidate=None))
    assert client.calls == 0
    assert result.policy_state_id is None
    assert result.persisted_status is None
    assert result.candidate_digest is None
    assert result.reused_existing_state is False
    assert result.classification.registration_timestamp_trusted is False
    assert result.policy_plan.action.value == "none"
    assert result.application_may_be_allowed_later is False
    assert "disabled" in result.policy_plan.reason.lower()
    assert session.flush_count == 0
    assert session.begin_nested_count == 0
    assert session.commit_count == 0
    assert session.rollback_count == 0


def test_invalid_configuration_performs_zero_client_and_store_writes():
    client = FakeClient()
    coordinator, session = _coordinator(settings=_settings(approved_profile=None), client=client)
    with pytest.raises(OpenRelEvaluationConfigurationError):
        coordinator.evaluate(_evaluation())
    assert client.calls == 0
    assert session.flush_count == 0
    assert session.begin_nested_count == 0


@pytest.mark.parametrize(
    "settings",
    [
        OpenRelPolicySettings(enabled=True, mode=OpenRelPolicyMode.disabled),
        OpenRelPolicySettings(enabled=False, mode=OpenRelPolicyMode.active),
        OpenRelPolicySettings(enabled=True, mode=OpenRelPolicyMode.active, base_url=None, approved_profile=None, approved_version=None, effective_date=None),
    ],
)
def test_contradictory_configuration_raises_before_side_effects(settings):
    client = FakeClient()
    coordinator, session = _coordinator(settings=settings, client=client)
    with pytest.raises(OpenRelEvaluationConfigurationError):
        coordinator.evaluate(_evaluation())
    assert client.calls == 0
    assert session.flush_count == 0
    assert session.begin_nested_count == 0


def test_dry_run_remains_non_mutating():
    coordinator, session = _coordinator(settings=_settings(mode=OpenRelPolicyMode.dry_run), client=FakeClient())
    result = coordinator.evaluate(_evaluation())
    assert result.provider_available is True
    assert result.policy_plan.apply_allowed is False
    assert result.persisted_status == "planned"
    assert "dry-run" in result.policy_plan.reason.lower()
    assert session.commit_count == 0
    assert session.rollback_count == 0


def test_unavailable_provider_produces_action_none_and_no_extra_lookups():
    client = FakeClient(available=False)
    coordinator, _session = _coordinator(client=client)
    result = coordinator.evaluate(_evaluation())
    assert client.calls == 1
    assert result.provider_available is False
    assert result.policy_plan.action.value == "none"
    assert result.policy_plan.apply_allowed is False
    assert "unavailable" in result.policy_plan.reason.lower()


def test_available_provider_with_no_candidate_does_not_fabricate_one():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(candidate=None, candidate_payload={"evaluation": {"candidate_present": False}}))
    assert result.provider_available is True
    assert result.policy_plan.action.value == "none"
    assert "missing" in result.policy_plan.reason.lower()


def test_valid_new_candidate_produces_full_replacement_plan():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation())
    assert result.policy_plan.action.value == "full-replacement"
    assert result.classification.registration_timestamp_trusted is True
    assert result.review_required is False
    assert result.application_may_be_allowed_later is True


def test_valid_historical_candidate_produces_historical_mapping_plan():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)))
    assert result.policy_plan.action.value == "historical-mapping"
    assert result.classification.registration_timestamp_trusted is True
    assert result.review_required is True
    assert result.application_may_be_allowed_later is False


def test_historical_missing_provenance_fails_closed():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(
        _evaluation(
            registration_timestamp=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
            candidate=_candidate(provenance=None, mapping_provenance=None),
        )
    )
    assert result.policy_plan.action.value == "none"
    assert "provenance" in result.policy_plan.reason.lower()


@pytest.mark.parametrize(
    "candidate",
    [
        _candidate(provider_url="https://evil.example/openrel/api/v0.4"),
        _candidate(profile="https://example.com/other-profile"),
        _candidate(vocabulary="https://example.com/other-vocabulary"),
        _candidate(version="9.9"),
        _candidate(content="", href="http://openrel.example.invalid/openrel/api/v0.4/licence/123"),
    ],
)
def test_candidate_validation_failures_are_delegated_to_planner(candidate):
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(candidate=candidate))
    assert result.policy_plan.action.value == "none"
    assert result.application_may_be_allowed_later is False


def test_imported_record_always_action_none_apply_false_review_true():
    coordinator, session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(source_kind="federation-imported"))
    assert result.policy_plan.action.value == "none"
    assert result.policy_plan.apply_allowed is False
    assert result.review_required is True
    state = session.get(__import__("src.license_facade_service.db.models.openrel_policy", fromlist=["OpenRelPolicyState"]).OpenRelPolicyState, result.policy_state_id)
    assert state is not None
    assert state.action == "none"
    assert state.apply_allowed is False
    assert state.review_required is True
    assert result.persisted_status == state.status
    assert result.candidate_digest == state.candidate_digest_sha256


def test_classification_boundary_before_on_after_effective_date():
    coordinator, _session = _coordinator(client=FakeClient())
    before = coordinator.evaluate(_evaluation(registration_timestamp=datetime(2026, 9, 3, 23, 59, tzinfo=timezone.utc)))
    on = coordinator.evaluate(_evaluation(canonical_license_id="lic-eval-2", registration_timestamp=datetime(2026, 9, 4, 0, 0, tzinfo=timezone.utc), candidate_payload={"candidate": 2}))
    after = coordinator.evaluate(_evaluation(canonical_license_id="lic-eval-3", registration_timestamp=datetime(2026, 9, 5, 0, 0, tzinfo=timezone.utc), candidate_payload={"candidate": 3}))
    assert before.classification.classification.value == "historical"
    assert on.classification.classification.value == "new"
    assert after.classification.classification.value == "new"


def test_timezone_naive_timestamp_fails_closed():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(registration_timestamp=datetime(2026, 9, 5, 12, 0)))
    assert result.classification.classification.value == "historical"
    assert result.classification.registration_timestamp_trusted is False
    assert result.classification.mutation_allowed is False
    assert result.classification.review_required is True
    assert result.policy_plan.action.value == "none"
    assert result.policy_plan.apply_allowed is False
    assert "missing or untrustworthy" in " ".join(result.reasons).lower()


def test_missing_timestamp_fails_closed_with_untrusted_flag():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(registration_timestamp=None))
    assert result.classification.classification.value == "historical"
    assert result.classification.registration_timestamp_trusted is False
    assert result.policy_plan.action.value == "none"
    assert result.policy_plan.apply_allowed is False


def test_imported_timestamp_trust_reported_but_action_remains_none():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(
        _evaluation(
            source_kind="federation-imported",
            registration_timestamp=date(2026, 9, 5),
        )
    )
    assert result.classification.registration_timestamp_trusted is True
    assert result.policy_plan.action.value == "none"
    assert result.policy_plan.apply_allowed is False


def test_exact_evaluation_replay_reuses_state():
    coordinator, _session = _coordinator(client=FakeClient())
    first = coordinator.evaluate(_evaluation())
    second = coordinator.evaluate(_evaluation())
    assert first.reused_existing_state is False
    assert first.policy_state_id == second.policy_state_id
    assert second.reused_existing_state is True


def test_changed_candidate_produces_different_state_and_digest():
    coordinator, _session = _coordinator(client=FakeClient())
    first = coordinator.evaluate(_evaluation())
    second = coordinator.evaluate(_evaluation(canonical_license_id="lic-eval-1", candidate_payload={"candidate": 2}))
    assert first.policy_state_id != second.policy_state_id
    assert first.candidate_digest != second.candidate_digest
    assert second.reused_existing_state is False


def test_a_then_b_then_replay_a_reports_exact_reuse():
    coordinator, _session = _coordinator(client=FakeClient())
    first = coordinator.evaluate(_evaluation(candidate_payload={"candidate": "A"}))
    second = coordinator.evaluate(_evaluation(candidate_payload={"candidate": "B"}))
    replay = coordinator.evaluate(_evaluation(candidate_payload={"candidate": "A"}))
    assert first.policy_state_id != second.policy_state_id
    assert replay.policy_state_id == first.policy_state_id
    assert replay.reused_existing_state is True


def test_imported_lookup_uses_projected_action_none_for_reuse():
    coordinator, _session = _coordinator(client=FakeClient())
    first = coordinator.evaluate(_evaluation(source_kind="federation-imported"))
    replay = coordinator.evaluate(_evaluation(source_kind="federation-imported"))
    assert replay.policy_state_id == first.policy_state_id
    assert replay.reused_existing_state is True


def test_actor_identity_reaches_audit_persistence():
    coordinator, session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(actor_type="worker", actor_id="worker-77"))
    event = next(obj for obj in session._objects if getattr(obj, "policy_state_id", None) == result.policy_state_id)
    assert event.actor_type == "worker"
    assert event.actor_id == "worker-77"


def test_invalid_actor_type_rejected_before_activity():
    client = FakeClient()
    coordinator, session = _coordinator(client=client)
    with pytest.raises(OpenRelEvaluationError):
        coordinator.evaluate(_evaluation(actor_type="invalid"))
    assert client.calls == 0
    assert session.flush_count == 0


def test_blank_actor_id_rejected_before_activity():
    client = FakeClient()
    coordinator, session = _coordinator(client=client)
    with pytest.raises(OpenRelEvaluationError):
        coordinator.evaluate(_evaluation(actor_id="   "))
    assert client.calls == 0
    assert session.flush_count == 0


def test_valid_actor_id_is_trimmed():
    coordinator, session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(actor_type="worker", actor_id=" worker-88 "))
    event = next(obj for obj in session._objects if getattr(obj, "policy_state_id", None) == result.policy_state_id)
    assert event.actor_id == "worker-88"


def test_client_domain_errors_fail_closed():
    from src.license_facade_service.services.openrel_client import OpenRelNetworkError

    coordinator, _session = _coordinator(client=FakeClient(error=OpenRelNetworkError("boom")))
    result = coordinator.evaluate(_evaluation())
    assert result.provider_available is False
    assert result.policy_plan.action.value == "none"


def test_unexpected_errors_propagate():
    coordinator, _session = _coordinator(client=FakeClient(error=RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        coordinator.evaluate(_evaluation())


def test_result_contains_no_secret_or_raw_response_data():
    coordinator, _session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation(candidate_payload={"token": "secret-token"}))
    assert "secret-token" not in " ".join(result.reasons)


def test_persisted_state_and_result_agree_for_normal_plan():
    coordinator, session = _coordinator(client=FakeClient())
    result = coordinator.evaluate(_evaluation())
    state = session.get(__import__("src.license_facade_service.db.models.openrel_policy", fromlist=["OpenRelPolicyState"]).OpenRelPolicyState, result.policy_state_id)
    assert state is not None
    assert result.persisted_status == state.status
    assert result.candidate_digest == state.candidate_digest_sha256
    assert result.review_required == state.review_required
    assert result.application_may_be_allowed_later == state.apply_allowed
    assert result.policy_plan.action.value == state.action
    assert result.policy_plan.reason == state.reason


def test_invalid_blank_identifiers_fail_before_client_or_store_activity():
    client = FakeClient()
    coordinator, session = _coordinator(client=client)
    with pytest.raises(OpenRelEvaluationError):
        coordinator.evaluate(_evaluation(canonical_license_id="   "))
    assert client.calls == 0
    assert session.flush_count == 0
