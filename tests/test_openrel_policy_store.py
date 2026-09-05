from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import date, timedelta
from functools import cmp_to_key
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, MultipleResultsFound

from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState
from src.license_facade_service.services.openrel_policy import (
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelPolicyMode,
    OpenRelPolicyPlan,
    OpenRelPolicySettings,
)
from src.license_facade_service.services.openrel_policy_store import (
    OpenRelPolicyPlanValidationError,
    OpenRelPolicyStore,
    OpenRelPolicyStoreCollisionError,
    OpenRelPolicyTransitionError,
    compute_candidate_digest,
    sanitize_audit_details,
    sanitize_review_reason,
)


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def one_or_none(self):
        if not self._rows:
            return None
        if len(self._rows) == 1:
            return self._rows[0]
        raise MultipleResultsFound("Multiple rows were found when one or none was required")


class FakeSession:
    def __init__(self):
        self._objects = []
        self.flush_count = 0
        self.commit_count = 0
        self.rollback_count = 0
        self.begin_nested_count = 0
        self.operation_log = []
        self.flush_side_effects = []
        self.nested_depth = 0
        self.query_overrides = []

    def add(self, obj):
        self._objects.append(obj)
        self.operation_log.append(f"add:{obj.__class__.__name__}")

    def flush(self):
        self.flush_count += 1
        self.operation_log.append("flush")
        if self.flush_side_effects:
            callback = self.flush_side_effects.pop(0)
            callback()

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1

    def begin_nested(self):
        session = self

        class _NestedTransaction:
            def __enter__(self_inner):
                session.begin_nested_count += 1
                session.nested_depth += 1
                session.operation_log.append("begin_nested")
                return self_inner

            def __exit__(self_inner, exc_type, exc, tb):
                session.operation_log.append("end_nested")
                session.nested_depth -= 1
                return False

        return _NestedTransaction()

    def get(self, model, key):
        for obj in self._objects:
            if isinstance(obj, model) and obj.id == key:
                return obj
        return None

    def query(self, model):
        if self.query_overrides:
            override = self.query_overrides.pop(0)
            if override["model"] is model:
                return override["query"]
            self.query_overrides.insert(0, override)
        return FakeQuery(self._objects, model)

    def execute(self, stmt):
        table = stmt.get_final_froms()[0]
        model = next((obj.__class__ for obj in self._objects if obj.__class__.__tablename__ == table.name), None)
        if model is None:
            return FakeResult([])
        rows = [obj for obj in self._objects if isinstance(obj, model)]
        where = getattr(stmt, "_where_criteria", ())
        for clause in where:
            left = clause.left
            right = clause.right.value
            rows = [obj for obj in rows if getattr(obj, left.name) == right]
        order_by = tuple(getattr(stmt, "_order_by_clauses", ()))

        def compare(left, right):
            for item in order_by:
                name = item.element.name
                left_value = getattr(left, name)
                right_value = getattr(right, name)
                modifier = getattr(item, "modifier", None)
                reverse = modifier is not None and getattr(modifier, "__name__", "") == "desc_op"
                if left_value == right_value:
                    continue
                if left_value < right_value:
                    return 1 if reverse else -1
                return -1 if reverse else 1
            return 0

        rows = sorted(rows, key=cmp_to_key(compare))
        limit = getattr(stmt, "_limit", None)
        if limit is not None:
            rows = rows[:limit]
        return FakeResult(rows)


class FakeQuery:
    def __init__(self, objects, model):
        self._objects = objects
        self._model = model
        self._filters = {}
        self._order_by = []

    def filter_by(self, **kwargs):
        self._filters.update(kwargs)
        return self

    def order_by(self, *args):
        self._order_by.extend(args)
        return self

    def first(self):
        rows = self.all()
        return rows[0] if rows else None

    def all(self):
        rows = [obj for obj in self._objects if isinstance(obj, self._model)]
        for key, value in self._filters.items():
            rows = [obj for obj in rows if getattr(obj, key) == value]

        def compare(left, right):
            for item in self._order_by:
                name = item.element.name
                left_value = getattr(left, name)
                right_value = getattr(right, name)
                reverse = getattr(item, "modifier", None) is not None and getattr(item.modifier, "__name__", "") == "desc_op"
                if left_value == right_value:
                    continue
                if left_value < right_value:
                    return 1 if reverse else -1
                return -1 if reverse else 1
            return 0

        return sorted(rows, key=cmp_to_key(compare))


class FakeWinnerQuery:
    def __init__(self, winner):
        self._winner = winner

    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args):
        return self

    def first(self):
        return self._winner


class FakeEmptyQuery:
    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args):
        return self

    def first(self):
        return None


class FakePlanBuilder:
    @staticmethod
    def default_plan(*, action=OpenRelPolicyAction.full_replacement, review_required=False, apply_allowed=True):
        return OpenRelPolicyPlan(
            action=action,
            classification=OpenRelLicenceClassification.new,
            policy_version="2026.09",
            active_profile="https://openrel.example.invalid/profile",
            active_vocabulary="https://openrel.example.invalid/vocab",
            original_profile="https://openrel.example.invalid/original-profile",
            mapping_profile=None,
            mapping_provenance=None,
            source_provider_url="https://openrel.example.invalid/provider",
            apply_allowed=apply_allowed,
            review_required=review_required,
            reason="standard plan",
        )


def _settings(**overrides):
    params = dict(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://openrel.example.invalid/provider",
        approved_profile="https://openrel.example.invalid/profile",
        approved_version="2026.09",
        effective_date=date(2026, 9, 4),
    )
    params.update(overrides)
    return OpenRelPolicySettings(**params)


def test_digest_is_deterministic_for_equivalent_payloads():
    payload_a = {"b": 2, "a": [3, 1, {"z": 0, "y": 2}]}
    payload_b = {"a": [3, 1, {"y": 2, "z": 0}], "b": 2}
    assert compute_candidate_digest(payload_a) == compute_candidate_digest(payload_b)


def test_digest_changes_when_payload_changes():
    assert compute_candidate_digest({"a": 1}) != compute_candidate_digest({"a": 2})


def test_record_plan_creates_state_and_one_planned_event():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 7}

    state = store.record_plan(
        canonical_license_id="lic-1",
        source_kind="custom",
        source_record_ref="ref-1",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-01",
    )

    assert isinstance(state, OpenRelPolicyState)
    assert state.status == "planned"
    assert state.candidate_digest_sha256 == compute_candidate_digest(payload)
    assert session.flush_count == 2
    assert session.commit_count == 0
    assert session.rollback_count == 0
    assert session.begin_nested_count == 1
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyState)]) == 1
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)]) == 1
    event = next(obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent))
    assert event.event_type == "planned"
    assert event.after_status == "planned"
    assert event.policy_state_id == state.id
    assert session.operation_log == [
        "begin_nested",
        "add:OpenRelPolicyState",
        "flush",
        "add:OpenRelPolicyEvent",
        "flush",
        "end_nested",
    ]


def test_exact_replay_returns_existing_state_without_duplicate_event():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 7}

    first = store.record_plan(
        canonical_license_id="lic-2",
        source_kind="custom",
        source_record_ref="ref-2",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-02",
    )
    second = store.record_plan(
        canonical_license_id="lic-2",
        source_kind="custom",
        source_record_ref="ref-2",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-02",
    )

    assert first.id == second.id
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyState)]) == 1
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)]) == 1


def test_record_plan_recovers_exact_race_without_outer_rollback():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 8}
    winner, winner_event, _ = store._build_state_record(
        canonical_license_id="lic-race-unit",
        source_kind="custom",
        source_record_ref="ref-race-unit",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-race",
        effective_policy_version=settings.approved_version,
        provider_url=settings.base_url,
        effective_date=settings.effective_date,
        requested_action=plan.action.value,
    )
    session.query_overrides.extend(
        [
            {"model": OpenRelPolicyState, "query": FakeEmptyQuery()},
            {"model": OpenRelPolicyState, "query": FakeWinnerQuery(winner)},
        ]
    )
    session._objects.append(winner)
    session._objects.append(winner_event)
    unrelated_state = OpenRelPolicyState(
        id=uuid.uuid4(),
        canonical_license_id="lic-unrelated",
        source_kind="custom",
        source_record_ref="ref-unrelated",
        classification="new",
        policy_mode="active",
        policy_version="2026.09",
        effective_date=settings.effective_date,
        action="full-replacement",
        status="planned",
        provider_url=settings.base_url,
        active_profile=plan.active_profile,
        active_vocabulary=plan.active_vocabulary,
        original_profile=plan.original_profile,
        mapping_profile=None,
        mapping_provenance=None,
        candidate_digest_sha256=compute_candidate_digest({"other": 1}),
        original_content_digest_sha256=None,
        candidate_payload={"other": 1},
        original_representation={"other": 1},
        apply_allowed=True,
        review_required=False,
        reason="keep me",
    )
    session._objects.append(unrelated_state)

    session.flush_side_effects.append(
        lambda: (_ for _ in ()).throw(
            IntegrityError(
                statement="INSERT state",
                params={},
                orig=SimpleNamespace(diag=SimpleNamespace(constraint_name="uq_openrel_policy_states_license_policy_candidate_action")),
            )
        )
    )
    pre_race_log_length = len(session.operation_log)

    recovered = store.record_plan(
        canonical_license_id="lic-race-unit",
        source_kind="custom",
        source_record_ref="ref-race-unit",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-race",
    )

    assert recovered.id == winner.id
    assert session.rollback_count == 0
    assert session.commit_count == 0
    assert session.flush_count == 1
    assert unrelated_state in session._objects
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.policy_state_id == winner.id]) == 1
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.policy_state_id != winner.id]) == 0
    assert session.operation_log[pre_race_log_length:] == [
        "begin_nested",
        "add:OpenRelPolicyState",
        "flush",
        "end_nested",
    ]


def test_record_plan_reraises_unrelated_integrity_error():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 9}
    err = IntegrityError(
        statement="INSERT state",
        params={},
        orig=SimpleNamespace(diag=SimpleNamespace(constraint_name="some_other_constraint")),
    )
    session.flush_side_effects.append(lambda: (_ for _ in ()).throw(err))

    try:
        store.record_plan(
            canonical_license_id="lic-race-unit-2",
            source_kind="custom",
            source_record_ref="ref-race-unit-2",
            settings=settings,
            plan=plan,
            candidate_payload=payload,
            original_representation={"name": "MIT"},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-race-2",
        )
        raise AssertionError("integrity error expected")
    except IntegrityError as exc:
        assert exc is err
    assert session.rollback_count == 0
    assert session.commit_count == 0


def test_record_plan_race_with_inconsistent_winner_raises_collision_error():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 10}
    winner = store.record_plan(
        canonical_license_id="lic-race-unit-3",
        source_kind="custom",
        source_record_ref="ref-original",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-original",
    )
    session.flush_side_effects.append(
        lambda: (_ for _ in ()).throw(
            IntegrityError(
                statement="INSERT state",
                params={},
                orig=SimpleNamespace(diag=SimpleNamespace(constraint_name="uq_openrel_policy_states_license_policy_candidate_action")),
            )
        )
    )

    try:
        store.record_plan(
            canonical_license_id="lic-race-unit-3",
            source_kind="custom",
            source_record_ref="ref-changed",
            settings=settings,
            plan=plan,
            candidate_payload=payload,
            original_representation={"name": "MIT"},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-original",
        )
        raise AssertionError("collision expected")
    except OpenRelPolicyStoreCollisionError:
        pass
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.policy_state_id == winner.id and obj.event_type == "planned"]) == 1


def test_materially_different_replay_raises_collision_error():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payload = {"license": "MIT", "value": 7}

    store.record_plan(
        canonical_license_id="lic-3",
        source_kind="custom",
        source_record_ref="ref-3",
        settings=settings,
        plan=plan,
        candidate_payload=payload,
        original_representation={"name": "MIT"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-03",
    )

    try:
        store.record_plan(
            canonical_license_id="lic-3",
            source_kind="custom",
            source_record_ref="ref-other",
            settings=settings,
            plan=plan,
            candidate_payload=payload,
            original_representation={"name": "MIT"},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-03",
        )
        raise AssertionError("collision error expected")
    except OpenRelPolicyStoreCollisionError:
        pass


def test_imported_record_projection_is_fail_closed():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings(mode=OpenRelPolicyMode.active)
    plan = OpenRelPolicyPlan(
        action=OpenRelPolicyAction.none,
        classification=OpenRelLicenceClassification.historical,
        policy_version="2026.09",
        active_profile="https://openrel.example.invalid/profile",
        active_vocabulary="https://openrel.example.invalid/vocab",
        original_profile="https://openrel.example.invalid/original-profile",
        mapping_profile=None,
        mapping_provenance=None,
        source_provider_url="https://openrel.example.invalid/provider",
        apply_allowed=False,
        review_required=True,
        reason="imported",
    )

    state = store.record_plan(
        canonical_license_id="lic-imported",
        source_kind="federation-imported",
        source_record_ref="imported-1",
        settings=settings,
        plan=plan,
        candidate_payload={"content": "import only"},
        original_representation={"source": "imported"},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-imported",
    )
    assert state.action == "none"
    assert state.apply_allowed is False
    assert state.review_required is True
    assert state.status == "planned"
    assert state.source_kind == "federation-imported"


def test_get_by_id_and_latest_ordered_query():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    payloads = [
        ("lic-4a", {"v": 1}),
        ("lic-4a", {"v": 2}),
    ]
    states = []
    for canonical_license_id, payload in payloads:
        states.append(
            store.record_plan(
                canonical_license_id=canonical_license_id,
                source_kind="custom",
                source_record_ref=f"ref-{payload['v']}",
                settings=settings,
                plan=plan,
                candidate_payload=payload,
                original_representation={"id": payload["v"]},
                original_content_digest=None,
                actor_type="system",
                actor_id="worker-04",
            )
        )
    latest = store.get_latest_state_for_canonical("lic-4a")
    assert latest is not None
    assert latest.id == states[-1].id
    assert store.get_state(states[0].id) == states[0]


def test_audit_ordering_is_occurred_at_then_uuid():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    state = store.record_plan(
        canonical_license_id="lic-5",
        source_kind="custom",
        source_record_ref="ref-5",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 1},
        original_representation={"v": 1},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-05",
    )
    event1 = OpenRelPolicyEvent(
        id=uuid.uuid4(),
        policy_state_id=state.id,
        event_type="review-approved",
        actor_type="system",
        actor_id="worker-05",
        before_status="pending-review",
        after_status="approved",
        details={"step": "one"},
        occurred_at=state.created_at - timedelta(seconds=1),
        created_at=state.created_at,
    )
    event2 = OpenRelPolicyEvent(
        id=uuid.uuid4(),
        policy_state_id=state.id,
        event_type="applied",
        actor_type="system",
        actor_id="worker-05",
        before_status="approved",
        after_status="applied",
        details={"step": "two"},
        occurred_at=state.created_at + timedelta(seconds=1),
        created_at=state.created_at,
    )
    session.add(event1)
    session.add(event2)
    events = store.list_audit_events_for_state(state.id)
    assert [evt.event_type for evt in events] == ["review-approved", "planned", "applied"]


def test_each_allowed_transition_succeeds_and_tracks_event():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    review_plan = FakePlanBuilder.default_plan(review_required=True, apply_allowed=True)
    apply_plan = FakePlanBuilder.default_plan(review_required=False, apply_allowed=True)
    state = store.record_plan(
        canonical_license_id="lic-6",
        source_kind="custom",
        source_record_ref="ref-6",
        settings=settings,
        plan=review_plan,
        candidate_payload={"v": 6},
        original_representation={"v": 6},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-06",
    )
    approved = store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com")
    assert approved.status == "approved"
    failed = store.transition_status(
        state.id,
        new_status="failed",
        error_code="E-1",
        error_detail={"msg": "boom"},
    )
    assert failed.status == "failed"

    state2 = store.record_plan(
        canonical_license_id="lic-6b",
        source_kind="custom",
        source_record_ref="ref-6b",
        settings=settings,
        plan=apply_plan,
        candidate_payload={"v": 6, "action": "apply"},
        original_representation={"v": 6},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-06b",
    )
    applied = store.transition_status(state2.id, new_status="applied")
    assert applied.status == "applied"

    state3 = store.record_plan(
        canonical_license_id="lic-6c",
        source_kind="custom",
        source_record_ref="ref-6c",
        settings=settings,
        plan=apply_plan,
        candidate_payload={"v": 6, "action": "rollback"},
        original_representation={"v": 6},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-06c",
    )
    applied_for_rollback = store.transition_status(state3.id, new_status="applied")
    rolled_back = store.transition_status(applied_for_rollback.id, new_status="rolled-back")
    assert rolled_back.status == "rolled-back"


def test_invalid_transition_rejected():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    state = store.record_plan(
        canonical_license_id="lic-7",
        source_kind="custom",
        source_record_ref="ref-7",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 7},
        original_representation={"v": 7},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-07",
    )
    try:
        store.transition_status(state.id, new_status="approved")
        raise AssertionError("approval without reviewer should fail")
    except OpenRelPolicyTransitionError:
        pass


def test_application_rules_are_enforced():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings(mode=OpenRelPolicyMode.active)
    plan = FakePlanBuilder.default_plan(apply_allowed=False, review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-8",
        source_kind="custom",
        source_record_ref="ref-8",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 8},
        original_representation={"v": 8},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-08",
    )
    try:
        store.transition_status(state.id, new_status="applied")
        raise AssertionError("apply without allow should fail")
    except OpenRelPolicyTransitionError:
        pass


def test_rollback_requires_original_representation():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    state = store.record_plan(
        canonical_license_id="lic-9",
        source_kind="custom",
        source_record_ref="ref-9",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 9},
        original_representation=None,
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-09",
    )
    state.status = "applied"
    state.apply_allowed = True
    try:
        store.transition_status(state.id, new_status="rolled-back")
        raise AssertionError("rollback without original representation should fail")
    except OpenRelPolicyTransitionError:
        pass


def test_exact_transition_retry_is_idempotent():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-10",
        source_kind="custom",
        source_record_ref="ref-10",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 10},
        original_representation={"v": 10},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-10",
    )
    first = store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com")
    second = store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com")
    assert first.id == second.id
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)]) == 2


def test_failure_requires_error_code_and_sanitizes_detail():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-11",
        source_kind="custom",
        source_record_ref="ref-11",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 11},
        original_representation={"v": 11},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-11",
    )
    try:
        store.transition_status(state.id, new_status="failed", error_code=" ", error_detail={"Authorization": "Bearer secret"})
        raise AssertionError("missing error code should fail")
    except OpenRelPolicyTransitionError:
        pass

    failed = store.transition_status(
        state.id,
        new_status="failed",
        error_code="E-11",
        error_detail={"Authorization": "Bearer secret", "nested": {"token": "abc", "value": "x" * 2000}},
    )
    assert failed.status == "failed"
    assert failed.error_code == "E-11"
    assert "secret" not in str(failed.error_detail).lower()
    assert "abc" not in str(failed.error_detail).lower()


def test_review_reason_is_recorded_in_new_audit_event_only():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-review-reason",
        source_kind="custom",
        source_record_ref="ref-review-reason",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 12},
        original_representation={"v": 12},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-12",
    )
    approved = store.transition_status(
        state.id,
        new_status="approved",
        reviewer_identity="curator@example.com",
        review_reason='{"reason":"approve this","token":"secret"}',
    )
    assert approved.reviewed_by == "curator@example.com"
    events = [obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.policy_state_id == state.id]
    review_event = next(evt for evt in events if evt.event_type == "review-approved")
    assert "secret" not in review_event.details["review_reason"]
    assert "[REDACTED]" in review_event.details["review_reason"]
    assert "approve this" in review_event.details["review_reason"]


def test_plain_review_reason_is_trimmed_and_preserved():
    assert sanitize_review_reason("  approve this  ") == "approve this"


def test_plain_review_reason_is_bounded_to_512_characters():
    value = "a" * 600
    assert sanitize_review_reason(value) == "a" * 512


def test_json_object_review_reason_is_sanitized_recursively():
    sanitized = sanitize_review_reason('{"token":"secret","nested":{"password":"pw"},"note":"approve"}')
    assert sanitized == '{"nested":{"password":"[REDACTED]"},"note":"approve","token":"[REDACTED]"}'


def test_json_array_review_reason_is_sanitized_recursively():
    sanitized = sanitize_review_reason('[{"api_key":"xyz"},{"note":"approve"}]')
    assert sanitized == '[{"api_key":"[REDACTED]"},{"note":"approve"}]'


def test_oversized_structured_review_reason_is_bounded_to_valid_json_deterministically():
    value = json.dumps(
        {
            "token": "secret",
            "items": [{"note": "approve", "blob": "x" * 480}, {"password": "pw"}],
            "tail": "y" * 200,
        },
        separators=(",", ":"),
    )
    first = sanitize_review_reason(value)
    second = sanitize_review_reason(value)
    assert first == second
    assert first is not None
    assert len(first) <= 512
    parsed = json.loads(first)
    assert isinstance(parsed, (dict, list))
    assert "secret" not in first
    assert "pw" not in first
    assert "[REDACTED]" in first
    assert "[TRUNCATED]" in first


def test_oversized_structured_review_reason_without_sensitive_fields_does_not_add_redaction_marker():
    value = json.dumps({"items": [{"note": "approve", "blob": "x" * 480}], "tail": "y" * 200}, separators=(",", ":"))
    result = sanitize_review_reason(value)
    assert result is not None
    assert len(result) <= 512
    json.loads(result)
    assert "[TRUNCATED]" in result
    assert "[REDACTED]" not in result


def test_fitting_structured_review_reason_remains_unchanged():
    value = '{"note":"approve","token":"secret"}'
    assert sanitize_review_reason(value) == '{"note":"approve","token":"[REDACTED]"}'


def test_duplicate_json_key_review_reason_is_rejected():
    try:
        sanitize_review_reason('{"token":"a","token":"b"}')
        raise AssertionError("duplicate keys should fail")
    except OpenRelPolicyTransitionError:
        pass


def test_malformed_json_like_review_reason_is_rejected_without_mutation():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-review-malformed",
        source_kind="custom",
        source_record_ref="ref-review-malformed",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 13},
        original_representation={"v": 13},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-13",
    )
    before_events = len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)])
    try:
        store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com", review_reason='{"token"')
        raise AssertionError("malformed structured reason should fail")
    except OpenRelPolicyTransitionError:
        pass
    assert state.status == "pending-review"
    after_events = len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)])
    assert before_events == after_events


def test_plain_review_reason_redacts_bearer_and_assignments_case_insensitively():
    sanitized = sanitize_review_reason("Bearer secret-value token=abc Password=pw api_key=key SECRET=top")
    assert "secret-value" not in sanitized
    assert "abc" not in sanitized
    assert "pw" not in sanitized
    assert "top" not in sanitized
    assert sanitized.count("[REDACTED]") == 5
    assert "api_key=[REDACTED]" in sanitized


def test_review_reason_input_remains_unchanged():
    value = '{"token":"secret","note":"approve"}'
    original = str(value)
    sanitize_review_reason(value)
    assert value == original


def test_reject_transition_also_sanitizes_review_reason():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-review-reject",
        source_kind="custom",
        source_record_ref="ref-review-reject",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 14},
        original_representation={"v": 14},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-14",
    )
    rejected = store.transition_status(
        state.id,
        new_status="rejected",
        reviewer_identity="curator@example.com",
        review_reason="token=abc reject",
    )
    assert rejected.status == "rejected"
    event = next(obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.event_type == "review-rejected")
    assert event.details["review_reason"] == "token=[REDACTED] reject"


def test_exact_retry_with_review_reason_creates_no_duplicate_event():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-review-retry",
        source_kind="custom",
        source_record_ref="ref-review-retry",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 15},
        original_representation={"v": 15},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-15",
    )
    first = store.transition_status(
        state.id,
        new_status="approved",
        reviewer_identity="curator@example.com",
        review_reason='{"token":"secret","note":"approve"}',
    )
    second = store.transition_status(
        state.id,
        new_status="approved",
        reviewer_identity="curator@example.com",
        review_reason='{"token":"secret","note":"approve"}',
    )
    assert first.id == second.id
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.event_type == "review-approved"]) == 1


def test_audit_sanitizer_redacts_secrets_and_does_not_mutate_input():
    source = {
        "Authorization": "Bearer secret",
        "nested": {"password": "p@ss", "items": ["ok", {"api_key": "1111"}]},
        "safe": "hello",
    }
    original = deepcopy(source)
    sanitized = sanitize_audit_details(source, max_depth=4, max_string_length=32)
    assert source == original
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["items"][1]["api_key"] == "[REDACTED]"
    assert isinstance(sanitized["safe"], str)


def test_session_transaction_is_shared():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    state = store.record_plan(
        canonical_license_id="lic-12",
        source_kind="custom",
        source_record_ref="ref-12",
        settings=settings,
        plan=plan,
        candidate_payload={"v": 12},
        original_representation={"v": 12},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-12",
    )
    assert state in session._objects
    assert next(obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)).policy_state_id == state.id


def test_nested_tuple_value_is_normalized_to_json_list_and_input_is_unchanged():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    payload = {"items": (1, {"b": 2, "a": (3, 4)})}
    original = deepcopy(payload)
    state = store.record_plan(
        canonical_license_id="lic-13",
        source_kind="custom",
        source_record_ref="ref-13",
        settings=_settings(),
        plan=FakePlanBuilder.default_plan(),
        candidate_payload=payload,
        original_representation={"nested": ("x", "y")},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-13",
    )
    assert payload == original
    assert state.candidate_payload["items"][0] == 1
    assert state.candidate_payload["items"][1]["a"] == [3, 4]
    assert state.original_representation["nested"] == ["x", "y"]


def test_nan_and_infinity_values_are_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            compute_candidate_digest({"bad": bad})
            raise AssertionError("domain error expected")
        except OpenRelPolicyPlanValidationError:
            pass


def test_unsupported_non_json_types_are_rejected_before_session_mutation():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    for payload in ({"bytes": b"x"}, {"set": {1, 2}}, {"date": date(2026, 9, 4)}, {"obj": object()}):
        try:
            store.record_plan(
                canonical_license_id="lic-14",
                source_kind="custom",
                source_record_ref="ref-14",
                settings=_settings(),
                plan=FakePlanBuilder.default_plan(),
                candidate_payload=payload,
                original_representation={"value": "ok"},
                original_content_digest=None,
                actor_type="system",
                actor_id="worker-14",
            )
            raise AssertionError("validation should fail")
        except OpenRelPolicyPlanValidationError:
            pass
    assert session.flush_count == 0
    assert len(session._objects) == 0


def test_imported_plan_is_projected_to_none_and_requested_action_only_in_details():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings(mode=OpenRelPolicyMode.active)
    plan = FakePlanBuilder.default_plan(action=OpenRelPolicyAction.full_replacement, review_required=False, apply_allowed=True)
    state = store.record_plan(
        canonical_license_id="lic-15",
        source_kind="federation-imported",
        source_record_ref="imported-15",
        settings=settings,
        plan=plan,
        candidate_payload={"content": "imported"},
        original_representation={"payload": "imported"},
        original_content_digest=None,
        actor_type="admin",
        actor_id=" admin@example.com ",
    )
    assert state.action == "none"
    assert state.apply_allowed is False
    assert state.review_required is True
    event = next(obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent))
    assert event.details["requested_action"] == "full-replacement"
    assert event.details["action"] == "none"


def test_invalid_settings_and_actor_inputs_are_rejected_before_mutation():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    bad_settings = _settings(enabled=False)
    try:
        store.record_plan(
            canonical_license_id="lic-16",
            source_kind="custom",
            source_record_ref="ref-16",
            settings=bad_settings,
            plan=FakePlanBuilder.default_plan(),
            candidate_payload={"ok": 1},
            original_representation={"ok": 1},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-16",
        )
        raise AssertionError("settings validation expected")
    except OpenRelPolicyPlanValidationError:
        pass
    try:
        store.record_plan(
            canonical_license_id="lic-17",
            source_kind="custom",
            source_record_ref="ref-17",
            settings=_settings(),
            plan=FakePlanBuilder.default_plan(),
            candidate_payload={"ok": 2},
            original_representation={"ok": 2},
            original_content_digest=None,
            actor_type="invalid",
            actor_id="worker-17",
        )
        raise AssertionError("actor validation expected")
    except OpenRelPolicyPlanValidationError:
        pass
    try:
        store.record_plan(
            canonical_license_id="lic-18",
            source_kind="custom",
            source_record_ref="ref-18",
            settings=_settings(),
            plan=FakePlanBuilder.default_plan(),
            candidate_payload={"ok": 3},
            original_representation={"ok": 3},
            original_content_digest=None,
            actor_type="system",
            actor_id="   ",
        )
        raise AssertionError("blank actor id expected")
    except OpenRelPolicyPlanValidationError:
        pass
    assert session.flush_count == 0


def test_original_representation_must_be_normalized_and_collision_reports_field_name():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan()
    first = store.record_plan(
        canonical_license_id="lic-19",
        source_kind="custom",
        source_record_ref="ref-19",
        settings=settings,
        plan=plan,
        candidate_payload={"value": (1, 2)},
        original_representation={"nested": ("a", "b")},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-19",
    )
    try:
        store.record_plan(
            canonical_license_id="lic-19",
            source_kind="custom",
            source_record_ref="ref-19-alt",
            settings=settings,
            plan=plan,
            candidate_payload={"value": (1, 2)},
            original_representation={"nested": ("a", "b")},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-19",
        )
        raise AssertionError("collision expected")
    except OpenRelPolicyStoreCollisionError as exc:
        assert "source_record_ref" in str(exc)
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyState)]) == 1
    assert len([obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent)]) == 1
    assert first.original_representation["nested"] == ["a", "b"]


def test_exact_replay_does_not_flush_again_and_retry_requires_matching_review_or_error_code():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-20",
        source_kind="custom",
        source_record_ref="ref-20",
        settings=settings,
        plan=plan,
        candidate_payload={"value": 20},
        original_representation={"value": 20},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-20",
    )
    first_flush = session.flush_count
    replay = store.record_plan(
        canonical_license_id="lic-20",
        source_kind="custom",
        source_record_ref="ref-20",
        settings=settings,
        plan=plan,
        candidate_payload={"value": 20},
        original_representation={"value": 20},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-20",
    )
    assert replay.id == state.id
    assert session.flush_count == first_flush

    approved = store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com")
    try:
        store.transition_status(state.id, new_status="approved", reviewer_identity="other@example.com")
        raise AssertionError("mismatched reviewer retry should fail")
    except OpenRelPolicyTransitionError:
        pass
    failed_state = store.transition_status(state.id, new_status="failed", error_code="E-9", error_detail={"safe": "value"})
    try:
        store.transition_status(failed_state.id, new_status="failed", error_code="E-10")
        raise AssertionError("mismatched failed retry should fail")
    except OpenRelPolicyTransitionError:
        pass


def test_planned_to_planned_and_pending_review_to_pending_review_are_rejected():
    session = FakeSession()
    store = OpenRelPolicyStore(session)
    settings = _settings()
    plan = FakePlanBuilder.default_plan(review_required=True)
    state = store.record_plan(
        canonical_license_id="lic-21",
        source_kind="custom",
        source_record_ref="ref-21",
        settings=settings,
        plan=plan,
        candidate_payload={"value": 21},
        original_representation={"value": 21},
        original_content_digest=None,
        actor_type="system",
        actor_id="worker-21",
    )
    try:
        store.transition_status(state.id, new_status="planned")
        raise AssertionError("planned->planned should fail")
    except OpenRelPolicyTransitionError:
        pass

    approved = store.transition_status(state.id, new_status="approved", reviewer_identity="curator@example.com")
    try:
        store.transition_status(approved.id, new_status="pending-review")
        raise AssertionError("pending-review retry should fail")
    except OpenRelPolicyTransitionError:
        pass


# This module intentionally exercises logic in-memory without PostgreSQL-specific validation.
