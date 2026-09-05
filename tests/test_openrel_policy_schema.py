from __future__ import annotations

from pathlib import Path

from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID

from src.license_facade_service.db.base import Base
from src.license_facade_service.db.models.custom_licence import CustomLicenceRepresentation
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState


REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_01_PATH = REPO_ROOT / "alembic" / "versions" / "20260904_01_openrel_policy_state.py"
MIGRATION_02_PATH = REPO_ROOT / "alembic" / "versions" / "20260904_02_openrel_policy_apply_rollback.py"
MIGRATION_03_PATH = REPO_ROOT / "alembic" / "versions" / "20260904_03_federation_event_idempotency.py"


def _normalized_constraint_sql(expression: str) -> str:
    return " ".join(expression.strip().lower().split())


def _constraint_sql_for(table_name: str, constraint_name: str) -> str:
    table = Base.metadata.tables[table_name]
    constraint = next(c for c in table.constraints if getattr(c, "name", None) == constraint_name)
    return _normalized_constraint_sql(str(constraint.sqltext))


def test_models_are_registered_in_base_metadata():
    assert "openrel_policy_states" in Base.metadata.tables
    assert "openrel_policy_events" in Base.metadata.tables
    assert "custom_licence_representations" in Base.metadata.tables
    assert OpenRelPolicyState.__tablename__ == "openrel_policy_states"
    assert OpenRelPolicyEvent.__tablename__ == "openrel_policy_events"
    assert CustomLicenceRepresentation.__tablename__ == "custom_licence_representations"


def test_state_table_has_apply_rollback_columns_and_types():
    table = Base.metadata.tables["openrel_policy_states"]
    required = {
        "target_custom_licence_id",
        "target_snapshot_before",
        "target_digest_before",
        "target_snapshot_after",
        "target_digest_after",
        "applied_by",
        "rolled_back_by",
    }
    assert required.issubset({column.name for column in table.columns})
    assert isinstance(table.c.target_custom_licence_id.type, UUID)
    assert isinstance(table.c.target_snapshot_before.type, JSONB)
    assert isinstance(table.c.target_snapshot_after.type, JSONB)
    assert table.c.applied_by.nullable is True
    assert table.c.rolled_back_by.nullable is True


def test_custom_licence_representation_table_has_required_columns_and_types():
    table = Base.metadata.tables["custom_licence_representations"]
    required = {
        "id",
        "custom_licence_id",
        "representation_type",
        "status",
        "media_type",
        "profile_uri",
        "vocabulary_uri",
        "content",
        "href",
        "content_digest_sha256",
        "mapping_profile",
        "mapping_provenance",
        "source_policy_state_id",
        "created_at",
        "updated_at",
        "rolled_back_at",
    }
    assert required.issubset({column.name for column in table.columns})
    assert isinstance(table.c.id.type, UUID)
    assert isinstance(table.c.custom_licence_id.type, UUID)
    assert isinstance(table.c.source_policy_state_id.type, UUID)
    assert isinstance(table.c.content.type, JSONB)
    assert isinstance(table.c.mapping_provenance.type, JSONB)
    assert table.c.mapping_provenance.nullable is False


def test_policy_state_constraints_and_indexes_include_apply_rollback_rules():
    table = Base.metadata.tables["openrel_policy_states"]
    check_names = {constraint.name for constraint in table.constraints if isinstance(constraint, CheckConstraint) and constraint.name}
    assert {
        "ck_orps_target_digest_before_fmt",
        "ck_orps_target_digest_after_fmt",
        "ck_orps_applied_fields",
        "ck_orps_rollback_fields",
        "ck_orps_pre_rb_null",
    }.issubset(check_names)
    assert "ix_openrel_policy_states_target_custom_licence_id" in {index.name for index in table.indexes if index.name}


def test_representation_constraints_indexes_and_fks_exist():
    table = Base.metadata.tables["custom_licence_representations"]
    check_names = {constraint.name for constraint in table.constraints if isinstance(constraint, CheckConstraint) and constraint.name}
    assert {
        "ck_clr_repr_type",
        "ck_clr_status",
        "ck_clr_content_or_href",
        "ck_clr_href_https",
        "ck_clr_digest",
        "ck_clr_rb_consistent",
    }.issubset(check_names)
    assert "uq_clr_policy_repr" in {constraint.name for constraint in table.constraints if getattr(constraint, "name", None)}
    assert {"ix_clr_custom_licence_id", "ix_clr_source_policy_state_id"}.issubset({index.name for index in table.indexes if index.name})
    fks = {fk.constraint.name: (fk.target_fullname, fk.ondelete) for fk in table.foreign_keys}
    assert fks["fk_clr_custom_licence"] == ("custom_licences.id", "CASCADE")
    assert fks["fk_clr_policy_state"] == ("openrel_policy_states.id", "RESTRICT")


def test_relationships_and_delete_behavior_are_declared():
    assert CustomLicenceRepresentation.custom_licence.property.back_populates == "representations"
    assert OpenRelPolicyState.__table__.c.target_custom_licence_id.foreign_keys


def test_migrations_point_to_expected_revisions_and_contain_new_objects():
    migration_01 = MIGRATION_01_PATH.read_text()
    migration_02 = MIGRATION_02_PATH.read_text()
    migration_03 = MIGRATION_03_PATH.read_text()
    assert 'revision: str = "20260904_01"' in migration_01
    assert 'revision: str = "20260904_02"' in migration_02
    assert 'down_revision: Union[str, Sequence[str], None] = "20260904_01"' in migration_02
    assert 'revision: str = "20260904_03"' in migration_03
    assert 'down_revision: Union[str, Sequence[str], None] = "20260904_02"' in migration_03
    assert "custom_licence_representations" in migration_02
    assert "target_custom_licence_id" in migration_02
    assert "idempotency_key" in migration_03
    assert "uix_fce_authority_idempotency" in migration_03


def test_federation_change_event_idempotency_column_and_partial_index_declared():
    table = Base.metadata.tables["federation_change_events"]
    assert "idempotency_key" in table.columns
    assert isinstance(table.c.idempotency_key.type, UUID)
    assert table.c.idempotency_key.nullable is True
    index = next(index for index in table.indexes if index.name == "uix_fce_authority_idempotency")
    assert [column.name for column in index.columns] == ["authority_node_id", "idempotency_key"]
    assert index.unique is True
    assert str(index.dialect_options["postgresql"]["where"]) == "idempotency_key IS NOT NULL"


def test_constraint_sql_matches_model_and_migration_for_new_rules():
    expectations = {
        "ck_orps_applied_fields": "(status <> 'applied') or (applied_at is not null and applied_by is not null and target_custom_licence_id is not null and target_snapshot_before is not null and target_digest_before is not null and target_snapshot_after is not null and target_digest_after is not null and action <> 'none' and apply_allowed = true and policy_mode = 'active' and source_kind <> 'federation-imported')",
        "ck_orps_rollback_fields": "(status <> 'rolled-back') or (rolled_back_at is not null and rolled_back_by is not null and applied_at is not null and applied_by is not null and target_custom_licence_id is not null and target_snapshot_before is not null and target_digest_before is not null and target_snapshot_after is not null and target_digest_after is not null and original_representation is not null)",
        "ck_orps_pre_rb_null": "(status in ('applied','rolled-back')) or (rolled_back_at is null and rolled_back_by is null)",
        "ck_clr_content_or_href": "(content is not null) or (href is not null)",
    }
    migration_text = _normalized_constraint_sql(MIGRATION_02_PATH.read_text())
    for name, expression in expectations.items():
        table_name = "openrel_policy_states" if name.startswith("ck_orps") else "custom_licence_representations"
        assert _normalized_constraint_sql(_constraint_sql_for(table_name, name)) == expression
        assert expression in migration_text


def test_named_identifiers_fit_postgresql_63_byte_limit():
    names = {
        "fk_orps_target_custom_licence",
        "ix_orps_target_custom_licence_id",
        "ck_orps_target_digest_before_fmt",
        "ck_orps_target_digest_after_fmt",
        "ck_orps_applied_fields",
        "ck_orps_rollback_fields",
        "ck_orps_pre_rb_null",
        "fk_clr_custom_licence",
        "fk_clr_policy_state",
        "ck_clr_repr_type",
        "ck_clr_status",
        "ck_clr_content_or_href",
        "ck_clr_href_https",
        "ck_clr_digest",
        "ck_clr_rb_consistent",
        "uq_clr_policy_repr",
        "ix_clr_custom_licence_id",
        "ix_clr_source_policy_state_id",
        "uix_fce_authority_idempotency",
    }
    assert all(len(name) <= 63 for name in names)
