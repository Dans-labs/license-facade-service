from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

from tests.schema_init import (
    ALEMBIC_HEAD_REVISION,
    CUSTOM_TABLES,
    FEDERATION_TABLES,
    PHASE5_HEAD_REVISION,
    assert_custom_model_migration_parity,
    docker_available,
    free_port,
    list_public_tables,
    now_utc,
    read_current_revision,
    run_alembic,
    start_postgres_container,
    stop_postgres_container,
)


@pytest.fixture()
def postgres_db() -> str:
    if not docker_available():
        pytest.skip("docker not available for schema init tests")
    container_name = f"lfs-schema-{uuid4().hex[:8]}"
    port = free_port()
    dsn = start_postgres_container(container_name, port)
    try:
        yield dsn
    finally:
        stop_postgres_container(container_name)


def _insert_custom_licence(raw_dsn: str) -> str:
    licence_id = str(uuid4())
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licences (
                    id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                    public_scope, federation_status, spdx_submission_status, lifecycle_status,
                    name, summary, description, license_text, normalized_text_digest, spdx_jsonld,
                    creator_role, created_at, updated_at
                ) VALUES (
                    %s, 'node-a', 'SchemaTest', '1.0', 'lfs-custom:node-a:SchemaTest:1.0', %s,
                    'federated', 'not_published', 'not_requested', 'registered',
                    'Schema Test', NULL, NULL, 'Schema test text', %s, '{}'::jsonb,
                    'curator', %s, %s
                )
                """,
                (licence_id, str(uuid4()), "a" * 64, now_utc(), now_utc()),
            )
        conn.commit()
    return licence_id


def _insert_federation_record_and_event(raw_dsn: str) -> tuple[str, str]:
    record_id = str(uuid4())
    event_id = str(uuid4())
    suffix = uuid4().hex[:8]
    local_id = f"rec-{suffix}"
    canonical_id = f"lfs:node-a:{local_id}:1.0"
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_records (
                    id, authority_node_id, local_id, version, canonical_id, resolving_uuid,
                    is_authoritative, payload, payload_digest_sha256, materialized_generation,
                    lifecycle_state, created_at, updated_at
                ) VALUES (
                    %s, 'node-a', %s, '1.0', %s, %s,
                    true, '{}'::jsonb, %s, 0,
                    'published', %s, %s
                )
                """,
                (record_id, local_id, canonical_id, str(uuid4()), "b" * 64, now_utc(), now_utc()),
            )
            cur.execute(
                """
                INSERT INTO federation_change_events (
                    id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at,
                    payload_schema_version, signed_payload, signed_payload_digest_sha256,
                    signature_base64url, signature_kid, signature_alg, provenance_type,
                    event_payload, event_digest_sha256, occurred_at, created_at
                ) VALUES (
                    %s, nextval('federation_change_event_sequence'), 'record.changed', 'node-a', %s, 'upsert', %s,
                    '1', '{}'::jsonb, %s, 'sig', 'kid-a1', 'EdDSA', 'publication',
                    '{}'::jsonb, %s, %s, %s
                )
                """,
                (event_id, record_id, now_utc(), "c" * 64, "d" * 64, now_utc(), now_utc()),
            )
        conn.commit()
    return record_id, event_id


def _function_exists(raw_dsn: str, signature: str) -> bool:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regprocedure(%s) IS NOT NULL", (signature,))
            return bool(cur.fetchone()[0])


def _event_trigger_function_names(raw_dsn: str) -> dict[str, str]:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.tgname, p.proname
                FROM pg_trigger t
                JOIN pg_proc p ON p.oid = t.tgfoid
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname = 'federation_change_events'
                  AND t.tgname IN ('trg_federation_change_events_no_update', 'trg_federation_change_events_no_delete')
                  AND NOT t.tgisinternal
                ORDER BY t.tgname
                """
            )
            return {str(name): str(fn) for name, fn in cur.fetchall()}


def _assert_federation_change_events_append_only(raw_dsn: str) -> None:
    _record_id, event_id = _insert_federation_record_and_event(raw_dsn)
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute("UPDATE federation_change_events SET operation = 'deprecate' WHERE id = %s", (event_id,))
            conn.rollback()
            with pytest.raises(psycopg.Error):
                cur.execute("DELETE FROM federation_change_events WHERE id = %s", (event_id,))
            conn.rollback()


def test_alembic_fresh_install_and_idempotent_upgrade(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", "head")

    tables = list_public_tables(postgres_db)
    assert FEDERATION_TABLES <= tables
    assert CUSTOM_TABLES <= tables
    assert read_current_revision(postgres_db) == ALEMBIC_HEAD_REVISION

    heads = run_alembic(postgres_db, "heads")
    assert heads.stdout.count("(head)") == 1
    assert ALEMBIC_HEAD_REVISION in heads.stdout

    run_alembic(postgres_db, "upgrade", "head")
    assert read_current_revision(postgres_db) == ALEMBIC_HEAD_REVISION
    assert FEDERATION_TABLES <= list_public_tables(postgres_db)
    assert CUSTOM_TABLES <= list_public_tables(postgres_db)


def test_upgrade_downgrade_repeatability_when_custom_tables_empty(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", PHASE5_HEAD_REVISION)
    run_alembic(postgres_db, "upgrade", ALEMBIC_HEAD_REVISION)
    run_alembic(postgres_db, "downgrade", PHASE5_HEAD_REVISION)
    assert CUSTOM_TABLES.isdisjoint(list_public_tables(postgres_db))
    run_alembic(postgres_db, "upgrade", ALEMBIC_HEAD_REVISION)
    assert read_current_revision(postgres_db) == ALEMBIC_HEAD_REVISION
    assert CUSTOM_TABLES <= list_public_tables(postgres_db)


def test_legacy_change_event_function_cleanup_roundtrip(postgres_db: str) -> None:
    raw_dsn = postgres_db.replace("+psycopg", "")

    run_alembic(postgres_db, "upgrade", PHASE5_HEAD_REVISION)
    assert _function_exists(raw_dsn, "lfs_reject_change_events_mutation()")
    assert _function_exists(raw_dsn, "lfs_reject_federation_change_events_mutation()")
    triggers_phase5 = _event_trigger_function_names(raw_dsn)
    assert triggers_phase5 == {
        "trg_federation_change_events_no_delete": "lfs_reject_federation_change_events_mutation",
        "trg_federation_change_events_no_update": "lfs_reject_federation_change_events_mutation",
    }
    _assert_federation_change_events_append_only(raw_dsn)

    run_alembic(postgres_db, "upgrade", ALEMBIC_HEAD_REVISION)
    assert not _function_exists(raw_dsn, "lfs_reject_change_events_mutation()")
    assert _function_exists(raw_dsn, "lfs_reject_federation_change_events_mutation()")
    triggers_head = _event_trigger_function_names(raw_dsn)
    assert triggers_head == triggers_phase5
    _assert_federation_change_events_append_only(raw_dsn)

    run_alembic(postgres_db, "downgrade", PHASE5_HEAD_REVISION)
    assert _function_exists(raw_dsn, "lfs_reject_change_events_mutation()")
    assert _function_exists(raw_dsn, "lfs_reject_federation_change_events_mutation()")
    triggers_downgraded = _event_trigger_function_names(raw_dsn)
    assert triggers_downgraded == triggers_phase5
    _assert_federation_change_events_append_only(raw_dsn)

    run_alembic(postgres_db, "upgrade", ALEMBIC_HEAD_REVISION)
    assert not _function_exists(raw_dsn, "lfs_reject_change_events_mutation()")
    assert _function_exists(raw_dsn, "lfs_reject_federation_change_events_mutation()")
    triggers_reupgraded = _event_trigger_function_names(raw_dsn)
    assert triggers_reupgraded == triggers_phase5
    _assert_federation_change_events_append_only(raw_dsn)


def test_downgrade_refuses_when_custom_data_exists(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", "head")
    raw_dsn = postgres_db.replace("+psycopg", "")
    _insert_custom_licence(raw_dsn)

    downgrade = run_alembic(postgres_db, "downgrade", PHASE5_HEAD_REVISION, check=False)
    assert downgrade.returncode != 0
    assert "Cannot downgrade 20260828_01 while custom-licence tables contain data" in (downgrade.stdout + downgrade.stderr)
    assert read_current_revision(postgres_db) == ALEMBIC_HEAD_REVISION


def test_custom_licence_audit_events_are_append_only(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", "head")
    raw_dsn = postgres_db.replace("+psycopg", "")
    licence_id = _insert_custom_licence(raw_dsn)
    audit_id = str(uuid4())

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licence_audit_events (
                    id, custom_licence_id, event_type, actor_role, before_state, after_state, source, created_at
                ) VALUES (%s, %s, 'created', 'curator', '{}'::jsonb, '{}'::jsonb, 'schema-test', %s)
                """,
                (audit_id, licence_id, now_utc()),
            )
        conn.commit()

        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute("UPDATE custom_licence_audit_events SET source = 'updated' WHERE id = %s", (audit_id,))
            conn.rollback()
            with pytest.raises(psycopg.Error):
                cur.execute("DELETE FROM custom_licence_audit_events WHERE id = %s", (audit_id,))
            conn.rollback()


def test_custom_outbox_foreign_keys_accept_valid_links_and_reject_invalid(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", "head")
    raw_dsn = postgres_db.replace("+psycopg", "")
    licence_id = _insert_custom_licence(raw_dsn)
    record_id, event_id = _insert_federation_record_and_event(raw_dsn)

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licence_federation_outbox (
                    id, custom_licence_id, operation, status, attempt_count, available_at,
                    lease_owner, lease_expires_at, last_error_class, last_error_at,
                    federation_record_id, federation_event_id, created_at, updated_at, published_at
                ) VALUES (
                    %s, %s, 'upsert', 'published', 0, %s,
                    NULL, NULL, NULL, NULL,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid4()),
                    licence_id,
                    now_utc(),
                    record_id,
                    event_id,
                    now_utc(),
                    now_utc(),
                    now_utc(),
                ),
            )
        conn.commit()

        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox (
                        id, custom_licence_id, operation, status, attempt_count, available_at,
                        federation_record_id, federation_event_id, created_at, updated_at, published_at
                    ) VALUES (
                        %s, %s, 'upsert', 'published', 0, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(uuid4()),
                        licence_id,
                        now_utc(),
                        str(uuid4()),
                        str(uuid4()),
                        now_utc(),
                        now_utc(),
                        now_utc(),
                    ),
                )
            conn.rollback()


def test_custom_tables_match_sqlalchemy_metadata(postgres_db: str) -> None:
    run_alembic(postgres_db, "upgrade", "head")
    assert_custom_model_migration_parity(postgres_db)
