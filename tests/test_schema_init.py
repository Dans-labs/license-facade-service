from __future__ import annotations

import re
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.dialects import postgresql

from src.license_facade_service.db import models as _load_models  # noqa: F401
from src.license_facade_service.db.base import Base
from tests.schema_init import SCHEMA_INIT_SQL_PATH, apply_schema_init_sql

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TRIGGER_FUNCTIONS: dict[str, set[str]] = {
    "lfs_reject_custom_licence_audit_mutation": {
        "trg_custom_licence_audit_events_no_update",
        "trg_custom_licence_audit_events_no_delete",
    },
    "lfs_reject_federation_change_events_mutation": {
        "trg_federation_change_events_no_update",
        "trg_federation_change_events_no_delete",
    },
    "lfs_reject_published_record_mutation": {
        "trg_federation_records_immutable_published_content",
    },
    "lfs_reject_record_identifier_mutation": {
        "trg_federation_records_immutable_published_identifier",
    },
}

EXPECTED_PARTIAL_UNIQUE_INDEXES: dict[str, str] = {
    "uix_custom_licence_federation_outbox_federation_event_id": "WHERE (federation_event_id IS NOT NULL)",
    "uix_custom_licence_federation_outbox_federation_record_id": "WHERE (federation_record_id IS NOT NULL)",
    "uq_federation_signing_keys_single_active": "WHERE (is_active = true)",
}

EXPECTED_FK_ON_DELETE: dict[str, str] = {
    "custom_licence_aliases_custom_licence_id_fkey": "RESTRICT",
    "custom_licence_audit_events_custom_licence_id_fkey": "RESTRICT",
    "custom_licence_federation_outbox_custom_licence_id_fkey": "RESTRICT",
    "custom_licence_federation_outbox_federation_event_id_fkey": "RESTRICT",
    "custom_licence_federation_outbox_federation_record_id_fkey": "RESTRICT",
}


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _normalize_sql(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"\s+", " ", value.strip().lower())


def _normalize_type(value: object) -> str:
    return _normalize_sql(str(value)) or ""


def _start_postgres(*, container_name: str, port: int, volume_name: str | None = None, mount_init_sql: bool = False) -> str:
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_DB=lfs_schema",
    ]
    if volume_name:
        cmd.extend(["-v", f"{volume_name}:/var/lib/postgresql/data"])
    if mount_init_sql:
        cmd.extend(["-v", f"{SCHEMA_INIT_SQL_PATH}:/docker-entrypoint-initdb.d/001-lfs-schema.sql:ro"])
    cmd.extend(["-p", f"{port}:5432", "postgres:16-alpine"])
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_schema"
    raw_dsn = dsn.replace("+psycopg", "")
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            with psycopg.connect(raw_dsn):
                return dsn
        except Exception:
            time.sleep(1)
    raise RuntimeError("postgres container did not become ready in time")


def _stop_container(container_name: str) -> None:
    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _container_logs(container_name: str) -> str:
    result = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True, check=False)
    return f"{result.stdout}\n{result.stderr}"


def _assert_metadata_parity(dsn: str) -> None:
    engine = create_engine(dsn, future=True)
    try:
        inspector = inspect(engine)
        db_tables = set(inspector.get_table_names(schema="public"))
        model_tables = {table.name for table in Base.metadata.sorted_tables}
        assert db_tables == model_tables

        for table in Base.metadata.sorted_tables:
            db_columns = {column["name"]: column for column in inspector.get_columns(table.name, schema="public")}
            assert set(db_columns) == {column.name for column in table.columns}
            for column in table.columns:
                db_column = db_columns[column.name]
                model_type = column.type.compile(dialect=postgresql.dialect())
                db_type = str(db_column["type"])
                if "timestamp" in _normalize_sql(model_type or "") and "timestamp" in _normalize_sql(db_type or ""):
                    assert bool(getattr(column.type, "timezone", False)) == bool(getattr(db_column["type"], "timezone", False))
                else:
                    assert _normalize_type(db_column["type"]) == _normalize_type(model_type)
                assert bool(db_column["nullable"]) == bool(column.nullable)
                if column.server_default is not None:
                    expected_default = _normalize_sql(str(column.server_default.arg.compile(dialect=postgresql.dialect())))
                    assert _normalize_sql(db_column["default"]) == expected_default

            expected_unique = {
                constraint.name
                for constraint in table.constraints
                if constraint.__class__.__name__ == "UniqueConstraint" and constraint.name
            }
            expected_checks = {
                constraint.name
                for constraint in table.constraints
                if constraint.__class__.__name__ == "CheckConstraint" and constraint.name
            }
            expected_indexes = {index.name for index in table.indexes if index.name}

            db_unique_names = {constraint["name"] for constraint in inspector.get_unique_constraints(table.name, schema="public")}
            assert expected_unique <= db_unique_names
            assert expected_checks == {constraint["name"] for constraint in inspector.get_check_constraints(table.name, schema="public")}
            assert expected_indexes <= {index["name"] for index in inspector.get_indexes(table.name, schema="public")}

        with engine.connect() as conn:
            fk_rows = conn.exec_driver_sql(
                """
                SELECT conname, pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE contype = 'f'
                """
            ).all()
        fk_defs = {name: definition for name, definition in fk_rows}
        for name, on_delete in EXPECTED_FK_ON_DELETE.items():
            assert name in fk_defs
            assert f"ON DELETE {on_delete}" in fk_defs[name]

        with engine.connect() as conn:
            index_rows = conn.exec_driver_sql(
                """
                SELECT indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = 'public'
                """
            ).all()
        index_defs = {name: definition for name, definition in index_rows}
        for name, where_clause in EXPECTED_PARTIAL_UNIQUE_INDEXES.items():
            assert name in index_defs
            assert "CREATE UNIQUE INDEX" in index_defs[name]
            assert where_clause in index_defs[name]
    finally:
        engine.dispose()


def _assert_trigger_function_references(raw_dsn: str) -> None:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.proname, t.tgname
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                LEFT JOIN pg_trigger t ON t.tgfoid = p.oid AND NOT t.tgisinternal
                WHERE n.nspname = 'public'
                  AND p.proname LIKE 'lfs_reject_%'
                ORDER BY p.proname, t.tgname
                """
            )
            rows = cur.fetchall()
    actual: dict[str, set[str]] = {}
    for function_name, trigger_name in rows:
        actual.setdefault(function_name, set())
        if trigger_name is not None:
            actual[function_name].add(trigger_name)
    assert actual == EXPECTED_TRIGGER_FUNCTIONS
    assert "lfs_reject_change_events_mutation" not in actual


def test_schema_init_matches_metadata_and_database_objects():
    if not _docker_available():
        pytest.skip("docker not available for schema init tests")
    container_name = f"lfs-schema-init-{uuid4().hex[:8]}"
    port = _free_port()
    dsn = _start_postgres(container_name=container_name, port=port)
    try:
        apply_schema_init_sql(dsn)
        _assert_metadata_parity(dsn)
        _assert_trigger_function_references(dsn.replace("+psycopg", ""))
    finally:
        _stop_container(container_name)


def test_schema_init_enforces_append_only_immutability_and_outbox_constraints():
    if not _docker_available():
        pytest.skip("docker not available for schema init tests")
    container_name = f"lfs-schema-guards-{uuid4().hex[:8]}"
    port = _free_port()
    dsn = _start_postgres(container_name=container_name, port=port)
    raw_dsn = dsn.replace("+psycopg", "")
    try:
        apply_schema_init_sql(dsn)
        with psycopg.connect(raw_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT nextval('federation_change_event_sequence')")
                first = cur.fetchone()[0]
                cur.execute("SELECT nextval('federation_change_event_sequence')")
                second = cur.fetchone()[0]
                assert second == first + 1

                record_id = str(uuid4())
                record_resolving_uuid = str(uuid4())
                cur.execute(
                    """
                    INSERT INTO federation_records (
                        id, authority_node_id, local_id, version, canonical_id, resolving_uuid,
                        is_authoritative, payload, payload_digest_sha256, published_at, materialized_generation,
                        lifecycle_state, verification_status, last_verified_at, created_at, updated_at
                    ) VALUES (
                        %s, 'node-a', 'Local-1', '1.0', 'lfs:node-a:Local-1:1.0', %s,
                        true, '{}'::jsonb, 'digest', now(), 1,
                        'published', 'verified', now(), now(), now()
                    )
                    """,
                    (record_id, record_resolving_uuid),
                )
                event_id = str(uuid4())
                cur.execute(
                    """
                    INSERT INTO federation_change_events (
                        id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at,
                        payload_schema_version, signed_payload, signed_payload_digest_sha256, signature_base64url,
                        signature_kid, signature_alg, provenance_type, event_payload, event_digest_sha256,
                        occurred_at, created_at
                    ) VALUES (
                        %s, nextval('federation_change_event_sequence'), 'record.changed', 'node-a', %s, 'upsert', now(),
                        '1', '{}'::jsonb, 'digest', 'sig', 'kid', 'EdDSA', 'publication', '{}'::jsonb, 'digest',
                        now(), now()
                    )
                    """,
                    (event_id, record_id),
                )

                licence_id = str(uuid4())
                cur.execute(
                    """
                    INSERT INTO custom_licences (
                        id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                        public_scope, federation_status, spdx_submission_status, lifecycle_status,
                        name, license_text, normalized_text_digest, spdx_jsonld, creator_role, created_at, updated_at
                    ) VALUES (
                        %s, 'lfs-local-authority', 'SchemaTest', '1.0', 'lfs-custom:lfs-local-authority:SchemaTest:1.0', %s,
                        'federated', 'published', 'not_requested', 'registered',
                        'Schema Test', 'Schema test text', %s, '{}'::jsonb, 'curator', now(), now()
                    )
                    """,
                    (licence_id, str(uuid4()), "a" * 64),
                )
                audit_id = str(uuid4())
                cur.execute(
                    """
                    INSERT INTO custom_licence_audit_events (
                        id, custom_licence_id, event_type, actor_role, before_state, after_state, source, created_at
                    ) VALUES (%s, %s, 'created', 'curator', '{}'::jsonb, '{}'::jsonb, 'schema-test', now())
                    """,
                    (audit_id, licence_id),
                )
                conn.commit()

                with pytest.raises(psycopg.Error):
                    cur.execute("UPDATE federation_change_events SET operation = 'deprecate' WHERE id = %s", (event_id,))
                conn.rollback()
                with pytest.raises(psycopg.Error):
                    cur.execute("DELETE FROM federation_change_events WHERE id = %s", (event_id,))
                conn.rollback()

                with pytest.raises(psycopg.Error):
                    cur.execute("UPDATE custom_licence_audit_events SET source = 'updated' WHERE id = %s", (audit_id,))
                conn.rollback()
                with pytest.raises(psycopg.Error):
                    cur.execute("DELETE FROM custom_licence_audit_events WHERE id = %s", (audit_id,))
                conn.rollback()

                with pytest.raises(psycopg.Error):
                    cur.execute("UPDATE federation_records SET canonical_id = 'changed' WHERE id = %s", (record_id,))
                conn.rollback()
                with pytest.raises(psycopg.Error):
                    cur.execute("UPDATE federation_records SET resolving_uuid = %s WHERE id = %s", (str(uuid4()), record_id))
                conn.rollback()

                with pytest.raises(psycopg.Error):
                    cur.execute(
                        """
                        INSERT INTO custom_licence_federation_outbox (
                            id, custom_licence_id, operation, status, attempt_count, available_at,
                            created_at, updated_at
                        ) VALUES (%s, %s, 'upsert', 'processing', 0, now(), now(), now())
                        """,
                        (str(uuid4()), licence_id),
                    )
                conn.rollback()
                with pytest.raises(psycopg.Error):
                    cur.execute(
                        """
                        INSERT INTO custom_licence_federation_outbox (
                            id, custom_licence_id, operation, status, attempt_count, available_at,
                            created_at, updated_at, published_at
                        ) VALUES (%s, %s, 'upsert', 'published', 0, now(), now(), now(), now())
                        """,
                        (str(uuid4()), licence_id),
                    )
                conn.rollback()
                with pytest.raises(psycopg.Error):
                    cur.execute(
                        """
                        INSERT INTO custom_licence_federation_outbox (
                            id, custom_licence_id, operation, status, attempt_count, available_at,
                            created_at, updated_at, published_at, federation_record_id, federation_event_id
                        ) VALUES (%s, %s, 'upsert', 'published', -1, now(), now(), now(), now(), %s, %s)
                        """,
                        (str(uuid4()), licence_id, record_id, event_id),
                    )
                conn.rollback()
    finally:
        _stop_container(container_name)


def test_docker_entrypoint_initializes_once_and_persists_existing_volume_data():
    if not _docker_available():
        pytest.skip("docker not available for schema init tests")

    volume_name = f"lfs-schema-volume-{uuid4().hex[:8]}"
    first_container = f"lfs-schema-first-{uuid4().hex[:8]}"
    second_container = f"lfs-schema-second-{uuid4().hex[:8]}"
    port = _free_port()

    first_dsn = _start_postgres(
        container_name=first_container,
        port=port,
        volume_name=volume_name,
        mount_init_sql=True,
    )
    raw_dsn = first_dsn.replace("+psycopg", "")

    try:
        first_logs = _container_logs(first_container)
        assert "/docker-entrypoint-initdb.d/001-lfs-schema.sql" in first_logs

        with psycopg.connect(raw_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT nextval('federation_change_event_sequence')")
                before_restart_sequence = int(cur.fetchone()[0])

                record_id = str(uuid4())
                event_id = str(uuid4())
                licence_id = str(uuid4())
                cur.execute(
                    """
                    INSERT INTO federation_records (
                        id, authority_node_id, local_id, version, canonical_id, resolving_uuid,
                        is_authoritative, payload, payload_digest_sha256, published_at, materialized_generation,
                        lifecycle_state, verification_status, last_verified_at, created_at, updated_at
                    ) VALUES (
                        %s, 'node-a', 'LocalRestart', '1.0', 'lfs:node-a:LocalRestart:1.0', %s,
                        true, '{}'::jsonb, 'digest', now(), 1,
                        'published', 'verified', now(), now(), now()
                    )
                    """,
                    (record_id, str(uuid4())),
                )
                cur.execute(
                    """
                    INSERT INTO federation_change_events (
                        id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at,
                        payload_schema_version, signed_payload, signed_payload_digest_sha256, signature_base64url,
                        signature_kid, signature_alg, provenance_type, event_payload, event_digest_sha256,
                        occurred_at, created_at
                    ) VALUES (
                        %s, nextval('federation_change_event_sequence'), 'record.changed', 'node-a', %s, 'upsert', now(),
                        '1', '{}'::jsonb, 'digest', 'sig', 'kid', 'EdDSA', 'publication', '{}'::jsonb, 'digest',
                        now(), now()
                    )
                    """,
                    (event_id, record_id),
                )
                cur.execute(
                    """
                    INSERT INTO custom_licences (
                        id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                        public_scope, federation_status, spdx_submission_status, lifecycle_status,
                        name, license_text, normalized_text_digest, spdx_jsonld, creator_role, created_at, updated_at
                    ) VALUES (
                        %s, 'lfs-local-authority', 'RestartProof', '1.0', 'lfs-custom:lfs-local-authority:RestartProof:1.0', %s,
                        'federated', 'published', 'not_requested', 'registered',
                        'Restart Proof', 'Restart proof text', %s, '{}'::jsonb, 'curator', now(), now()
                    )
                    """,
                    (licence_id, str(uuid4()), "b" * 64),
                )
                cur.execute(
                    """
                    INSERT INTO custom_licence_aliases (
                        id, custom_licence_id, alias_type, alias, normalized_alias, created_at
                    ) VALUES (%s, %s, 'legacy', 'Restart Alias', 'restart alias', now())
                    """,
                    (str(uuid4()), licence_id),
                )
                cur.execute(
                    """
                    INSERT INTO custom_licence_audit_events (
                        id, custom_licence_id, event_type, actor_role, before_state, after_state, source, created_at
                    ) VALUES (%s, %s, 'created', 'curator', '{}'::jsonb, '{}'::jsonb, 'restart-test', now())
                    """,
                    (str(uuid4()), licence_id),
                )
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox (
                        id, custom_licence_id, operation, status, attempt_count, available_at,
                        federation_record_id, federation_event_id, created_at, updated_at, published_at
                    ) VALUES (%s, %s, 'upsert', 'published', 1, now(), %s, %s, now(), now(), now())
                    """,
                    (str(uuid4()), licence_id, record_id, event_id),
                )
                conn.commit()

                cur.execute("SELECT count(*) FROM custom_licence_aliases WHERE custom_licence_id = %s", (licence_id,))
                aliases_before = int(cur.fetchone()[0])
                cur.execute("SELECT count(*) FROM custom_licence_audit_events WHERE custom_licence_id = %s", (licence_id,))
                audits_before = int(cur.fetchone()[0])

        _stop_container(first_container)
        _start_postgres(
            container_name=second_container,
            port=port,
            volume_name=volume_name,
            mount_init_sql=True,
        )
        second_logs = _container_logs(second_container)
        assert "/docker-entrypoint-initdb.d/001-lfs-schema.sql" not in second_logs

        with psycopg.connect(raw_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, canonical_id, resolving_uuid, public_scope, normalized_text_digest
                    FROM custom_licences
                    WHERE requested_license_id = 'RestartProof'
                    """
                )
                row = cur.fetchone()
                assert row is not None
                assert row[1] == "lfs-custom:lfs-local-authority:RestartProof:1.0"
                assert row[3] == "federated"
                assert row[4] == "b" * 64

                cur.execute("SELECT count(*) FROM custom_licence_aliases WHERE custom_licence_id = %s", (row[0],))
                assert int(cur.fetchone()[0]) == aliases_before
                cur.execute("SELECT count(*) FROM custom_licence_audit_events WHERE custom_licence_id = %s", (row[0],))
                assert int(cur.fetchone()[0]) == audits_before

                cur.execute(
                    """
                    SELECT status, federation_record_id, federation_event_id
                    FROM custom_licence_federation_outbox
                    WHERE custom_licence_id = %s
                    """,
                    (row[0],),
                )
                outbox = cur.fetchone()
                assert outbox is not None
                assert outbox[0] == "published"
                assert outbox[1] is not None
                assert outbox[2] is not None

                cur.execute("SELECT nextval('federation_change_event_sequence')")
                sequence_after_restart = int(cur.fetchone()[0])
                assert sequence_after_restart > before_restart_sequence
    finally:
        _stop_container(first_container)
        _stop_container(second_container)
        subprocess.run(["docker", "volume", "rm", volume_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
