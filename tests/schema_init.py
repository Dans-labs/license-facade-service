from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from sqlalchemy import create_engine, inspect
from sqlalchemy.dialects import postgresql

from src.license_facade_service.db import models as _load_models  # noqa: F401
from src.license_facade_service.db.base import Base

REPO_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG_PATH = REPO_ROOT / "alembic.ini"
ALEMBIC_HEAD_REVISION = "20260904_03"
PHASE5_HEAD_REVISION = "c8b534db4b5c"
CUSTOM_TABLES = {
    "custom_licences",
    "custom_licence_aliases",
    "custom_licence_audit_events",
    "custom_licence_federation_outbox",
}
FEDERATION_TABLES = {
    table.name
    for table in Base.metadata.sorted_tables
    if table.name.startswith("federation_")
}


@dataclass(frozen=True)
class AlembicResult:
    returncode: int
    stdout: str
    stderr: str


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_postgres_container(container_name: str, port: int) -> str:
    subprocess.run(
        [
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
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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


def stop_postgres_container(container_name: str) -> None:
    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def run_alembic(database_url: str, *args: str, check: bool = True) -> AlembicResult:
    env = dict(os.environ)
    env["ALEMBIC_DATABASE_URL"] = database_url
    result = subprocess.run(
        ["uv", "run", "alembic", "-c", str(ALEMBIC_CONFIG_PATH), *args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"alembic {' '.join(args)} failed (rc={result.returncode})\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return AlembicResult(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_sql(value: str | None) -> str | None:
    if value is None:
        return None
    return " ".join(value.strip().lower().split())


def normalize_type(value: object) -> str:
    return normalize_sql(str(value)) or ""


def list_public_tables(database_url: str) -> set[str]:
    engine = create_engine(database_url, future=True)
    try:
        inspector = inspect(engine)
        return set(inspector.get_table_names(schema="public"))
    finally:
        engine.dispose()


def read_current_revision(database_url: str) -> str:
    with psycopg.connect(database_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version_num FROM alembic_version")
            return str(cur.fetchone()[0])


def assert_custom_model_migration_parity(database_url: str) -> None:
    engine = create_engine(database_url, future=True)
    try:
        inspector = inspect(engine)
        for table_name in CUSTOM_TABLES:
            model_table = Base.metadata.tables[table_name]
            db_columns = {
                column["name"]: column
                for column in inspector.get_columns(table_name, schema="public")
            }
            assert set(db_columns) == {column.name for column in model_table.columns}
            for column in model_table.columns:
                db_column = db_columns[column.name]
                model_type = column.type.compile(dialect=postgresql.dialect())
                db_type = str(db_column["type"])
                if "timestamp" in normalize_sql(model_type or "") and "timestamp" in normalize_sql(db_type or ""):
                    assert bool(getattr(column.type, "timezone", False)) == bool(getattr(db_column["type"], "timezone", False))
                else:
                    assert normalize_type(db_column["type"]) == normalize_type(model_type)
                assert bool(db_column["nullable"]) == bool(column.nullable)
                if column.server_default is None:
                    assert db_column["default"] is None
                else:
                    expected_default = normalize_sql(
                        str(column.server_default.arg.compile(dialect=postgresql.dialect()))
                    )
                    assert normalize_sql(db_column["default"]) == expected_default

            expected_unique = {
                constraint.name
                for constraint in model_table.constraints
                if constraint.__class__.__name__ == "UniqueConstraint" and constraint.name
            }
            db_unique = {
                constraint["name"]
                for constraint in inspector.get_unique_constraints(table_name, schema="public")
            }
            assert expected_unique <= db_unique

            expected_checks = {
                constraint.name
                for constraint in model_table.constraints
                if constraint.__class__.__name__ == "CheckConstraint" and constraint.name
            }
            db_checks = {
                constraint["name"]
                for constraint in inspector.get_check_constraints(table_name, schema="public")
            }
            assert expected_checks == db_checks

            expected_indexes = {index.name for index in model_table.indexes if index.name}
            db_indexes = {
                index["name"]
                for index in inspector.get_indexes(table_name, schema="public")
            }
            assert expected_indexes <= db_indexes

        with engine.connect() as conn:
            fk_rows = conn.exec_driver_sql(
                """
                SELECT conname, pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE contype = 'f'
                  AND conname LIKE 'fk_custom_licence_%%'
                """
            ).all()
            fk_defs = {name: definition for name, definition in fk_rows}

            assert "fk_custom_licence_aliases_custom_licence_id" in fk_defs
            assert "ON DELETE RESTRICT" in fk_defs["fk_custom_licence_aliases_custom_licence_id"]
            assert "fk_custom_licence_audit_events_custom_licence_id" in fk_defs
            assert "ON DELETE RESTRICT" in fk_defs["fk_custom_licence_audit_events_custom_licence_id"]
            assert "fk_custom_licence_federation_outbox_custom_licence_id" in fk_defs
            assert "ON DELETE RESTRICT" in fk_defs["fk_custom_licence_federation_outbox_custom_licence_id"]
            assert "fk_custom_licence_federation_outbox_federation_record_id" in fk_defs
            assert "ON DELETE RESTRICT" in fk_defs["fk_custom_licence_federation_outbox_federation_record_id"]
            assert "fk_custom_licence_federation_outbox_federation_event_id" in fk_defs
            assert "ON DELETE RESTRICT" in fk_defs["fk_custom_licence_federation_outbox_federation_event_id"]
    finally:
        engine.dispose()


def apply_schema_init_sql(database_url: str) -> None:
    run_alembic(database_url, "upgrade", "head")


def reset_public_schema(database_url: str) -> None:
    with psycopg.connect(database_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
            tables = [row[0] for row in cur.fetchall() if row[0] != "alembic_version"]
            if tables:
                cur.execute(
                    sql.SQL("TRUNCATE {} RESTART IDENTITY CASCADE").format(
                        sql.SQL(", ").join(sql.Identifier("public", table) for table in tables)
                    )
                )
            cur.execute("ALTER SEQUENCE IF EXISTS public.federation_change_event_sequence RESTART WITH 1")
