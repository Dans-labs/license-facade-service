from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import psycopg
from psycopg import sql

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_INIT_SQL_PATH = REPO_ROOT / "docker" / "postgres-init" / "001-lfs-schema.sql"


@lru_cache(maxsize=1)
def _load_schema_init_sql() -> str:
    return SCHEMA_INIT_SQL_PATH.read_text(encoding="utf-8")


def apply_schema_init_sql(database_url: str) -> None:
    sql = _load_schema_init_sql()
    with psycopg.connect(database_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


def reset_public_schema(database_url: str) -> None:
    with psycopg.connect(database_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
            tables = [row[0] for row in cur.fetchall()]
            if tables:
                cur.execute(
                    sql.SQL("TRUNCATE {} RESTART IDENTITY CASCADE").format(
                        sql.SQL(", ").join(sql.Identifier("public", table) for table in tables)
                    )
                )
            cur.execute("ALTER SEQUENCE IF EXISTS public.federation_change_event_sequence RESTART WITH 1")
