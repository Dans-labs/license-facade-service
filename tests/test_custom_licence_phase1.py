from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from src.license_facade_service.custom_licences.models import (
    CustomLicenceLifecycleStatus,
    FederationStatus,
    PublicLicenseScope,
    SpdxSubmissionStatus,
)
from src.license_facade_service.db.models.custom_licence import (
    CustomLicence,
    CustomLicenceAlias,
    CustomLicenceAuditEvent,
    normalize_alias,
)
from src.license_facade_service.main import create_app
from src.license_facade_service.services.spdx_custom_license import (
    SpdxCustomLicenseBuilder,
    SpdxCustomLicenseBuilderInput,
)
from src.license_facade_service.services.spdx_validation import (
    EXPECTED_SCHEMA_SHA256,
    Spdx301StructuralValidator,
    SpdxStructuralValidationError,
)
from tests.schema_init import apply_schema_init_sql, reset_public_schema

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "vendor" / "spdx" / "3.0.1" / "spdx-json-schema.json"

VALID_SPDX_GRAPH = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {
            "type": "Organization",
            "spdxId": "https://lfs.example/spdx/agents/lfs-operator",
            "name": "LFS Operator",
            "creationInfo": "_:creation-info",
        },
        {
            "@id": "_:creation-info",
            "type": "CreationInfo",
            "specVersion": "3.0.1",
            "created": "2026-08-12T12:00:00Z",
            "createdBy": ["https://lfs.example/spdx/agents/lfs-operator"],
        },
        {
            "type": "expandedlicensing_CustomLicense",
            "spdxId": "https://lfs.example/spdx/licenses/DANS-Custom-1.0",
            "creationInfo": "_:creation-info",
            "name": "DANS Custom License v1.0",
            "summary": "A custom licence maintained by DANS.",
            "simplelicensing_licenseText": "Complete and exact licence text...",
        },
    ],
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


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL migration test")

    port = _free_port()
    container_name = f"lfs-custom-licences-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            "POSTGRES_DB=lfs_custom_licence",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_custom_licence"
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_custom_licence"
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(raw_dsn):
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("postgres container did not become ready in time")
        apply_schema_init_sql(dsn)
        reset_public_schema(dsn)
        yield dsn
    finally:
        subprocess.run(["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def test_vendor_schema_is_official_and_self_contained() -> None:
    assert SCHEMA_PATH.is_file()
    actual_sha = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    assert actual_sha == EXPECTED_SCHEMA_SHA256

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"

    refs: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref":
                    refs.append(str(value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema)
    assert all(ref.startswith("#") for ref in refs)

    validator = Spdx301StructuralValidator(SCHEMA_PATH)
    validator.validate(VALID_SPDX_GRAPH)


def test_builder_validates_generated_custom_license() -> None:
    builder = SpdxCustomLicenseBuilder()
    created_at = datetime(2026, 8, 12, 12, 0, 0, tzinfo=timezone.utc)
    generated = builder.build(
        SpdxCustomLicenseBuilderInput(
            authority_base_iri="https://lfs.example",
            creator_organization_name="  LFS Operator  ",
            creator_organization_iri="https://lfs.example/spdx/agents/lfs-operator",
            custom_license_id="DANS-Custom-1.0",
            name=" DANS Custom License v1.0 ",
            summary="A custom licence maintained by DANS.",
            license_text="  Complete and exact licence text...  ",
            created_at=created_at,
        )
    )
    assert generated["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    assert generated["@graph"][0]["name"] == "LFS Operator"
    assert generated["@graph"][2]["name"] == "DANS Custom License v1.0"
    assert generated["@graph"][2]["spdxId"] == "https://lfs.example/licenses/DANS-Custom-1.0"
    assert generated["@graph"][2]["simplelicensing_licenseText"] == "  Complete and exact licence text...  "
    assert "public_scope" not in json.dumps(generated)
    assert "spdx_submission_status" not in json.dumps(generated)

    with pytest.raises(TypeError):
        SpdxCustomLicenseBuilderInput(
            authority_base_iri="https://lfs.example",
            creator_organization_name="LFS Operator",
            custom_license_id="DANS-Custom-1.0",
            name="DANS Custom License v1.0",
            license_text="Complete and exact licence text...",
            extra_fields={"expandedlicensing_isOsiApproved": False},
        )


def test_builder_rejects_invalid_custom_license_documents() -> None:
    validator = Spdx301StructuralValidator()
    invalid_specs = [
        {**VALID_SPDX_GRAPH, "@graph": [{**VALID_SPDX_GRAPH["@graph"][0], "spdxId": "SPDXRef-foo"}, VALID_SPDX_GRAPH["@graph"][1], VALID_SPDX_GRAPH["@graph"][2]]},
        {**VALID_SPDX_GRAPH, "@graph": [{**VALID_SPDX_GRAPH["@graph"][0]}, {**VALID_SPDX_GRAPH["@graph"][1], "specVersion": "3.0"}, VALID_SPDX_GRAPH["@graph"][2]]},
        {**VALID_SPDX_GRAPH, "@graph": [{**VALID_SPDX_GRAPH["@graph"][0]}, VALID_SPDX_GRAPH["@graph"][1], {**VALID_SPDX_GRAPH["@graph"][2], "licenseText": "Complete and exact licence text..."}]},
        {**VALID_SPDX_GRAPH, "@graph": [{**VALID_SPDX_GRAPH["@graph"][0]}, VALID_SPDX_GRAPH["@graph"][1], {**VALID_SPDX_GRAPH["@graph"][2]}], "@context": "https://example.com"},
    ]
    for document in invalid_specs:
        with pytest.raises(SpdxStructuralValidationError):
            validator.validate(document)

    with pytest.raises(ValueError):
        SpdxCustomLicenseBuilder().build(
            SpdxCustomLicenseBuilderInput(
                authority_base_iri="https://lfs.example",
                creator_organization_name="LFS Operator",
                custom_license_id="DANS-Custom-1.0",
                name="DANS Custom License v1.0",
                license_text="",
            )
        )
    with pytest.raises(ValueError):
        SpdxCustomLicenseBuilder().build(
            SpdxCustomLicenseBuilderInput(
                authority_base_iri="https://lfs.example",
                creator_organization_name="LFS Operator",
                custom_license_id="DANS-Custom-1.0",
                name="DANS Custom License v1.0",
                license_text=" \n\t  ",
            )
        )


def test_builder_preserves_exact_license_text_bytes() -> None:
    input_text = "  DANS custom licence text.\n\nCopyright 2026 DANS.\n"
    built = SpdxCustomLicenseBuilder().build(
        SpdxCustomLicenseBuilderInput(
            authority_base_iri="https://example.org",
            creator_organization_name="LFS Operator",
            custom_license_id="DANS-Custom-1.0",
            name="DANS Custom License v1.0",
            license_text=input_text,
        )
    )
    assert built["@graph"][2]["simplelicensing_licenseText"] == input_text


@pytest.mark.parametrize(
    ("authority_base_iri", "creator_organization_iri", "custom_license_id"),
    [
        ("httpwhatever", None, "DANS-Custom-1.0"),
        ("https://", None, "DANS-Custom-1.0"),
        ("https://user:pass@example.org", None, "DANS-Custom-1.0"),
        ("https://example.org?x=1", None, "DANS-Custom-1.0"),
        ("https://example.org?", None, "DANS-Custom-1.0"),
        ("https://example.org#x", None, "DANS-Custom-1.0"),
        ("https://example.org#", None, "DANS-Custom-1.0"),
        ("https://example.org:65536", None, "DANS-Custom-1.0"),
        ("https://exa\\mple.org", None, "DANS-Custom-1.0"),
        ("https://exa\nmple.org", None, "DANS-Custom-1.0"),
        ("https://example.org", None, "   "),
        ("https://example.org", None, "/escaped"),
        ("https://example.org", None, "../escaped"),
        ("https://example.org", None, "https://attacker.example/item"),
        ("https://example.org", None, "encoded%2Fslash"),
        ("https://example.org", None, "encoded%252Fslash"),
        ("https://example.org", None, "%2E%2E"),
        ("https://example.org", None, "%252E%252E"),
        ("https://example.org", None, "encoded%2Edot"),
        ("https://example.org", "httpwhatever", "DANS-Custom-1.0"),
        ("https://example.org", "https://creator.example.org?", "DANS-Custom-1.0"),
        ("https://example.org", "https://creator.example.org#", "DANS-Custom-1.0"),
        ("https://example.org", "https://cre\\ator.example.org", "DANS-Custom-1.0"),
    ],
)
def test_builder_rejects_invalid_iri_and_identifier_inputs(authority_base_iri: str, creator_organization_iri: str | None, custom_license_id: str) -> None:
    with pytest.raises(ValueError):
        SpdxCustomLicenseBuilder().build(
            SpdxCustomLicenseBuilderInput(
                authority_base_iri=authority_base_iri,
                creator_organization_name="LFS Operator",
                creator_organization_iri=creator_organization_iri,
                custom_license_id=custom_license_id,
                name="DANS Custom License v1.0",
                license_text="Complete and exact licence text...",
            )
        )


@pytest.mark.parametrize("authority_base_iri", ["https://example.org", "https://example.org/base/"])
def test_builder_accepts_valid_authority_base_iris(authority_base_iri: str) -> None:
    built = SpdxCustomLicenseBuilder().build(
        SpdxCustomLicenseBuilderInput(
            authority_base_iri=authority_base_iri,
            creator_organization_name="LFS Operator",
            custom_license_id="DANS-Custom-1.0",
            name="DANS Custom License v1.0",
            license_text="Complete and exact licence text...",
        )
    )
    assert built["@graph"][2]["spdxId"].startswith(authority_base_iri.rstrip("/"))


def test_builder_supports_unicode_identifier_with_single_encoding_pass() -> None:
    # Rule: caller supplies raw identifier; builder applies exactly one percent-encoding pass.
    custom_id = "Lícença-ß-1.0"
    built = SpdxCustomLicenseBuilder().build(
        SpdxCustomLicenseBuilderInput(
            authority_base_iri="https://example.org",
            creator_organization_name="LFS Operator",
            custom_license_id=custom_id,
            name="DANS Custom License v1.0",
            license_text="Complete and exact licence text...",
        )
    )
    assert built["@graph"][2]["spdxId"] == "https://example.org/licenses/L%C3%ADcen%C3%A7a-%C3%9F-1.0"


def test_alias_normalization_and_domain_enums() -> None:
    assert PublicLicenseScope.LOCAL.value == "local"
    assert FederationStatus.NOT_PUBLISHED.value == "not_published"
    assert SpdxSubmissionStatus.READY_FOR_REVIEW.value == "ready_for_review"
    assert CustomLicenceLifecycleStatus.TOMBSTONED.value == "tombstoned"

    normalized = normalize_alias("  DANS\u00a0Custom\u2003License  ")
    assert normalized == "dans custom license"
    assert normalize_alias("MÄR") == "mär"

    with pytest.raises(ValueError):
        normalize_alias(" ")
    with pytest.raises(ValueError):
        normalize_alias("\x00bad")
    with pytest.raises(ValueError):
        normalize_alias(" " * 600)


def test_spdx_jsonld_default_and_model_parity() -> None:
    assert CustomLicence.__table__.c.spdx_jsonld.default is None
    assert CustomLicence.__table__.c.spdx_jsonld.nullable is False
    assert CustomLicenceAuditEvent.__table__.c.before_state.default is None
    assert CustomLicenceAuditEvent.__table__.c.after_state.default is None
    assert CustomLicenceAuditEvent.__table__.c.before_state.nullable is True
    assert CustomLicenceAuditEvent.__table__.c.after_state.nullable is True
    assert str(CustomLicence.__table__.c.created_at.server_default.arg).lower().find("now()") >= 0
    assert str(CustomLicence.__table__.c.updated_at.server_default.arg).lower().find("now()") >= 0


def test_phase1_models_are_present_without_phase2_and_phase4_tables() -> None:
    assert CustomLicence.__tablename__ == "custom_licences"
    assert CustomLicenceAlias.__tablename__ == "custom_licence_aliases"
    assert CustomLicenceAuditEvent.__tablename__ == "custom_licence_audit_events"

    app = create_app()
    admin_routes = [route for route in app.routes if getattr(route, "path", None) == "/api/v1/admin/licenses/{record_id}"]
    assert not admin_routes


def test_schema_init_creates_custom_licence_tables(postgres_url: str):
    raw_dsn = postgres_url.replace("+psycopg", "")
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT column_name, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'custom_licences'
                ORDER BY ordinal_position
                """
            )
            column_info = {row[0]: {"nullable": row[1], "default": row[2]} for row in cur.fetchall()}
            assert column_info["spdx_jsonld"]["nullable"] == "NO"
            assert column_info["spdx_jsonld"]["default"] is None
            assert column_info["created_at"]["default"] is not None and "now()" in column_info["created_at"]["default"]
            assert column_info["updated_at"]["default"] is not None and "now()" in column_info["updated_at"]["default"]

            cur.execute(
                """
                SELECT column_name, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'custom_licence_audit_events'
                  AND column_name IN ('before_state', 'after_state')
                ORDER BY column_name
                """
            )
            audit_column_info = {row[0]: {"nullable": row[1], "default": row[2]} for row in cur.fetchall()}
            assert audit_column_info["after_state"]["nullable"] == "YES"
            assert audit_column_info["after_state"]["default"] is None
            assert audit_column_info["before_state"]["nullable"] == "YES"
            assert audit_column_info["before_state"]["default"] is None

            cur.execute(
                """
                SELECT conname
                FROM pg_constraint
                WHERE conrelid = 'public.custom_licences'::regclass
                """
            )
            check_names = {row[0] for row in cur.fetchall()}
            assert "ck_custom_licences_creator_role_nonblank_trimmed" in check_names
            assert "ck_custom_licences_digest_format" in check_names
            assert "uq_custom_licences_authority_requested_version" in check_names
            assert "uq_custom_licences_canonical_id" in check_names
            assert "uq_custom_licences_resolving_uuid" in check_names

            cur.execute(
                """
                SELECT conname
                FROM pg_constraint
                WHERE conrelid = 'public.custom_licence_aliases'::regclass
                """
            )
            alias_constraint_names = {row[0] for row in cur.fetchall()}
            assert "uq_custom_licence_aliases_normalized_alias" in alias_constraint_names

            cur.execute(
                """
                SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename='custom_licences'
                """
            )
            db_indexes = {row[0] for row in cur.fetchall()}
            assert "ix_custom_licences_authority_requested" in db_indexes
            assert "ix_custom_licences_scope_status" in db_indexes
            assert "ix_custom_licences_lifecycle_status" in db_indexes

            cur.execute(
                """
                SELECT conname, confdeltype
                FROM pg_constraint
                WHERE conrelid = 'public.custom_licence_aliases'::regclass AND confrelid = 'public.custom_licences'::regclass
                """
            )
            assert any(row[1] == "r" for row in cur.fetchall())

            cur.execute(
                """
                SELECT conname, confdeltype
                FROM pg_constraint
                WHERE conrelid = 'public.custom_licence_audit_events'::regclass AND confrelid = 'public.custom_licences'::regclass
                """
            )
            assert any(row[1] == "r" for row in cur.fetchall())

            cur.execute(
                """
                SELECT tgname
                FROM pg_trigger
                WHERE tgrelid = 'public.custom_licence_audit_events'::regclass
                """
            )
            trigger_names = {row[0] for row in cur.fetchall()}
            assert "trg_custom_licence_audit_events_no_update" in trigger_names
            assert "trg_custom_licence_audit_events_no_delete" in trigger_names

            valid_id = uuid.uuid4()
            cur.execute(
                """
                INSERT INTO custom_licences (
                    id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                    public_scope, federation_status, spdx_submission_status, lifecycle_status,
                    name, license_text, normalized_text_digest, spdx_jsonld, creator_role,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s::jsonb, %s,
                    NOW(), NOW()
                )
                """,
                (
                    valid_id,
                    "lfs-node-1",
                    "DANS-Custom-1.0",
                    "1.0",
                    "lfs:lfs-node-1:DANS-Custom-1.0:1.0",
                    uuid.uuid4(),
                    "local",
                    "not_published",
                    "not_requested",
                    "registered",
                    "DANS Custom License v1.0",
                    "Complete and exact licence text...",
                    "a" * 64,
                    json.dumps({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}),
                    "curator",
                ),
            )
            conn.commit()

            cur.execute(
                "INSERT INTO custom_licence_aliases (id, custom_licence_id, alias_type, alias, normalized_alias, created_at) VALUES (%s, %s, %s, %s, %s, NOW())",
                (uuid.uuid4(), valid_id, "requested_id", "DANS-Custom-1.0", "dans-custom-1.0"),
            )
            conn.commit()

            audit_event_id = uuid.uuid4()
            cur.execute(
                "INSERT INTO custom_licence_audit_events (id, custom_licence_id, event_type, actor_role, before_state, after_state, source, created_at) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, NOW())",
                (audit_event_id, valid_id, "created", "curator", "{}", "{}", "migration-test"),
            )
            conn.commit()

            try:
                cur.execute("UPDATE custom_licence_audit_events SET source = %s WHERE id = %s", ("updated", audit_event_id))
                pytest.fail("expected append-only trigger")
            except psycopg.Error as exc:
                assert "custom_licence_audit_events is append-only" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")

            try:
                cur.execute("DELETE FROM custom_licence_audit_events WHERE id = %s", (audit_event_id,))
                pytest.fail("expected append-only trigger")
            except psycopg.Error as exc:
                assert "custom_licence_audit_events is append-only" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")
            cur.execute("SELECT count(*) FROM custom_licences WHERE id = %s", (valid_id,))
            assert cur.fetchone()[0] == 1

            try:
                cur.execute(
                    "INSERT INTO custom_licence_aliases (id, custom_licence_id, alias_type, alias, normalized_alias, created_at) VALUES (%s, %s, %s, %s, %s, NOW())",
                    (uuid.uuid4(), valid_id, "requested_id", "DANS-Custom-1.0", "dans-custom-1.0"),
                )
                pytest.fail("expected alias uniqueness failure")
            except psycopg.Error as exc:
                assert "uq_custom_licence_aliases_normalized_alias" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")

            try:
                cur.execute("UPDATE custom_licences SET normalized_text_digest = %s WHERE id = %s", ("bad", valid_id))
                pytest.fail("expected digest check failure")
            except psycopg.Error as exc:
                assert "ck_custom_licences_digest_format" in str(exc) or "ck_custom_licences_digest_length" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")

            try:
                cur.execute("UPDATE custom_licences SET creator_role = %s WHERE id = %s", ("   ", valid_id))
                pytest.fail("expected creator role failure")
            except psycopg.Error as exc:
                assert "ck_custom_licences_creator_role_nonblank_trimmed" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")

            try:
                cur.execute("UPDATE custom_licences SET public_scope = %s WHERE id = %s", ("bad", valid_id))
                pytest.fail("expected public scope failure")
            except psycopg.Error as exc:
                assert "ck_custom_licences_public_scope" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")

            try:
                cur.execute("UPDATE custom_licences SET spdx_jsonld = NULL WHERE id = %s", (valid_id,))
                pytest.fail("expected not-null failure")
            except psycopg.Error as exc:
                assert "not-null" in str(exc)
                conn.rollback()
            cur.execute("SELECT 1")
