from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from enum import Enum
from urllib.parse import unquote, urlparse
from uuid import UUID, NAMESPACE_DNS, uuid5

import httpx
from pydantic import BaseModel, Field
from rdflib import Graph, URIRef
from sqlalchemy import or_, select

from src.license_facade_service.db.models.custom_licence import CustomLicence, CustomLicenceAlias, normalize_alias
from src.license_facade_service.db.session import Database
from src.license_facade_service.services.custom_licence_registration import build_resolving_uri
from src.license_facade_service.utils.rdf_transformer import json_to_rdf
from src.license_facade_service.services.contract import (
    ConformanceRequirement,
    ConformanceStatus,
    CrossReference,
    EncodingRepresentation,
    LicenseDetail,
    LicenseInventoryItem,
    LegalRepresentation,
    MachineRepresentation,
    OriginalRepresentation,
    RepresentationDescriptor,
    is_valid_json_document,
    parse_rdf,
    safe_escape_text,
)

SPDX_LICENSES_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
SPDX_DETAILS_BASE_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/details"

REPRESENTATION_HTML = "html"
REPRESENTATION_JSON = "json"
REPRESENTATION_JSON_LD = "json-ld"
REPRESENTATION_TURTLE = "turtle"
REPRESENTATION_RDFXML = "rdfxml"
REPRESENTATION_ORIGINAL = "original"
REPRESENTATION_LEGAL = "legal"
REPRESENTATION_MACHINE = "machine"
REPRESENTATION_ENCODING = "encoding"

SUPPORTED_ACCEPT_TYPES = {
    "text/html": REPRESENTATION_HTML,
    "application/json": REPRESENTATION_JSON,
    "application/ld+json": REPRESENTATION_JSON_LD,
    "text/turtle": REPRESENTATION_TURTLE,
    "application/rdf+xml": REPRESENTATION_RDFXML,
}

REPRESENTATION_MEDIA_TYPES = {
    REPRESENTATION_HTML: "text/html; charset=utf-8",
    REPRESENTATION_JSON: "application/json; charset=utf-8",
    REPRESENTATION_JSON_LD: "application/ld+json; charset=utf-8",
    REPRESENTATION_TURTLE: "text/turtle; charset=utf-8",
    REPRESENTATION_RDFXML: "application/rdf+xml; charset=utf-8",
}

ALLOWED_REL_IRIS = {
    "https://www.w3.org/ns/odrl/2/",
    "https://www.w3.org/ns/odrl.jsonld",
    "http://creativecommons.org/ns#",
    "https://opensource.creativecommons.org/ccrel/",
    "https://dalicc.github.io/",
    "https://www.w3.org/ns/odrl-profile/",
    "https://openrel.org/ns#",
    "https://www.dublincore.org/specifications/dublin-core/dcmi-terms/",
    "http://schema.org/",
    "https://schema.org/",
}

REL_TERM_NAMESPACES = {
    "https://www.w3.org/ns/odrl/2/": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/"},
    "http://www.w3.org/ns/odrl/2/": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/"},
    "https://www.w3.org/ns/odrl.jsonld": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/"},
    "http://www.w3.org/ns/odrl.jsonld": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/"},
    "https://www.w3.org/ns/odrl-profile/": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/", "https://www.w3.org/ns/odrl-profile/", "http://www.w3.org/ns/odrl-profile/"},
    "http://www.w3.org/ns/odrl-profile/": {"https://www.w3.org/ns/odrl/2/", "http://www.w3.org/ns/odrl/2/", "https://www.w3.org/ns/odrl-profile/", "http://www.w3.org/ns/odrl-profile/"},
    "https://openrel.org/ns#": {"https://openrel.org/ns#", "http://openrel.org/ns#"},
    "http://openrel.org/ns#": {"https://openrel.org/ns#", "http://openrel.org/ns#"},
    "http://creativecommons.org/ns#": {"http://creativecommons.org/ns#", "https://creativecommons.org/ns#"},
    "https://opensource.creativecommons.org/ccrel/": {"https://opensource.creativecommons.org/ccrel/", "http://opensource.creativecommons.org/ccrel/"},
    "https://dalicc.github.io/": {"https://dalicc.github.io/", "http://dalicc.github.io/"},
    "https://www.dublincore.org/specifications/dublin-core/dcmi-terms/": {"https://www.dublincore.org/specifications/dublin-core/dcmi-terms/"},
    "http://schema.org/": {"http://schema.org/"},
    "https://schema.org/": {"https://schema.org/"},
}

REL_TERM_PREFIXES = {
    "https://www.w3.org/ns/odrl/2/": {"odrl"},
    "http://www.w3.org/ns/odrl/2/": {"odrl"},
    "https://www.w3.org/ns/odrl.jsonld": {"odrl"},
    "http://www.w3.org/ns/odrl.jsonld": {"odrl"},
    "https://www.w3.org/ns/odrl-profile/": {"odrl"},
    "http://www.w3.org/ns/odrl-profile/": {"odrl"},
    "https://openrel.org/ns#": {"openrel"},
    "http://openrel.org/ns#": {"openrel"},
    "http://creativecommons.org/ns#": {"cc"},
    "https://opensource.creativecommons.org/ccrel/": {"cc"},
    "https://dalicc.github.io/": {"dali"},
    "https://www.dublincore.org/specifications/dublin-core/dcmi-terms/": {"dcterms"},
    "http://schema.org/": {"schema"},
    "https://schema.org/": {"schema"},
}


class LicenseNotFoundError(Exception):
    """License could not be resolved."""


class ConcurrentRefreshError(Exception):
    """Raised when a concurrent cache refresh is already in progress."""


class OptionalRepresentationUnavailable(Exception):
    """Raised when optional representation is unavailable for this license."""


class AmbiguousCustomLicenseIdentifierError(LicenseNotFoundError):
    """Custom-licence identifier maps to multiple local records."""


@dataclass(frozen=True)
class ResolvedLicense:
    license_id: str
    identifier: str
    record: dict[str, Any]
    details: dict[str, Any]
    uri: str
    source: "ResolvedLicenseSource"


class ResolvedLicenseSource(str, Enum):
    SPDX_LISTED = "spdx-listed"
    LOCAL_CUSTOM = "local-custom"
    FEDERATED_CUSTOM = "federated-custom"


class LicenseSnapshotStatus(BaseModel):
    cached: bool
    version: str | None = None
    total_licenses: int = 0
    last_updated: str | None = None


def _safe_json_load(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_file():
            with path.open("r", encoding="utf-8") as file:
                return json.load(file)
    except (ValueError, OSError):
        return None
    return None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            json.dump(payload, tmp_file, indent=2)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


@contextmanager
def _exclusive_lock(lock_file: Path):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    try:
        fd = os.open(str(lock_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as lock:
            lock.write(str(os.getpid()))
        yield
    except FileExistsError as exc:
        raise ConcurrentRefreshError("Cache refresh already running") from exc
    finally:
        try:
            if lock_file.exists():
                lock_file.unlink()
        except OSError:
            pass


class SPDXClient:
    def __init__(
        self,
        *,
        list_url: str = SPDX_LICENSES_URL,
        details_base_url: str = SPDX_DETAILS_BASE_URL,
        timeout: float = 10.0,
        retries: int = 3,
        backoff_seconds: float = 0.5,
    ) -> None:
        self.list_url = list_url
        self.details_base_url = details_base_url
        self.timeout = timeout
        self.retries = retries
        self.backoff_seconds = backoff_seconds

    async def fetch_license_list(self) -> dict[str, Any]:
        return await self._fetch_json(self.list_url)

    async def fetch_license_details(self, license_id: str) -> dict[str, Any]:
        return await self._fetch_json(f"{self.details_base_url}/{license_id}.json")

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        attempt = 0
        while True:
            attempt += 1
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError):
                if attempt >= self.retries:
                    raise
                await asyncio.sleep(self.backoff_seconds * (2 ** (attempt - 1)))


class SnapshotCache:
    def __init__(self, base_dir: Path) -> None:
        self.cache_root = base_dir / "resources" / "data" / "licenses"
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir = self.cache_root / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.current_file = self.cache_root / "current_snapshot.json"
        self.version_file = self.cache_root / "version.json"
        self.legacy_list_file = self.cache_root / "licenses_list.json"
        self.curated_representations_file = self.cache_root / "curated_representations.json"
        self.lock_file = self.cache_root / ".refresh.lock"

    def _active_snapshot_dir(self) -> Path | None:
        state = _safe_json_load(self.current_file)
        if state and state.get("snapshot"):
            directory = self.snapshots_dir / state["snapshot"]
            if directory.is_dir():
                return directory
        return None

    def get_status(self) -> LicenseSnapshotStatus:
        snapshot_dir = self._active_snapshot_dir()
        if snapshot_dir:
            version_data = _safe_json_load(snapshot_dir / "version.json") or {}
            list_data = _safe_json_load(snapshot_dir / "licenses_list.json") or {}
            return LicenseSnapshotStatus(
                cached=True,
                version=version_data.get("licenseListVersion"),
                total_licenses=len(list_data.get("licenses", [])),
                last_updated=version_data.get("lastUpdated"),
            )

        legacy_data = _safe_json_load(self.legacy_list_file)
        version_data = _safe_json_load(self.version_file) or {}
        if legacy_data:
            return LicenseSnapshotStatus(
                cached=True,
                version=version_data.get("licenseListVersion"),
                total_licenses=len(legacy_data.get("licenses", [])),
                last_updated=version_data.get("lastUpdated"),
            )

        return LicenseSnapshotStatus(cached=False)

    def load_licenses_list(self) -> dict[str, Any] | None:
        snapshot_dir = self._active_snapshot_dir()
        if snapshot_dir:
            return _safe_json_load(snapshot_dir / "licenses_list.json")
        return _safe_json_load(self.legacy_list_file)

    def load_license_details(self, license_id: str) -> dict[str, Any] | None:
        snapshot_dir = self._active_snapshot_dir()
        if snapshot_dir:
            return _safe_json_load(snapshot_dir / f"{license_id}.json")
        return _safe_json_load(self.cache_root / f"{license_id}.json")

    def load_curated_representations(self) -> dict[str, Any]:
        data = _safe_json_load(self.curated_representations_file)
        return data or {}

    async def refresh(self, spdx: SPDXClient) -> LicenseSnapshotStatus:
        with _exclusive_lock(self.lock_file):
            licenses_payload = await spdx.fetch_license_list()
            licenses = licenses_payload.get("licenses", [])
            if not isinstance(licenses, list) or not licenses:
                raise RuntimeError("SPDX license list is empty")

            temp_dir = self.snapshots_dir / f".tmp-{int(time.time() * 1000)}"
            temp_dir.mkdir(parents=True, exist_ok=False)
            try:
                enriched_payload = dict(licenses_payload)
                enriched_payload["licenses"] = []

                for item in licenses:
                    license_id = item.get("licenseId")
                    if not license_id:
                        raise RuntimeError("Invalid SPDX license entry without licenseId")
                    details = await spdx.fetch_license_details(license_id)

                    with (temp_dir / f"{license_id}.json").open("w", encoding="utf-8") as details_file:
                        json.dump(details, details_file, indent=2)

                    enriched_item = dict(item)
                    enriched_item["uri"] = generate_license_uri(license_id)
                    enriched_payload["licenses"].append(enriched_item)

                with (temp_dir / "licenses_list.json").open("w", encoding="utf-8") as list_file:
                    json.dump(enriched_payload, list_file, indent=2)

                version_payload = {
                    "licenseListVersion": licenses_payload.get("licenseListVersion"),
                    "licenseCount": len(licenses),
                    "lastUpdated": datetime.now(timezone.utc).isoformat(),
                }
                _atomic_write_json(temp_dir / "version.json", version_payload)

                final_name = (
                    f"{licenses_payload.get('licenseListVersion', 'unknown')}-{int(time.time())}"
                    .replace("/", "-")
                )
                final_dir = self.snapshots_dir / final_name
                os.replace(temp_dir, final_dir)
                _atomic_write_json(self.current_file, {"snapshot": final_name})
                return self.get_status()
            finally:
                if temp_dir.exists():
                    for child in temp_dir.glob("*"):
                        try:
                            child.unlink()
                        except OSError:
                            pass
                    try:
                        temp_dir.rmdir()
                    except OSError:
                        pass


def generate_license_uri(license_id: str) -> str:
    url_base = os.getenv("URL_BASE", "https://lfs.labs.dansdemo.nl/api/v1/licenses").rstrip("/")
    license_uuid = uuid5(NAMESPACE_DNS, f"spdx.org/licenses/{license_id}")
    return f"{url_base}/{license_uuid}"


class LicenseService:
    def __init__(
        self,
        *,
        base_dir: Path | None = None,
        spdx_client: SPDXClient | None = None,
    ) -> None:
        resolved_base_dir = base_dir or Path(os.getenv("BASE_DIR", os.getcwd()))
        self.cache = SnapshotCache(resolved_base_dir)
        timeout = float(os.getenv("SPDX_TIMEOUT_SECONDS", "10"))
        retries = int(os.getenv("SPDX_RETRIES", "3"))
        backoff = float(os.getenv("SPDX_RETRY_BACKOFF_SECONDS", "0.5"))
        self.spdx = spdx_client or SPDXClient(timeout=timeout, retries=retries, backoff_seconds=backoff)
        self._custom_database_url = os.getenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL")
        self._custom_authority_base_iri = os.getenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI")
        self._custom_db: Database | None = None

    async def ensure_cache_updated(self) -> None:
        if self.cache.get_status().cached:
            return
        await self.refresh_cache()

    async def refresh_cache(self) -> LicenseSnapshotStatus:
        return await self.cache.refresh(self.spdx)

    def cache_status(self) -> LicenseSnapshotStatus:
        return self.cache.get_status()

    def health_can_resolve(self) -> bool:
        licenses_list = self.cache.load_licenses_list()
        if not licenses_list:
            return False
        licenses = licenses_list.get("licenses", [])
        if not licenses:
            return False
        first = licenses[0].get("licenseId")
        if not first:
            return False
        return self.cache.load_license_details(first) is not None

    async def get_all_licenses(self) -> dict[str, Any]:
        licenses_list = self.cache.load_licenses_list()
        if licenses_list is None:
            licenses_list = await self.spdx.fetch_license_list()
        licenses = licenses_list.get("licenses", [])
        enriched = []
        for item in licenses:
            lic = dict(item)
            lic["uri"] = lic.get("uri") or generate_license_uri(lic["licenseId"])
            enriched.append(self.build_inventory_item(lic).model_dump(exclude_none=True))
        licenses_list["licenses"] = enriched
        return licenses_list

    async def resolve(self, identifier: str) -> ResolvedLicense:
        normalized = unquote(identifier).strip()
        if ".." in normalized or "\\" in normalized:
            raise LicenseNotFoundError

        custom = self._resolve_custom_record(normalized)
        if custom is not None:
            return custom

        licenses_list = await self.get_all_licenses()
        licenses = licenses_list.get("licenses", [])
        record = self._resolve_record(normalized, licenses)
        if record is None:
            raise LicenseNotFoundError

        license_id = record["licenseId"]
        details = self.cache.load_license_details(license_id)
        if details is None:
            details = await self.spdx.fetch_license_details(license_id)

        uri = record.get("uri") or generate_license_uri(license_id)
        return ResolvedLicense(
            license_id=license_id,
            identifier=normalized,
            record=record,
            details=details,
            uri=uri,
            source=ResolvedLicenseSource.SPDX_LISTED,
        )

    @property
    def custom_db(self) -> Database | None:
        if not self._custom_database_url:
            return None
        if self._custom_db is None:
            self._custom_db = Database.from_url(self._custom_database_url)
        return self._custom_db

    def _resolve_custom_record(self, identifier: str) -> ResolvedLicense | None:
        database = self.custom_db
        if database is None:
            return None
        with database.transaction() as session:
            strong_match = (
                session.execute(
                    select(CustomLicence).where(
                        or_(
                            CustomLicence.canonical_id == identifier,
                            CustomLicence.resolving_uuid == self._uuid_or_none(identifier),
                        )
                    ).limit(1)
                )
                .scalars()
                .first()
            )
            if strong_match is None:
                uri_match = (
                    session.execute(
                        select(CustomLicence)
                        .join(CustomLicenceAlias, CustomLicenceAlias.custom_licence_id == CustomLicence.id)
                        .where(
                            CustomLicenceAlias.alias_type == "resolving_uri",
                            CustomLicenceAlias.alias == identifier,
                        )
                        .limit(1)
                    )
                    .scalars()
                    .first()
                )
                if uri_match is not None:
                    strong_match = uri_match
            if strong_match is not None:
                return self._build_custom_resolved(strong_match)

            requested_rows = (
                session.execute(
                    select(CustomLicence)
                    .where(
                        CustomLicence.requested_license_id == identifier,
                        CustomLicence.lifecycle_status.in_(("registered", "deprecated")),
                    )
                    .limit(2)
                )
                .scalars()
                .all()
            )
            if len(requested_rows) > 1:
                raise AmbiguousCustomLicenseIdentifierError
            if len(requested_rows) == 1:
                return self._build_custom_resolved(requested_rows[0])

            try:
                normalized_alias = normalize_alias(identifier)
            except (TypeError, ValueError):
                return None
            alias_match = (
                session.execute(
                    select(CustomLicence)
                    .join(CustomLicenceAlias, CustomLicenceAlias.custom_licence_id == CustomLicence.id)
                    .where(CustomLicenceAlias.normalized_alias == normalized_alias)
                    .limit(1)
                )
                .scalars()
                .first()
            )
            if alias_match is None:
                return None
            return self._build_custom_resolved(alias_match)

    def _build_custom_resolved(self, row: CustomLicence) -> ResolvedLicense | None:
        if row.lifecycle_status not in {"registered", "deprecated"}:
            return None
        resolving_uri = (
            build_resolving_uri(
                authority_base_iri=self._custom_authority_base_iri,
                authority_id=row.authority_id,
                requested_license_id=row.requested_license_id,
                version=row.version,
            )
            if self._custom_authority_base_iri
            else ""
        )
        record: dict[str, Any] = {
            "id": str(row.id),
            "requestedLicenseId": row.requested_license_id,
            "version": row.version,
            "canonicalId": row.canonical_id,
            "resolvingUuid": str(row.resolving_uuid),
            "resolvingUri": resolving_uri,
            "name": row.name,
            "summary": row.summary,
            "description": row.description,
            "scope": row.public_scope,
            "federationStatus": row.federation_status,
            "spdxSubmissionStatus": row.spdx_submission_status,
            "lifecycleStatus": row.lifecycle_status,
            "normalizedTextDigest": row.normalized_text_digest,
            "spdxJsonld": row.spdx_jsonld,
            "createdAt": row.created_at,
            "updatedAt": row.updated_at,
        }
        return ResolvedLicense(
            license_id=row.canonical_id,
            identifier=row.canonical_id,
            record=record,
            details=row.spdx_jsonld,
            uri=resolving_uri or row.canonical_id,
            source=ResolvedLicenseSource.LOCAL_CUSTOM,
        )

    def _uuid_or_none(self, value: str) -> UUID | None:
        try:
            return UUID(value)
        except ValueError:
            return None

    def _resolve_record(self, identifier: str, licenses: list[dict[str, Any]]) -> dict[str, Any] | None:
        by_id = next((item for item in licenses if item.get("licenseId") == identifier), None)
        if by_id:
            return by_id

        try:
            uuid_identifier = str(UUID(identifier))
            by_uuid = next(
                (
                    item
                    for item in licenses
                    if str(item.get("uri", "")).rstrip("/").rsplit("/", 1)[-1] == uuid_identifier
                ),
                None,
            )
            if by_uuid:
                return by_uuid
        except ValueError:
            pass

        by_uri = next((item for item in licenses if item.get("uri") == identifier), None)
        if by_uri:
            return by_uri

        for item in licenses:
            aliases = item.get("aliases", [])
            if identifier in aliases:
                return item
        return None

    def representation_links(self, resolved: ResolvedLicense) -> dict[str, str]:
        raw_id = resolved.license_id
        return {
            "self": f"/api/v1/licenses/{raw_id}",
            "html": f"/api/v1/licenses/{raw_id}/html",
            "json": f"/api/v1/licenses/{raw_id}/json",
            "json-ld": f"/api/v1/licenses/{raw_id}/json-ld",
            "turtle": f"/api/v1/licenses/{raw_id}/turtle",
            "rdfxml": f"/api/v1/licenses/{raw_id}/rdfxml",
            "original": f"/api/v1/licenses/{raw_id}/original",
            "legal": f"/api/v1/licenses/{raw_id}/legal",
            "machine": f"/api/v1/licenses/{raw_id}/machine",
            "encoding": f"/api/v1/licenses/{raw_id}/encoding",
        }

    def _curated_store(self) -> dict[str, Any]:
        return self.cache.load_curated_representations()

    def _representations_for(self, license_id: str) -> dict[str, Any]:
        store = self._curated_store()
        entry = store.get(license_id) or {}
        if not isinstance(entry, dict):
            return {}
        return entry

    def _normalize_rel(self, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        return value

    def _validate_vocabulary(self, descriptor: RepresentationDescriptor) -> bool:
        iris = [self._normalize_rel(descriptor.profile), self._normalize_rel(descriptor.vocabulary)]
        iris = [iri for iri in iris if iri]
        if not iris:
            return False
        for iri in iris:
            if iri not in ALLOWED_REL_IRIS:
                return False
        return True

    def _graph_uses_declared_vocabulary(self, graph: Graph, declared_iris: list[str]) -> bool:
        semantically_relevant = set()
        semantic_prefixes = set()
        for iri in declared_iris:
            if not iri:
                continue
            semantically_relevant.update(REL_TERM_NAMESPACES.get(iri, {iri}))
            semantic_prefixes.update(REL_TERM_PREFIXES.get(iri, set()))

        for _, predicate, obj in graph.triples((None, None, None)):
            predicate_value = str(predicate)
            if any(predicate_value.startswith(namespace) for namespace in semantically_relevant):
                return True
            if ":" in predicate_value:
                prefix = predicate_value.split(":", 1)[0]
                if prefix in semantic_prefixes:
                    return True

            if isinstance(obj, URIRef):
                obj_value = str(obj)
                if any(obj_value.startswith(namespace) for namespace in semantically_relevant):
                    return True
                if ":" in obj_value:
                    prefix = obj_value.split(":", 1)[0]
                    if prefix in semantic_prefixes:
                        return True
        return False

    def _validate_machine_representation(self, descriptor: MachineRepresentation) -> bool:
        if descriptor.mediaType not in (
            "application/ld+json",
            "application/json",
            "text/turtle",
            "application/rdf+xml",
        ):
            return False
        if not descriptor.content and not descriptor.href:
            return False
        if not self._validate_vocabulary(descriptor):
            return False

        declared_iris = [
            self._normalize_rel(descriptor.profile),
            self._normalize_rel(descriptor.vocabulary),
        ]
        declared_iris = [iri for iri in declared_iris if iri]

        if descriptor.content is not None:
            if descriptor.mediaType in {"application/json", "application/ld+json"}:
                if not is_valid_json_document(descriptor.content):
                    return False
                payload = json.loads(descriptor.content) if isinstance(descriptor.content, str) else descriptor.content
                if not isinstance(payload, (dict, list)):
                    return False
                graph_text = json.dumps(payload)
                try:
                    graph = Graph()
                    graph.parse(data=graph_text, format="json-ld")
                except Exception:
                    return False
            else:
                graph_text = descriptor.content if isinstance(descriptor.content, str) else json.dumps(descriptor.content)
                try:
                    graph = parse_rdf(graph_text, descriptor.mediaType)
                except Exception:
                    return False

            if declared_iris and not self._graph_uses_declared_vocabulary(graph, declared_iris):
                return False

        return True

    def _validate_original_representation(self, descriptor: OriginalRepresentation | None) -> bool:
        if descriptor is None:
            return False
        if not descriptor.href:
            return False
        return True

    def _validate_legal_representation(self, descriptor: LegalRepresentation | None) -> bool:
        if descriptor is None:
            return False
        if descriptor.content:
            return descriptor.mediaType in {"text/plain", "text/html", "text/markdown"}
        return bool(descriptor.href)

    def _validate_encoding_representation(self, descriptor: EncodingRepresentation | None) -> bool:
        return bool(descriptor and descriptor.href)

    def _validate_table5_crossrefs(self, details: dict[str, Any]) -> tuple[list[str], list[str]]:
        missing: list[str] = []
        invalid: list[str] = []
        required_fields = (
            ("match", "match"),
            ("URL", "url"),
            ("isValid", "isValid"),
            ("isLive", "isLive"),
            ("timeStamp", "timestamp"),
            ("isWayBackLink", "isWayBackLink"),
            ("order", "order"),
        )

        for index, raw in enumerate(details.get("crossRef", [])):
            if not isinstance(raw, dict):
                for canonical, _ in required_fields:
                    invalid.append(f"crossRef[{index}].{canonical}")
                continue

            row_values = {
                "match": raw.get("match"),
                "URL": raw.get("url") if "url" in raw else raw.get("URL"),
                "isValid": raw.get("isValid"),
                "isLive": raw.get("isLive"),
                "timeStamp": raw.get("timestamp") if "timestamp" in raw else raw.get("timeStamp"),
                "isWayBackLink": raw.get("isWayBackLink"),
                "order": raw.get("order"),
            }

            for canonical, _ in required_fields:
                value = row_values[canonical]
                path = f"crossRef[{index}].{canonical}"
                if value is None:
                    missing.append(path)
                    continue

                if canonical in {"match", "isValid", "isLive", "isWayBackLink"}:
                    if type(value) is not bool:
                        invalid.append(path)
                    continue

                if canonical == "URL":
                    parsed = urlparse(str(value))
                    if parsed.scheme != "https" or not parsed.netloc:
                        invalid.append(path)
                    continue

                if canonical == "timeStamp":
                    if not isinstance(value, str):
                        invalid.append(path)
                        continue
                    normalized = value.replace("Z", "+00:00")
                    try:
                        datetime.fromisoformat(normalized)
                    except ValueError:
                        invalid.append(path)
                    continue

                if canonical == "order" and (type(value) is not int):
                    invalid.append(path)

        return missing, invalid

    def _crossrefs_from_spdx(self, details: dict[str, Any]) -> list[CrossReference]:
        cross_refs: list[CrossReference] = []
        for cross_ref in details.get("crossRef", []):
            if not isinstance(cross_ref, dict):
                continue
            url = cross_ref.get("URL") or cross_ref.get("url")
            if not url:
                continue
            raw_timestamp = cross_ref.get("timeStamp")
            if raw_timestamp is None:
                raw_timestamp = cross_ref.get("timestamp")
            normalized_timestamp = raw_timestamp
            if isinstance(raw_timestamp, str):
                candidate = raw_timestamp.strip()
                if candidate.endswith("Z"):
                    candidate = f"{candidate[:-1]}+00:00"
                try:
                    normalized_timestamp = datetime.fromisoformat(candidate).isoformat()
                except ValueError:
                    normalized_timestamp = raw_timestamp
            try:
                normalized = CrossReference(
                    type="upstream",
                    URL=url,
                    match=_coerce_optional_bool(cross_ref.get("match")),
                    isValid=_coerce_optional_bool(cross_ref.get("isValid")),
                    isLive=_coerce_optional_bool(cross_ref.get("isLive")),
                    timeStamp=normalized_timestamp,
                    isWayBackLink=_coerce_optional_bool(cross_ref.get("isWayBackLink")),
                    order=cross_ref.get("order"),
                    provenance="spdx",
                    source=details.get("spdxDetailsURL") or details.get("detailsUrl") or details.get("detailsURL"),
                )
            except ValueError:
                continue
            cross_refs.append(normalized)
        return cross_refs

    def _table6_crossrefs(self, resolved: ResolvedLicense, reps: dict[str, Any]) -> list[CrossReference]:
        items = self._crossrefs_from_spdx(resolved.details)
        local_urls = self.representation_links(resolved)
        for relation in ("original", "machine", "legal", "encoding"):
            rep = reps.get(relation)
            if not rep:
                continue
            if isinstance(rep, dict):
                authority = rep.get("authority")
                curator = rep.get("curator")
                provenance = rep.get("provenance")
                source = rep.get("source")
            else:
                authority = rep.authority
                curator = rep.curator
                provenance = rep.provenance
                source = rep.source
            href = local_urls.get(relation)
            if not href:
                continue
            items.append(
                CrossReference(
                    type=relation,
                    URL=str(href),
                    authority=authority,
                    curator=curator,
                    provenance=provenance,
                    source=source,
                    relation=relation,
                )
            )
        return items

    def _require_https_or_approved_exception(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return True
        return False

    def _select_original_representation(self, resolved: ResolvedLicense) -> OriginalRepresentation | None:
        reps = self._representations_for(resolved.license_id)
        original = reps.get("original")
        if isinstance(original, dict):
            try:
                candidate = OriginalRepresentation.model_validate(original)
            except Exception:
                return None
            if self._validate_original_representation(candidate):
                return candidate
        for cross_ref in resolved.details.get("crossRef", []):
            if not isinstance(cross_ref, dict):
                continue
            if cross_ref.get("type") == "original" and cross_ref.get("url"):
                candidate = OriginalRepresentation(
                    href=str(cross_ref["url"]),
                    relation="original",
                    type="original",
                    mediaType=cross_ref.get("mediaType", "text/html"),
                    provenance="spdx-crossref",
                    source=resolved.details.get("detailsUrl"),
                )
                if self._validate_original_representation(candidate):
                    return candidate
        return None

    def _select_legal_representation(self, resolved: ResolvedLicense) -> LegalRepresentation | None:
        reps = self._representations_for(resolved.license_id)
        legal = reps.get("legal")
        if isinstance(legal, dict):
            try:
                candidate = LegalRepresentation.model_validate(legal)
            except Exception:
                return None
            if self._validate_legal_representation(candidate):
                return candidate
        return None

    def _select_machine_representation(self, resolved: ResolvedLicense) -> MachineRepresentation | None:
        reps = self._representations_for(resolved.license_id)
        machine = reps.get("machine")
        if isinstance(machine, dict):
            try:
                candidate = MachineRepresentation.model_validate(machine)
            except Exception:
                return None
            if self._validate_machine_representation(candidate):
                return candidate
        return None

    def _select_encoding_representation(self, resolved: ResolvedLicense) -> EncodingRepresentation | None:
        reps = self._representations_for(resolved.license_id)
        encoding = reps.get("encoding")
        if isinstance(encoding, dict):
            try:
                candidate = EncodingRepresentation.model_validate(encoding)
            except Exception:
                return None
            if self._validate_encoding_representation(candidate):
                return candidate
        return None

    def build_metadata(self, resolved: ResolvedLicense) -> dict[str, Any]:
        details = resolved.details
        record = resolved.record
        original = self._select_original_representation(resolved)
        legal = self._select_legal_representation(resolved)
        machine = self._select_machine_representation(resolved)
        encoding = self._select_encoding_representation(resolved)

        missing_representations = []
        if original is None:
            missing_representations.append("original")
        if machine is None:
            missing_representations.append("machine")

        missing_table4_fields = []
        for field_name in ("licenseText", "standardLicenseTemplate", "licenseTextHtml"):
            value = details.get(field_name)
            if value is None:
                missing_table4_fields.append(field_name)
                continue
            if isinstance(value, str) and not value.strip():
                missing_table4_fields.append(field_name)

        missing_table5_fields, invalid_table5_fields = self._validate_table5_crossrefs(details)
        missing_metadata_fields = missing_table4_fields + missing_table5_fields

        conformance = ConformanceStatus(
            conformant=not missing_representations and not missing_metadata_fields and not invalid_table5_fields,
            specification="LICENCE FACADE SERVICE - Rights & Ethics",
            requirements={
                "LFS-REQ-2-04": ConformanceRequirement(
                    status="passed" if not missing_representations else "failed",
                    missing=missing_representations,
                    note="Table 2 mandatory representation coverage",
                ),
                "LFS-REQ-4-01": ConformanceRequirement(
                    status="passed" if not missing_metadata_fields and not invalid_table5_fields else "failed",
                    missing=missing_metadata_fields,
                    invalid=invalid_table5_fields,
                ),
            },
        )
        representation_status = {
            "original": {"available": original is not None, "mandatory": True},
            "machine": {"available": machine is not None, "mandatory": True},
            "legal": {"available": legal is not None, "mandatory": False},
            "encoding": {"available": encoding is not None, "mandatory": False},
        }

        cross_refs = self._table6_crossrefs(
            resolved,
            {"original": original, "legal": legal, "machine": machine, "encoding": encoding},
        )
        details_url = f"/api/v1/licenses/{resolved.license_id}/json"
        reference_number = details.get("referenceNumber") if "referenceNumber" in details else record.get("referenceNumber")
        is_fsf_libre = details.get("isFsfLibre") if "isFsfLibre" in details else record.get("isFsfLibre")
        spdx_details_url = (
            record.get("spdxDetailsURL")
            or record.get("detailsUrl")
            or record.get("detailsURL")
            or details.get("detailsURL")
            or details.get("detailsUrl")
        )
        metadata = {
            "uri": resolved.uri,
            "referenceNumber": reference_number,
            "licenseId": resolved.license_id,
            "licenseID": resolved.license_id,
            "licenceID": resolved.license_id,
            "name": record.get("name") or details.get("name"),
            "detailsURL": details_url,
            "spdxDetailsURL": spdx_details_url,
            "reference": record.get("reference"),
            "isDeprecatedLicenseId": bool(record.get("isDeprecatedLicenseId", False)),
            "isDeprecatedLicenseID": bool(record.get("isDeprecatedLicenseId", False)),
            "seeAlso": record.get("seeAlso", []),
            "isOsiApproved": bool(record.get("isOsiApproved", False)),
            "licenseText": details.get("licenseText"),
            "standardLicenseTemplate": details.get("standardLicenseTemplate"),
            "licenseTextHtml": details.get("licenseTextHtml"),
            "licenseComments": details.get("licenseComments"),
            "standardLicenseHeader": details.get("standardLicenseHeader"),
            "standardLicenseHeaderTemplate": details.get("standardLicenseHeaderTemplate"),
            "crossRef": [item.model_dump(exclude_none=True) for item in cross_refs],
            "representations": {
                key: value.model_dump(exclude_none=True)
                for key, value in {
                    "original": original,
                    "legal": legal,
                    "machine": machine,
                    "encoding": encoding,
                }.items()
                if value is not None
            },
            "conformance": conformance.model_dump(exclude_none=True),
            "representationStatus": representation_status,
            "_links": self.representation_links(resolved),
        }
        if is_fsf_libre is not None:
            metadata["isFsfLibre"] = is_fsf_libre
        return metadata

    def build_inventory_item(self, record: dict[str, Any]) -> LicenseInventoryItem:
        license_id = record.get("licenseId")
        return LicenseInventoryItem(
            uri=record.get("uri") or generate_license_uri(license_id),
            referenceNumber=record.get("referenceNumber"),
            licenseId=license_id,
            name=record.get("name"),
            isDeprecatedLicenseId=bool(record.get("isDeprecatedLicenseId", False)),
            isOsiApproved=bool(record.get("isOsiApproved", False)),
            seeAlso=record.get("seeAlso", []),
            detailsURL=f"/api/v1/licenses/{license_id}/json",
            spdxDetailsURL=(
                record.get("spdxDetailsURL")
                or record.get("detailsUrl")
                or record.get("detailsURL")
            ),
            reference=record.get("reference"),
            isFsfLibre=record.get("isFsfLibre"),
        )

    def _render_html(self, metadata: dict[str, Any]) -> str:
        def safe_href(value: str | None) -> str:
            if not value:
                return "#"
            parsed = urlparse(value)
            if parsed.scheme and parsed.scheme != "https":
                return "#"
            return value

        links = metadata.get("representations", {})
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>"
            f"{safe_escape_text(metadata.get('name'))}</title></head><body>"
            f"<h1>{safe_escape_text(metadata.get('name'))}</h1>"
            f"<p><strong>License ID:</strong> {safe_escape_text(metadata.get('licenseId'))}</p>"
            f"<p><strong>URI:</strong> {safe_escape_text(metadata.get('uri'))}</p>"
            "<ul>"
            + "".join(
                f"<li><a href=\"{safe_href(rep.get('href') or '')}\">{safe_escape_text(name)}</a></li>"
                for name, rep in links.items()
            )
            + "</ul></body></html>"
        )

    def render_representation(self, resolved: ResolvedLicense, representation: str) -> tuple[str | bytes, str]:
        metadata = self.build_metadata(resolved)
        if representation == REPRESENTATION_HTML:
            return self._render_html(metadata), REPRESENTATION_MEDIA_TYPES[REPRESENTATION_HTML]
        if representation == REPRESENTATION_JSON:
            return json.dumps(metadata), REPRESENTATION_MEDIA_TYPES[REPRESENTATION_JSON]
        if representation == REPRESENTATION_JSON_LD:
            return json_to_rdf(metadata, format="json-ld"), REPRESENTATION_MEDIA_TYPES[REPRESENTATION_JSON_LD]
        if representation == REPRESENTATION_TURTLE:
            return json_to_rdf(metadata, format="turtle"), REPRESENTATION_MEDIA_TYPES[REPRESENTATION_TURTLE]
        if representation == REPRESENTATION_RDFXML:
            return json_to_rdf(metadata, format="xml"), REPRESENTATION_MEDIA_TYPES[REPRESENTATION_RDFXML]
        raise ValueError("Unsupported representation")

    def get_original_source(self, resolved: ResolvedLicense) -> str | None:
        original = self._select_original_representation(resolved)
        return original.href if original else None

    def get_legal_representation(self, resolved: ResolvedLicense) -> LegalRepresentation | None:
        return self._select_legal_representation(resolved)

    def get_machine_representation(self, resolved: ResolvedLicense) -> MachineRepresentation | None:
        return self._select_machine_representation(resolved)

    def get_encoding_representation(self, resolved: ResolvedLicense) -> EncodingRepresentation | None:
        return self._select_encoding_representation(resolved)


def negotiate_representation(accept_header: str | None) -> str | None:
    if accept_header is None or not accept_header.strip():
        return REPRESENTATION_JSON

    media_ranges = [part.strip().split(";")[0].strip() for part in accept_header.split(",") if part.strip()]
    if not media_ranges or "*/*" in media_ranges:
        return REPRESENTATION_JSON

    for media in media_ranges:
        if media == "text/html":
            return REPRESENTATION_HTML
        negotiated = SUPPORTED_ACCEPT_TYPES.get(media)
        if negotiated:
            return negotiated
        if media.endswith("/*"):
            family = media.split("/", 1)[0]
            for supported_media, mapped in SUPPORTED_ACCEPT_TYPES.items():
                if supported_media.startswith(f"{family}/"):
                    return mapped
    return None


def _coerce_optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            return True
        if normalized in {"false", "0", "no", "n"}:
            return False
    return None
