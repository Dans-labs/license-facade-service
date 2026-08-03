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
from urllib.parse import unquote
from uuid import UUID, NAMESPACE_DNS, uuid5

import httpx
from pydantic import BaseModel, Field

from src.license_facade_service.utils.rdf_transformer import json_to_rdf

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

ALLOWED_REL_MARKERS = ("odrl", "ccrel", "dalicc", "openrel")


class LicenseNotFoundError(Exception):
    """License could not be resolved."""


class ConcurrentRefreshError(Exception):
    """Raised when a concurrent cache refresh is already in progress."""


class OptionalRepresentationUnavailable(Exception):
    """Raised when optional representation is unavailable for this license."""


@dataclass(frozen=True)
class ResolvedLicense:
    license_id: str
    identifier: str
    record: dict[str, Any]
    details: dict[str, Any]
    uri: str


class MachineRepresentation(BaseModel):
    content: str | dict[str, Any]
    media_type: str
    profile: str | None = None
    vocabulary: str | None = None


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
            enriched.append(lic)
        licenses_list["licenses"] = enriched
        return licenses_list

    async def resolve(self, identifier: str) -> ResolvedLicense:
        normalized = unquote(identifier).strip()
        if ".." in normalized or "\\" in normalized:
            raise LicenseNotFoundError

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
        )

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

    def _transform_cross_refs(self, cross_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        transformed: list[dict[str, Any]] = []
        for cross_ref in cross_refs:
            if not isinstance(cross_ref, dict):
                continue
            item = dict(cross_ref)
            if "url" in cross_ref and "URL" not in item:
                item["URL"] = cross_ref["url"]
            if "timestamp" in cross_ref and "timeStamp" not in item:
                item["timeStamp"] = cross_ref["timestamp"]
            transformed.append(item)
        return transformed

    def _representation_payload(self, resolved: ResolvedLicense) -> dict[str, Any]:
        representations: dict[str, Any] = {}
        links = self.representation_links(resolved)
        original = self.get_original_source(resolved)
        legal = self.get_legal_representation(resolved)
        machine = self.get_machine_representation(resolved)
        encoding = resolved.details.get("lfsRepresentations", {}).get("encoding")

        representations["html"] = {"href": links["html"], "mediaType": "text/html"}
        representations["json"] = {"href": links["json"], "mediaType": "application/json"}
        representations["json-ld"] = {"href": links["json-ld"], "mediaType": "application/ld+json"}
        representations["turtle"] = {"href": links["turtle"], "mediaType": "text/turtle"}
        representations["rdfxml"] = {"href": links["rdfxml"], "mediaType": "application/rdf+xml"}
        if original:
            representations["original"] = {
                "href": original,
                "mediaType": "text/html",
            }
        if legal:
            representations["legal"] = {
                "href": links["legal"],
                "mediaType": legal.get("mediaType", "text/plain"),
                "profile": legal.get("profile"),
                "vocabulary": legal.get("vocabulary"),
            }
        if machine:
            representations["machine"] = {
                "href": links["machine"],
                "mediaType": machine.media_type,
                "profile": machine.profile,
                "vocabulary": machine.vocabulary,
            }
        if isinstance(encoding, dict) and encoding.get("href"):
            representations["encoding"] = {
                "href": encoding["href"],
                "mediaType": encoding.get("mediaType"),
                "profile": encoding.get("profile"),
                "vocabulary": encoding.get("vocabulary"),
            }
        return representations

    def build_metadata(self, resolved: ResolvedLicense) -> dict[str, Any]:
        details = resolved.details
        record = resolved.record
        cross_refs = self._transform_cross_refs(details.get("crossRef", []))
        reference_number = record.get("referenceNumber")
        metadata = {
            "uri": resolved.uri,
            "uriRef": resolved.uri,
            "referenceNumber": reference_number,
            "licenseId": resolved.license_id,
            "licenseID": resolved.license_id,
            "licenceID": resolved.license_id,
            "name": record.get("name") or details.get("name"),
            "isDeprecatedLicenseId": record.get("isDeprecatedLicenseId", False),
            "isDeprecatedLicenseID": record.get("isDeprecatedLicenseId", False),
            "isOsiApproved": record.get("isOsiApproved", False),
            "seeAlso": record.get("seeAlso", []),
            "reference": record.get("reference"),
            "detailsURL": record.get("detailsUrl"),
            "detailsUrl": record.get("detailsUrl"),
            "licenseText": details.get("licenseText", ""),
            "standardLicenseTemplate": details.get("standardLicenseTemplate", ""),
            "licenseTextHtml": details.get("licenseTextHtml", ""),
            "crossRef": cross_refs,
            "representations": self._representation_payload(resolved),
            "_links": self.representation_links(resolved),
        }
        if "isFsfLibre" in details:
            metadata["isFsfLibre"] = details.get("isFsfLibre")
        return metadata

    def _render_html(self, metadata: dict[str, Any]) -> str:
        return (
            "<!doctype html>"
            "<html><head><meta charset='utf-8'><title>"
            f"{metadata.get('licenseId')}</title></head><body>"
            f"<h1>{metadata.get('name')}</h1>"
            f"<p><strong>License ID:</strong> {metadata.get('licenseId')}</p>"
            f"<p><strong>URI:</strong> {metadata.get('uri')}</p>"
            "<p>Representations:</p><ul>"
            + "".join(
                f"<li><a href='{href}'>{name}</a></li>"
                for name, href in metadata["_links"].items()
                if name in {"json", "json-ld", "turtle", "rdfxml", "original", "legal", "machine"}
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
        representations = resolved.details.get("lfsRepresentations", {})
        representation = representations.get("original")
        if isinstance(representation, dict) and representation.get("href"):
            return str(representation["href"])
        reference = resolved.record.get("reference")
        if isinstance(reference, str) and reference:
            return reference
        for cross_ref in resolved.details.get("crossRef", []):
            url = cross_ref.get("url")
            if url:
                return str(url)
        return None

    def get_legal_representation(self, resolved: ResolvedLicense) -> dict[str, Any] | None:
        representation = resolved.details.get("lfsRepresentations", {}).get("legal")
        if not isinstance(representation, dict):
            return None
        if not representation.get("content"):
            return None
        return representation

    def get_machine_representation(self, resolved: ResolvedLicense) -> MachineRepresentation | None:
        representation = resolved.details.get("lfsRepresentations", {}).get("machine")
        if not isinstance(representation, dict):
            return None

        content = representation.get("content")
        media_type = representation.get("mediaType")
        if not content or not media_type:
            return None
        profile = representation.get("profile")
        vocabulary = representation.get("vocabulary")
        marker_source = f"{profile or ''} {vocabulary or ''}".lower()
        if not any(marker in marker_source for marker in ALLOWED_REL_MARKERS):
            return None
        return MachineRepresentation(
            content=content,
            media_type=media_type,
            profile=profile,
            vocabulary=vocabulary,
        )

    def get_encoding_representation(self, resolved: ResolvedLicense) -> dict[str, Any] | None:
        representation = resolved.details.get("lfsRepresentations", {}).get("encoding")
        if not isinstance(representation, dict):
            return None
        href = representation.get("href")
        if not href:
            return None
        return representation


def negotiate_representation(accept_header: str | None) -> str | None:
    if accept_header is None or not accept_header.strip():
        return REPRESENTATION_HTML

    media_ranges = [part.strip().split(";")[0].strip() for part in accept_header.split(",") if part.strip()]
    if not media_ranges or "*/*" in media_ranges:
        return REPRESENTATION_HTML

    for media in media_ranges:
        negotiated = SUPPORTED_ACCEPT_TYPES.get(media)
        if negotiated:
            return negotiated
        if media.endswith("/*"):
            family = media.split("/", 1)[0]
            for supported_media, mapped in SUPPORTED_ACCEPT_TYPES.items():
                if supported_media.startswith(f"{family}/"):
                    return mapped
    return None
