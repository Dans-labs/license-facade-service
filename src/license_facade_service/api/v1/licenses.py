import logging
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_DNS

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse


router = APIRouter()

# Base URL for URI generation
URL_BASE = os.getenv("URL_BASE", "https://lfs.labs.dansdemo.nl/api/v1/licenses")

# SPDX License List Data GitHub URLs
SPDX_LICENSES_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
SPDX_DETAILS_BASE_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/details"

# Cache directory setup
BASE_DIR = os.getenv("BASE_DIR", os.getcwd())
CACHE_DIR = Path(BASE_DIR) / "resources" / "data" / "licenses"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

LICENSES_LIST_CACHE = CACHE_DIR / "licenses_list.json"
VERSION_FILE = CACHE_DIR / "version.json"


def generate_license_uri(license_id: str) -> str:
    """Generate a consistent URI for a license using UUID5 based on license ID."""
    # Use UUID5 with DNS namespace to generate deterministic UUIDs
    license_uuid = uuid5(NAMESPACE_DNS, f"spdx.org/licenses/{license_id}")
    return f"{URL_BASE}/{license_uuid}"


def get_cached_version() -> Optional[Dict[str, Any]]:
    """Get the cached version information."""
    try:
        if VERSION_FILE.exists():
            with open(VERSION_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to read cached version: {e}")
    return None


def save_version_info(version: str, license_count: int):
    """Save version information to cache."""
    try:
        version_data = {
            "licenseListVersion": version,
            "licenseCount": license_count,
            "lastUpdated": datetime.now(timezone.utc).isoformat()
        }
        with open(VERSION_FILE, 'w') as f:
            json.dump(version_data, f, indent=2)
        logging.info(f"Saved version info: {version}")
    except Exception as e:
        logging.error(f"Failed to save version info: {e}")


def get_cached_licenses_list() -> Optional[Dict[str, Any]]:
    """Get the cached licenses list."""
    try:
        if LICENSES_LIST_CACHE.exists():
            with open(LICENSES_LIST_CACHE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to read cached licenses list: {e}")
    return None


def save_licenses_list(data: Dict[str, Any]):
    """Save licenses list to cache with URIs added to each license."""
    try:
        # Add URI to each license in the list
        if "licenses" in data:
            for license_info in data["licenses"]:
                license_id = license_info.get("licenseId")
                if license_id:
                    license_info["uri"] = generate_license_uri(license_id)

        with open(LICENSES_LIST_CACHE, 'w') as f:
            json.dump(data, f, indent=2)
        logging.info(f"Saved licenses list with {len(data.get('licenses', []))} licenses")
    except Exception as e:
        logging.error(f"Failed to save licenses list: {e}")


def get_cached_license_details(license_id: str) -> Optional[Dict[str, Any]]:
    """Get cached license details."""
    try:
        cache_file = CACHE_DIR / f"{license_id}.json"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to read cached license {license_id}: {e}")
    return None


def save_license_details(license_id: str, data: Dict[str, Any]):
    """Save license details to cache with URI."""
    try:
        # Add URI to the data before saving
        data_with_uri = {"uri": generate_license_uri(license_id)}
        data_with_uri.update(data)

        cache_file = CACHE_DIR / f"{license_id}.json"
        with open(cache_file, 'w') as f:
            json.dump(data_with_uri, f, indent=2)
        logging.debug(f"Saved license details for {license_id}")
    except Exception as e:
        logging.error(f"Failed to save license details for {license_id}: {e}")


async def check_for_updates() -> bool:
    """Check if SPDX license data has been updated."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(SPDX_LICENSES_URL)
            response.raise_for_status()
            remote_data = response.json()
            remote_version = remote_data.get("licenseListVersion")

            cached_version_info = get_cached_version()

            if not cached_version_info:
                logging.info("No cached version found, will download all licenses")
                return True

            cached_version = cached_version_info.get("licenseListVersion")

            if remote_version != cached_version:
                logging.info(f"Version changed: {cached_version} -> {remote_version}")
                return True

            logging.debug(f"Cache is up to date: {remote_version}")
            return False
    except Exception as e:
        logging.error(f"Failed to check for updates: {e}")
        return False


async def download_all_licenses():
    """Download and cache all license data from SPDX."""
    logging.info("Starting download of all SPDX licenses...")

    try:
        # Fetch licenses list
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(SPDX_LICENSES_URL)
            response.raise_for_status()
            licenses_data = response.json()

        # Save licenses list
        save_licenses_list(licenses_data)

        # Get all license IDs
        licenses_list = licenses_data.get("licenses", [])
        total = len(licenses_list)
        logging.info(f"Downloading {total} license details...")

        # Download each license detail
        success_count = 0
        async with httpx.AsyncClient(timeout=30.0) as client:
            for idx, license_info in enumerate(licenses_list, 1):
                license_id = license_info.get("licenseId")
                try:
                    url = f"{SPDX_DETAILS_BASE_URL}/{license_id}.json"
                    response = await client.get(url)
                    response.raise_for_status()
                    details = response.json()
                    save_license_details(license_id, details)
                    success_count += 1

                    if idx % 50 == 0:
                        logging.info(f"Progress: {idx}/{total} licenses downloaded")
                except Exception as e:
                    logging.error(f"Failed to download {license_id}: {e}")

        # Save version info
        version = licenses_data.get("licenseListVersion")
        save_version_info(version, success_count)

        logging.info(f"Download complete: {success_count}/{total} licenses cached")
        return True

    except Exception as e:
        logging.error(f"Failed to download licenses: {e}")
        return False


async def ensure_cache_updated():
    """Ensure the cache is up to date, download if needed."""
    # Check if we need to update
    needs_update = await check_for_updates()

    if needs_update:
        logging.info("Cache update needed, downloading latest licenses...")
        await download_all_licenses()
    else:
        logging.debug("Using cached license data")


async def fetch_licenses_list() -> Dict[str, Any]:
    """Fetch the complete list of licenses (from cache or SPDX)."""
    # Try to get from cache first
    cached_data = get_cached_licenses_list()

    if cached_data:
        logging.debug("Using cached licenses list")
        return cached_data

    # If no cache, fetch from remote and cache it
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(SPDX_LICENSES_URL)
            response.raise_for_status()
            data = response.json()
            save_licenses_list(data)

            # Also save version info
            version = data.get("licenseListVersion")
            licenses_count = len(data.get("licenses", []))
            save_version_info(version, licenses_count)

            return data
    except httpx.HTTPError as e:
        logging.error(f"Failed to fetch licenses list: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch licenses from SPDX repository")
    except Exception as e:
        logging.error(f"Unexpected error fetching licenses list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def fetch_license_details(license_id: str) -> Dict[str, Any]:
    """Fetch detailed information for a specific license (from cache or SPDX)."""
    # Try to get from cache first
    cached_data = get_cached_license_details(license_id)

    if cached_data:
        logging.debug(f"Using cached details for {license_id}")
        return cached_data

    # If no cache, fetch from remote and cache it
    try:
        url = f"{SPDX_DETAILS_BASE_URL}/{license_id}.json"
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            save_license_details(license_id, data)
            return data
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"License '{license_id}' not found")
        logging.error(f"HTTP error fetching license {license_id}: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch license details")
    except httpx.HTTPError as e:
        logging.error(f"Failed to fetch license details for {license_id}: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch license details")
    except Exception as e:
        logging.error(f"Unexpected error fetching license {license_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/licenses")
async def licenses():
    """Retrieve all available licenses with complete details from SPDX license list."""
    logging.debug("Licenses endpoint called")

    # Get the licenses list
    data = await fetch_licenses_list()
    licenses_list = data.get("licenses", [])

    # Enrich each license with detailed information
    enriched_licenses = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for idx, license_info in enumerate(licenses_list, 1):
            license_id = license_info.get("licenseId")

            try:
                # Fetch detailed information for this license
                details = await fetch_license_details(license_id)

                # Build complete license object with all requested fields in order
                complete_license = {
                    "uri": license_info.get("uri") or generate_license_uri(license_id),
                    "referenceNumber": license_info.get("referenceNumber"),
                    "licenseId": license_info.get("licenseId"),
                    "name": license_info.get("name"),
                    "detailsUrl": license_info.get("detailsUrl"),
                    "reference": license_info.get("reference"),
                    "isDeprecatedLicenseId": license_info.get("isDeprecatedLicenseId", False),
                    "seeAlso": license_info.get("seeAlso", []),
                    "isOsiApproved": license_info.get("isOsiApproved", False),
                    "licenseText": details.get("licenseText", ""),
                    "standardLicenseTemplate": details.get("standardLicenseTemplate", ""),
                    "licenseTextHtml": details.get("licenseTextHtml", ""),
                    "crossRef": details.get("crossRef", [])
                }

                enriched_licenses.append(complete_license)

                if idx % 50 == 0:
                    logging.info(f"Enriched {idx}/{len(licenses_list)} licenses")

            except Exception as e:
                logging.warning(f"Failed to enrich license {license_id}: {e}, using basic info")
                # If detailed fetch fails, return basic info
                basic_license = {
                    "uri": license_info.get("uri") or generate_license_uri(license_id),
                    "referenceNumber": license_info.get("referenceNumber"),
                    "licenseId": license_info.get("licenseId"),
                    "name": license_info.get("name"),
                    "detailsUrl": license_info.get("detailsUrl"),
                    "reference": license_info.get("reference"),
                    "isDeprecatedLicenseId": license_info.get("isDeprecatedLicenseId", False),
                    "seeAlso": license_info.get("seeAlso", []),
                    "isOsiApproved": license_info.get("isOsiApproved", False),
                    "licenseText": "",
                    "standardLicenseTemplate": "",
                    "licenseTextHtml": "",
                    "crossRef": []
                }
                enriched_licenses.append(basic_license)

    logging.info(f"Returning {len(enriched_licenses)} enriched licenses")

    return {
        "licenseListVersion": data.get("licenseListVersion"),
        "licenses": enriched_licenses
    }


@router.get("/licenses/cache/status")
async def cache_status():
    """Get cache status and version information."""
    version_info = get_cached_version()

    if not version_info:
        return {
            "cached": False,
            "message": "No cached data available"
        }

    # Count cached license files
    cached_files = list(CACHE_DIR.glob("*.json"))
    # Exclude version.json and licenses_list.json
    license_details_count = len([f for f in cached_files if f.name not in ["version.json", "licenses_list.json"]])

    return {
        "cached": True,
        "version": version_info.get("licenseListVersion"),
        "totalLicenses": version_info.get("licenseCount"),
        "cachedDetails": license_details_count,
        "lastUpdated": version_info.get("lastUpdated"),
        "cacheDirectory": str(CACHE_DIR)
    }


@router.post("/licenses/cache/update")
async def update_cache():
    """Manually trigger cache update from SPDX repository."""
    logging.info("Manual cache update triggered")

    try:
        needs_update = await check_for_updates()

        if needs_update:
            success = await download_all_licenses()
            if success:
                version_info = get_cached_version()
                return {
                    "status": "success",
                    "message": "Cache updated successfully",
                    "version": version_info.get("licenseListVersion") if version_info else None
                }
            else:
                raise HTTPException(status_code=500, detail="Failed to download licenses")
        else:
            version_info = get_cached_version()
            return {
                "status": "up-to-date",
                "message": "Cache is already up to date",
                "version": version_info.get("licenseListVersion") if version_info else None
            }
    except Exception as e:
        logging.error(f"Cache update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cache update failed: {str(e)}")


@router.post("/licenses/cache/refresh")
async def refresh_cache():
    """Force refresh cache regardless of version."""
    logging.info("Forced cache refresh triggered")

    try:
        success = await download_all_licenses()
        if success:
            version_info = get_cached_version()
            return {
                "status": "success",
                "message": "Cache refreshed successfully",
                "version": version_info.get("licenseListVersion") if version_info else None
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to refresh cache")
    except Exception as e:
        logging.error(f"Cache refresh failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cache refresh failed: {str(e)}")



@router.get("/licenses/{id}")
async def get_license(id: str):
    """Get complete license information by license ID or URI."""
    logging.debug(f"Get license endpoint called with id: {id}")

    # Get basic info from licenses list
    data = await fetch_licenses_list()
    licenses_list = data.get("licenses", [])

    # Check if id is a URI, UUID, or license ID
    license_info = None
    actual_id = id

    if id.startswith("http://") or id.startswith("https://"):
        # It's a full URI, search by exact URI match
        logging.debug(f"Searching by full URI: {id}")
        license_info = next((lic for lic in licenses_list if lic.get("uri") == id), None)

        # If found by URI, get the actual license ID
        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by full URI: {actual_id}")
    elif "/" in id:
        # It might be a partial UUID or path, extract UUID portion if present
        logging.debug(f"Searching by URI-like pattern: {id}")
        # Extract the UUID from the end (last segment after /)
        uuid_part = id.split("/")[-1] if "/" in id else id

        # Search by URI containing this UUID
        license_info = next((lic for lic in licenses_list if uuid_part in lic.get("uri", "")), None)

        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by UUID in URI: {actual_id}")
    elif "-" in id and len(id) == 36:
        # It looks like a UUID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        logging.debug(f"Searching by UUID: {id}")
        license_info = next((lic for lic in licenses_list if id in lic.get("uri", "")), None)

        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by UUID: {actual_id}")
    else:
        # It's a license ID, search by licenseId field
        logging.debug(f"Searching by license ID: {id}")
        license_info = next((lic for lic in licenses_list if lic.get("licenseId") == id), None)

    if not license_info:
        raise HTTPException(status_code=404, detail=f"License '{id}' not found")

    # Get detailed info including full text, templates, HTML, and cross-references
    try:
        details = await fetch_license_details(actual_id)

        # Build complete info with all fields from details
        complete_info = {
            "uri": license_info.get("uri") or generate_license_uri(actual_id),
            "isDeprecatedLicenseId": license_info.get("isDeprecatedLicenseId", False),
            "licenseText": details.get("licenseText", ""),
            "standardLicenseTemplate": details.get("standardLicenseTemplate", ""),
            "name": license_info.get("name"),
            "licenseId": license_info.get("licenseId"),
            "crossRef": details.get("crossRef", []),
            "seeAlso": license_info.get("seeAlso", []),
            "isOsiApproved": license_info.get("isOsiApproved", False),
            "licenseTextHtml": details.get("licenseTextHtml", "")
        }

        # Add isFsfLibre from details if available
        if "isFsfLibre" in details:
            complete_info["isFsfLibre"] = details.get("isFsfLibre")

        return complete_info
    except HTTPException:
        # If details not available, return basic info from list with URI
        if "uri" not in license_info:
            license_info["uri"] = generate_license_uri(actual_id)
        return license_info
    except Exception as e:
        logging.warning(f"Could not fetch details for {actual_id}: {e}, returning basic info")
        if "uri" not in license_info:
            license_info["uri"] = generate_license_uri(actual_id)
        return license_info


@router.get("/licenses/{id}/json")
async def get_license_json(id: str):
    """Get detailed license information in JSON format with all fields."""
    logging.debug(f"Get license JSON endpoint called with id: {id}")

    # Get basic info from licenses list
    data = await fetch_licenses_list()
    licenses_list = data.get("licenses", [])

    # Check if id is a URI, UUID, or license ID (same logic as get_license)
    license_info = None
    actual_id = id

    if id.startswith("http://") or id.startswith("https://"):
        # It's a full URI, search by exact URI match
        logging.debug(f"Searching by full URI: {id}")
        license_info = next((lic for lic in licenses_list if lic.get("uri") == id), None)

        # If found by URI, get the actual license ID
        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by full URI: {actual_id}")
    elif "/" in id:
        # It might be a partial UUID or path, extract UUID portion if present
        logging.debug(f"Searching by URI-like pattern: {id}")
        # Extract the UUID from the end (last segment after /)
        uuid_part = id.split("/")[-1] if "/" in id else id

        # Search by URI containing this UUID
        license_info = next((lic for lic in licenses_list if uuid_part in lic.get("uri", "")), None)

        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by UUID in URI: {actual_id}")
    elif "-" in id and len(id) == 36:
        # It looks like a UUID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        logging.debug(f"Searching by UUID: {id}")
        license_info = next((lic for lic in licenses_list if id in lic.get("uri", "")), None)

        if license_info:
            actual_id = license_info.get("licenseId")
            logging.debug(f"Found license by UUID: {actual_id}")
    else:
        # It's a license ID, search by licenseId field
        logging.debug(f"Searching by license ID: {id}")
        license_info = next((lic for lic in licenses_list if lic.get("licenseId") == id), None)

    if not license_info:
        raise HTTPException(status_code=404, detail=f"License '{id}' not found")

    # Get detailed info including full text, templates, HTML, and cross-references
    try:
        details = await fetch_license_details(actual_id)

        # Build complete info with all fields from details - same structure as get_license
        complete_info = {
            "uri": license_info.get("uri") or generate_license_uri(actual_id),
            "isDeprecatedLicenseId": license_info.get("isDeprecatedLicenseId", False),
            "licenseText": details.get("licenseText", ""),
            "standardLicenseTemplate": details.get("standardLicenseTemplate", ""),
            "name": license_info.get("name"),
            "licenseId": license_info.get("licenseId"),
            "crossRef": details.get("crossRef", []),
            "seeAlso": license_info.get("seeAlso", []),
            "isOsiApproved": license_info.get("isOsiApproved", False),
            "licenseTextHtml": details.get("licenseTextHtml", "")
        }

        # Add isFsfLibre from details if available
        if "isFsfLibre" in details:
            complete_info["isFsfLibre"] = details.get("isFsfLibre")

        return complete_info
    except HTTPException:
        # If details not available, return basic info from list with URI
        if "uri" not in license_info:
            license_info["uri"] = generate_license_uri(actual_id)
        return license_info
    except Exception as e:
        logging.warning(f"Could not fetch details for {actual_id}: {e}, returning basic info")
        if "uri" not in license_info:
            license_info["uri"] = generate_license_uri(actual_id)
        return license_info


@router.get("/licenses/{id}/original", response_class=PlainTextResponse)
async def get_license_original(id: str):
    """Get original license text."""
    logging.debug(f"Get license original endpoint called with id: {id}")
    details = await fetch_license_details(id)
    license_text = details.get("licenseText", "")

    if not license_text:
        raise HTTPException(status_code=404, detail=f"License text not found for '{id}'")

    return license_text


@router.get("/licenses/{id}/machine")
async def get_license_machine(id: str):
    """Get machine-readable license format with key metadata."""
    logging.debug(f"Get license machine endpoint called with id: {id}")
    details = await fetch_license_details(id)

    return {
        "licenseId": details.get("licenseId"),
        "name": details.get("name"),
        "isOsiApproved": details.get("isOsiApproved", False),
        "isFsfLibre": details.get("isFsfLibre"),
        "isDeprecatedLicenseId": details.get("isDeprecatedLicenseId", False),
        "seeAlso": details.get("seeAlso", []),
        "crossRef": details.get("crossRef", [])
    }


@router.get("/licenses/{id}/legal", response_class=PlainTextResponse)
async def get_license_legal(id: str):
    """Get legal text (same as original for SPDX licenses)."""
    logging.debug(f"Get license legal endpoint called with id: {id}")
    details = await fetch_license_details(id)
    license_text = details.get("licenseText", "")

    if not license_text:
        raise HTTPException(status_code=404, detail=f"License text not found for '{id}'")

    return license_text
