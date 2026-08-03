#!/usr/bin/env python3
"""Create a complete SPDX 3.0 JSON-LD document for a given license.

This script mirrors the logic of the API endpoint
`POST /licenses/spdx3/complete/{license_id}` implemented in
`src/license_facade_service/api/v1/licenses.py`.

It reads SPDX v2 JSON from the cached SPDX licenses (or directly
from the SPDX license-list-data repository) and wraps it into a
minimal SPDX 3.0 JSON-LD structure with:

- CreationInfo node
- SpdxDocument node
- ListedLicense node (expandedlicensing_ListedLicense)

Usage examples:

    python scripts/create_complete_spdx_v3.py 0BSD
    python scripts/create_complete_spdx_v3.py 0BSD --out spdx_out/0BSD.spdx3.jsonld
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import httpx

# Paths and URLs aligned with the service
BASE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = BASE_DIR / "resources" / "data" / "licenses"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

SPDX_DETAILS_BASE_URL = (
    "https://raw.githubusercontent.com/spdx/license-list-data/main/json/details"
)


def load_spdx2_details(license_id: str) -> Dict[str, Any]:
    """Load SPDX v2 JSON details from cache or remote SPDX repo."""
    cache_file = CACHE_DIR / f"{license_id}.json"

    # Try cache first
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            # Fall back to remote fetch
            pass

    # Fetch from SPDX repo
    url = f"{SPDX_DETAILS_BASE_URL}/{license_id}.json"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise SystemExit(f"ERROR: License '{license_id}' not found in SPDX repository")
        raise SystemExit(f"ERROR: HTTP error fetching SPDX v2 details for {license_id}: {e}")
    except Exception as e:
        raise SystemExit(f"ERROR: Failed to fetch SPDX v2 details for {license_id}: {e}")

    # Cache it
    try:
        cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        # Non-fatal if caching fails
        pass

    return data


def build_complete_spdx3_document(license_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """Build a complete SPDX 3.0 JSON-LD document for the given license.

    Structure:
    - @context: SPDX 3.0.1 context URL
    - @graph:
      * CreationInfo node
      * SpdxDocument node (rootElement -> ListedLicense)
      * expandedlicensing_ListedLicense node with license data
    """
    created = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    creation_info_id = "_:creationInfo_0"
    namespace = f"https://spdx.org/spdxdocs/{license_id}"
    document_spdx_id = f"{namespace}_document"
    license_element_id = f"{namespace}#License-{license_id}"

    creation_info_node: Dict[str, Any] = {
        "@id": creation_info_id,
        "type": "CreationInfo",
        "specVersion": "3.0.1",
        "createdBy": [f"{namespace}/creator"],
        "created": created,
    }

    document_node: Dict[str, Any] = {
        "spdxId": document_spdx_id,
        "type": "SpdxDocument",
        "rootElement": [license_element_id],
        "name": f"SPDX Document for {license_id}",
        "creationInfo": creation_info_id,
    }

    license_node: Dict[str, Any] = {
        "spdxId": license_element_id,
        "type": "expandedlicensing_ListedLicense",
        "name": details.get("name"),
        "simplelicensing_licenseText": details.get("licenseText", ""),
        "expandedlicensing_standardLicenseTemplate": details.get(
            "standardLicenseTemplate", ""
        ),
        "expandedlicensing_isOsiApproved": details.get("isOsiApproved", False),
        "expandedlicensing_isDeprecatedLicenseId": details.get(
            "isDeprecatedLicenseId", False
        ),
        "expandedlicensing_seeAlso": details.get("seeAlso", []),
        "creationInfo": creation_info_id,
    }

    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [creation_info_node, document_node, license_node],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a complete SPDX 3.0 JSON-LD document for a given license.",
    )
    parser.add_argument(
        "license_id",
        help="SPDX license identifier (e.g. 0BSD, MIT, Apache-2.0)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output file path for SPDX 3 JSON-LD (default: <license_id>.spdx3.jsonld)",
    )

    args = parser.parse_args()
    license_id: str = args.license_id
    out_path = (
        Path(args.out)
        if args.out
        else Path(f"{license_id}.spdx3.jsonld")
    )

    print(f"Creating SPDX 3.0 document for license: {license_id}")

    # Load SPDX v2 details
    details = load_spdx2_details(license_id)

    # Build SPDX v3 JSON-LD structure
    spdx3_doc = build_complete_spdx3_document(license_id, details)

    # Write to disk
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(spdx3_doc, indent=2), encoding="utf-8")

    print(f"\n✔ Wrote SPDX 3.0 JSON-LD document to: {out_path}")
    print("You can validate it with your validate_spdx_v3.py script, e.g.:")
    print(f"  python scripts/validate_spdx_v3.py {out_path}")


if __name__ == "__main__":
    main()

