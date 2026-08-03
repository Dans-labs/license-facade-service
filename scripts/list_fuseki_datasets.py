"""List all Apache Jena Fuseki datasets via the admin API.

Usage (from project root):

    uv run python scripts/list_fuseki_datasets.py

By default this script connects to:
  - URL: http://localhost:3030
  - Username: admin
  - Password: admin

You can override these via environment variables:
  FUSEKI_URL, FUSEKI_USER, FUSEKI_PASSWORD
"""

import os
import sys
from typing import Any, Dict, List

import httpx


DEFAULT_FUSEKI_URL = "http://localhost:3030"
DEFAULT_FUSEKI_USER = "admin"
DEFAULT_FUSEKI_PASSWORD = "admin"


def get_fuseki_config() -> Dict[str, str]:
    """Return Fuseki connection settings, allowing env overrides."""
    return {
        "url": os.getenv("FUSEKI_URL", DEFAULT_FUSEKI_URL).rstrip("/"),
        "user": os.getenv("FUSEKI_USER", DEFAULT_FUSEKI_USER),
        "password": os.getenv("FUSEKI_PASSWORD", DEFAULT_FUSEKI_PASSWORD),
    }


def format_dataset_row(ds: Dict[str, Any]) -> str:
    """Return a one-line human-readable description of a Fuseki dataset entry."""
    name = ds.get("ds.name", "<unknown>")  # e.g. "/licenses"
    state = ds.get("ds.state", "active")
    ds_type = ds.get("ds.type", "")
    services = ds.get("ds.services", []) or []

    service_names = ", ".join(sorted({s.get("srv.type", "?") for s in services})) or "-"

    return f"{name:20} type={ds_type:<10} state={state:<10} services=[{service_names}]"


def list_datasets() -> int:
    cfg = get_fuseki_config()
    admin_url = f"{cfg['url']}/$/datasets"

    print("========================================")
    print("Fuseki dataset listing")
    print("========================================")
    print(f"URL:      {admin_url}")
    print(f"Username: {cfg['user']}")
    print("----------------------------------------")

    try:
        with httpx.Client(auth=(cfg["user"], cfg["password"])) as client:
            resp = client.get(admin_url, timeout=10.0)
            resp.raise_for_status()
            datasets: List[Dict[str, Any]] = resp.json()
    except httpx.HTTPStatusError as e:
        print(f"✗ HTTP error when talking to Fuseki: {e.response.status_code} {e.response.reason_phrase}")
        print(f"  URL: {e.request.url}")
        return 1
    except httpx.RequestError as e:
        print(f"✗ Failed to connect to Fuseki: {e}")
        print("  Is Fuseki running and reachable at the configured URL?")
        return 1
    except ValueError as e:
        print(f"✗ Failed to parse JSON response from Fuseki: {e}")
        return 1

    if not datasets:
        print("No datasets found.")
        return 0

    print(f"Found {len(datasets)} dataset(s):\n")
    for ds in datasets:
        print(" - " + format_dataset_row(ds))

    return 0


if __name__ == "__main__":
    sys.exit(list_datasets())

