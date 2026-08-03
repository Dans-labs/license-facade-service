#!/usr/bin/env python3
"""
Simple script to check if 'licenses' dataset exists in Fuseki and list all datasets
"""

import asyncio
import sys
import httpx
from src.license_facade_service.infra.fuseki_client import FusekiClient


async def get_all_datasets(fuseki_url: str, username: str = "admin", password: str = "admin"):
    """Get list of all datasets in Fuseki."""
    try:
        auth = httpx.BasicAuth(username, password)
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{fuseki_url}/$/datasets", auth=auth)
            if response.status_code == 200:
                data = response.json()
                datasets = [licenses["licenses.name"].strip("/") for licenses in data.get("datasets", [])]
                return datasets
            else:
                print(f"  (API returned status {response.status_code})")
                return None
    except Exception as e:
        print(f"  (error: {e})")
        return None


async def main():
    # Parse arguments
    fuseki_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3030"
    dataset = sys.argv[2] if len(sys.argv) > 2 else "licenses"
    username = sys.argv[3] if len(sys.argv) > 3 else "admin"
    password = sys.argv[4] if len(sys.argv) > 4 else "admin"

    print(f"Checking dataset '{dataset}' in Fuseki at {fuseki_url}...")
    print(f"Using authentication: {username}/{'*' * len(password)}")
    print("-" * 60)

    client = FusekiClient(fuseki_url=fuseki_url, dataset=dataset)

    # Check connection
    if not await client.check_connection():
        print("❌ Fuseki is not accessible")
        return 1

    print("✓ Fuseki is accessible")

    # List all datasets
    print("\nAll datasets in Fuseki:")
    all_datasets = await get_all_datasets(fuseki_url, username, password)
    if all_datasets:
        if len(all_datasets) > 0:
            for idx, licenses in enumerate(all_datasets, 1):
                marker = "→" if licenses == dataset else " "
                print(f"  {marker} {idx}. {licenses}")
        else:
            print("  (no datasets found)")
    else:
        print("  (unable to retrieve dataset list)")
        print("  Hint: Check if authentication is required")

    print("\n" + "-" * 60)

    # Check specific dataset
    if await client.dataset_exists():
        print(f"✓ Dataset '{dataset}' exists")

        # Show stats
        triples = await client.count_triples()
        licenses = await client.get_license_count()

        if triples is not None:
            print(f"  - Triples: {triples:,}")
        if licenses is not None:
            print(f"  - Licenses: {licenses:,}")

        return 0
    else:
        print(f"❌ Dataset '{dataset}' does NOT exist")

        # Try to create the dataset
        print(f"\n🔨 Attempting to create dataset '{dataset}'...")

        created = await client.create_dataset()

        if created:
            print(f"✓ Dataset '{dataset}' created successfully!")

            # Verify it was created
            all_datasets_after = await get_all_datasets(fuseki_url, username, password)
            if all_datasets_after:
                print(f"\nUpdated datasets in Fuseki:")
                for idx, licenses in enumerate(all_datasets_after, 1):
                    marker = "→" if licenses == dataset else " "
                    print(f"  {marker} {idx}. {licenses}")

            return 0
        else:
            print(f"❌ Failed to create dataset '{dataset}'")
            print(f"\nYou can create it manually:")
            print(f"  1. Via Fuseki UI: {fuseki_url}")
            print(f"  2. Via API: curl -X POST {fuseki_url}/$/datasets -d 'dbName={dataset}&dbType=tdb2'")
            return 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print("""
Usage: python check_ds.py [FUSEKI_URL] [DATASET] [USERNAME] [PASSWORD]

Arguments:
  FUSEKI_URL  Fuseki server URL (default: http://localhost:3030)
  DATASET     Dataset name to check (default: licenses)
  USERNAME    Fuseki admin username (default: admin)
  PASSWORD    Fuseki admin password (default: admin)

Examples:
  python check_ds.py
  python check_ds.py http://localhost:3030 abc
  python check_ds.py http://localhost:3030 abc admin mypassword

Features:
  - Lists all datasets in Fuseki
  - Checks if specific dataset exists
  - Automatically creates dataset if missing
  - Shows dataset statistics (triples, licenses)
        """)
        sys.exit(0)

    sys.exit(asyncio.run(main()))

