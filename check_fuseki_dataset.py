#!/usr/bin/env python3
"""
Check if a Fuseki dataset exists

Simple script to verify if a dataset exists in Apache Jena Fuseki.
"""

import asyncio
import sys
from src.license_facade_service.infra.fuseki_client import FusekiClient


async def check_dataset_exists(fuseki_url: str, dataset: str):
    """Check if a dataset exists in Fuseki."""

    print(f"Checking Fuseki dataset...")
    print(f"  URL: {fuseki_url}")
    print(f"  Dataset: {dataset}")
    print("-" * 60)

    # Create Fuseki client
    client = FusekiClient(fuseki_url=fuseki_url, dataset=dataset)

    # Check connection
    print("\n1. Checking Fuseki connection...")
    is_connected = await client.check_connection()

    if not is_connected:
        print("   ❌ Cannot connect to Fuseki server")
        print(f"   Make sure Fuseki is running at {fuseki_url}")
        return False

    print("   ✅ Fuseki server is accessible")

    # Check if dataset exists
    print(f"\n2. Checking if dataset '{dataset}' exists...")
    exists = await client.dataset_exists()

    if exists:
        print(f"   ✅ Dataset '{dataset}' exists")

        # Get additional information
        print(f"\n3. Getting dataset statistics...")

        # Count triples
        triple_count = await client.count_triples()
        if triple_count is not None:
            print(f"   Total triples: {triple_count:,}")
        else:
            print("   Total triples: Unable to retrieve")

        # Count licenses
        license_count = await client.get_license_count()
        if license_count is not None:
            print(f"   Total licenses: {license_count:,}")
        else:
            print("   Total licenses: Unable to retrieve")

        return True
    else:
        print(f"   ❌ Dataset '{dataset}' does not exist")
        print(f"\n   Available datasets:")

        # Try to list available datasets
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as http_client:
                response = await http_client.get(f"{fuseki_url}/$/datasets")
                if response.status_code == 200:
                    datasets = response.json()
                    dataset_list = [licenses["licenses.name"].strip("/") for licenses in datasets.get("datasets", [])]
                    if dataset_list:
                        for ds_name in dataset_list:
                            print(f"     - {ds_name}")
                    else:
                        print("     (no datasets found)")
                else:
                    print("     (unable to retrieve dataset list)")
        except Exception as e:
            print(f"     (error retrieving list: {e})")

        return False


async def main():
    """Main function."""
    # Default values
    fuseki_url = "http://localhost:3030"
    dataset = "licenses"

    # Parse command line arguments
    if len(sys.argv) > 1:
        fuseki_url = sys.argv[1]
    if len(sys.argv) > 2:
        dataset = sys.argv[2]

    print("=" * 60)
    print("Fuseki Dataset Checker")
    print("=" * 60)

    try:
        exists = await check_dataset_exists(fuseki_url, dataset)

        print("\n" + "=" * 60)
        if exists:
            print("✅ RESULT: Dataset exists and is accessible")
            sys.exit(0)
        else:
            print("❌ RESULT: Dataset does not exist")
            print("\nTo create the dataset, you can:")
            print(f"  1. Use Fuseki web UI: {fuseki_url}")
            print(f"  2. Run: curl -X POST {fuseki_url}/$/datasets -d 'dbName={dataset}&dbType=tdb2'")
            print(f"  3. Start the License Facade Service (will auto-create)")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    print("""
Usage: python check_fuseki_dataset.py [FUSEKI_URL] [DATASET]

Examples:
  python check_fuseki_dataset.py
  python check_fuseki_dataset.py http://localhost:3030 licenses
  python check_fuseki_dataset.py http://fuseki:3030 licenses

Default: http://localhost:3030, dataset 'licenses'
""")

    asyncio.run(main())

