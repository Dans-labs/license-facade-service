"""
Test Apache Jena Fuseki Integration

This script tests the Fuseki integration functionality.
"""

import asyncio
import logging
from pathlib import Path

from src.license_facade_service.infra.fuseki_client import FusekiClient
from src.license_facade_service.utils.license_rdf_uploader import (
    initialize_fuseki_with_licenses,
    upload_all_cached_licenses
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)


async def test_fuseki_connection():
    """Test basic Fuseki connection."""
    print("\n" + "=" * 80)
    print("Test 1: Fuseki Connection")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030")

    # Test connection
    is_connected = await client.check_connection()
    if is_connected:
        print("✓ Successfully connected to Fuseki")
    else:
        print("✗ Cannot connect to Fuseki")
        print("  Make sure Fuseki is running: fuseki-server --port=3030")
        return False

    return True


async def test_dataset_operations():
    """Test dataset creation and checking."""
    print("\n" + "=" * 80)
    print("Test 2: Dataset Operations")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030", dataset="test_licenses")

    # Check if dataset exists
    exists = await client.dataset_exists()
    print(f"Dataset 'test_licenses' exists: {exists}")

    # Create dataset if it doesn't exist
    if not exists:
        created = await client.create_dataset()
        if created:
            print("✓ Dataset 'test_licenses' created successfully")
        else:
            print("✗ Failed to create dataset")
            return False

    return True


async def test_rdf_upload():
    """Test uploading RDF data."""
    print("\n" + "=" * 80)
    print("Test 3: RDF Upload")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030", dataset="test_licenses")

    # Sample RDF data (Turtle format)
    rdf_data = """
    @prefix spdx: <http://spdx.org/rdf/terms#> .
    @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
    
    <http://example.org/test-license> a spdx:License ;
        spdx:licenseId "TEST-1.0" ;
        spdx:name "Test License" ;
        rdfs:label "Test License" ;
        spdx:isOsiApproved false .
    """

    # Upload RDF data
    success = await client.upload_rdf(rdf_data, content_type="text/turtle")

    if success:
        print("✓ RDF data uploaded successfully")

        # Verify upload by counting triples
        count = await client.count_triples()
        print(f"  Total triples in dataset: {count}")

        # Count licenses
        license_count = await client.get_license_count()
        print(f"  Total licenses in dataset: {license_count}")
    else:
        print("✗ Failed to upload RDF data")
        return False

    return True


async def test_sparql_query():
    """Test SPARQL querying."""
    print("\n" + "=" * 80)
    print("Test 4: SPARQL Query")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030", dataset="test_licenses")

    # Query for all licenses
    query = """
    PREFIX spdx: <http://spdx.org/rdf/terms#>
    SELECT ?license ?name
    WHERE {
        ?license a spdx:License ;
                 spdx:name ?name .
    }
    LIMIT 10
    """

    results = await client.query(query)

    if results:
        print("✓ SPARQL query executed successfully")
        bindings = results.get("results", {}).get("bindings", [])
        print(f"  Found {len(bindings)} results")

        for i, binding in enumerate(bindings[:5], 1):
            name = binding.get("name", {}).get("value", "Unknown")
            license_uri = binding.get("license", {}).get("value", "Unknown")
            print(f"  {i}. {name} ({license_uri})")
    else:
        print("✗ Failed to execute SPARQL query")
        return False

    return True


async def test_clear_dataset():
    """Test clearing dataset."""
    print("\n" + "=" * 80)
    print("Test 5: Clear Dataset")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030", dataset="test_licenses")

    # Get count before clearing
    count_before = await client.count_triples()
    print(f"Triples before clear: {count_before}")

    # Clear dataset
    success = await client.clear_dataset()

    if success:
        print("✓ Dataset cleared successfully")

        # Get count after clearing
        count_after = await client.count_triples()
        print(f"Triples after clear: {count_after}")

        if count_after == 0:
            print("✓ Dataset is empty")
        else:
            print(f"⚠ Dataset still has {count_after} triples")
    else:
        print("✗ Failed to clear dataset")
        return False

    return True


async def test_full_license_upload():
    """Test uploading all cached licenses."""
    print("\n" + "=" * 80)
    print("Test 6: Full License Upload")
    print("=" * 80)

    # Initialize Fuseki with actual license data
    result = await initialize_fuseki_with_licenses(
        fuseki_url="http://localhost:3030",
        dataset="test_licenses",
        clear_existing=True
    )

    if result["success"]:
        print("✓ Full license upload completed successfully")

        stats = result.get("upload_stats", {})
        print(f"\nUpload Statistics:")
        print(f"  Total licenses: {stats.get('total_licenses', 0)}")
        print(f"  Uploaded: {stats.get('uploaded', 0)}")
        print(f"  Failed: {stats.get('failed', 0)}")
        print(f"  Batches: {stats.get('batches', 0)}")

        if "fuseki_license_count" in stats:
            print(f"  Licenses in Fuseki: {stats['fuseki_license_count']}")
        if "fuseki_triple_count" in stats:
            print(f"  Total triples: {stats['fuseki_triple_count']}")

        if stats.get("errors"):
            print(f"\nErrors:")
            for error in stats["errors"]:
                print(f"  - {error}")
    else:
        print("✗ Full license upload failed")
        print(f"Fuseki available: {result.get('fuseki_available', False)}")
        if result.get("errors"):
            print("Errors:")
            for error in result["errors"]:
                print(f"  - {error}")
        return False

    return True


async def test_sample_queries():
    """Test sample SPARQL queries on uploaded data."""
    print("\n" + "=" * 80)
    print("Test 7: Sample Queries")
    print("=" * 80)

    client = FusekiClient(fuseki_url="http://localhost:3030", dataset="test_licenses")

    queries = [
        {
            "name": "Count OSI-approved licenses",
            "query": """
                PREFIX spdx: <http://spdx.org/rdf/terms#>
                SELECT (COUNT(?license) as ?count)
                WHERE {
                    ?license a spdx:License ;
                             spdx:isOsiApproved true .
                }
            """
        },
        {
            "name": "Find deprecated licenses",
            "query": """
                PREFIX spdx: <http://spdx.org/rdf/terms#>
                SELECT ?id ?name
                WHERE {
                    ?license a spdx:License ;
                             spdx:licenseId ?id ;
                             spdx:name ?name ;
                             spdx:isDeprecatedLicenseId true .
                }
                LIMIT 5
            """
        },
        {
            "name": "Licenses with 'Apache' in name",
            "query": """
                PREFIX spdx: <http://spdx.org/rdf/terms#>
                SELECT ?id ?name
                WHERE {
                    ?license a spdx:License ;
                             spdx:licenseId ?id ;
                             spdx:name ?name .
                    FILTER(CONTAINS(LCASE(?name), "apache"))
                }
                LIMIT 5
            """
        }
    ]

    for query_info in queries:
        print(f"\n{query_info['name']}:")
        result = await client.query(query_info['query'])

        if result:
            bindings = result.get("results", {}).get("bindings", [])
            if bindings:
                for binding in bindings:
                    values = {k: v.get("value", "") for k, v in binding.items()}
                    print(f"  {values}")
            else:
                print("  No results")
        else:
            print("  Query failed")

    return True


async def main():
    """Run all tests."""
    print("=" * 80)
    print("Apache Jena Fuseki Integration Tests")
    print("=" * 80)

    print("\nPrerequisites:")
    print("1. Fuseki must be running on http://localhost:3030")
    print("2. License cache must be populated")
    print("\nTo start Fuseki:")
    print("  Docker: docker run -d -p 3030:3030 secoresearch/fuseki")
    print("  Manual: fuseki-server --port=3030")

    input("\nPress Enter to start tests...")

    tests = [
        ("Connection", test_fuseki_connection),
        ("Dataset Operations", test_dataset_operations),
        ("RDF Upload", test_rdf_upload),
        ("SPARQL Query", test_sparql_query),
        ("Clear Dataset", test_clear_dataset),
        ("Full License Upload", test_full_license_upload),
        ("Sample Queries", test_sample_queries),
    ]

    results = []

    for name, test_func in tests:
        try:
            success = await test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n✗ Test '{name}' failed with exception: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n⚠ {total - passed} test(s) failed")


if __name__ == "__main__":
    asyncio.run(main())

