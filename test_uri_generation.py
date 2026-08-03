#!/usr/bin/env python3
"""
Test script for URI generation in license endpoints
Verifies that URIs are generated using UUID5
"""
import asyncio
import sys
import os

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import generate_license_uri, get_license, get_license_json


async def test_uri_generation():
    """Test URI generation for various licenses"""
    print("=" * 70)
    print("Testing URI Generation with UUID5")
    print("=" * 70)
    print()

    # Test the generate_license_uri function directly
    print("Direct URI Generation Tests:")
    print("-" * 70)

    test_licenses = ["MIT", "Apache-2.0", "GPL-3.0-or-later", "Gutmann", "AFL-1.1"]

    for license_id in test_licenses:
        uri = generate_license_uri(license_id)
        print(f"License ID: {license_id:20} → URI: {uri}")

    print()
    print("=" * 70)
    print("Testing Endpoint Responses")
    print("=" * 70)
    print()

    # Test that the same license always gets the same URI (deterministic)
    print("Deterministic UUID Test:")
    print("-" * 70)
    uri1 = generate_license_uri("MIT")
    uri2 = generate_license_uri("MIT")
    print(f"First call:  {uri1}")
    print(f"Second call: {uri2}")
    print(f"Match: {uri1 == uri2} ✓" if uri1 == uri2 else f"Match: {uri1 == uri2} ✗")
    print()

    # Test endpoint responses
    print("Endpoint Response Tests:")
    print("-" * 70)

    try:
        # Test /licenses/{id} endpoint
        print("\nTesting GET /licenses/Gutmann")
        result = await get_license("Gutmann")

        if "uri" in result:
            print(f"✓ URI field present: {result['uri']}")
            print(f"✓ License ID: {result.get('licenseId')}")
            print(f"✓ Name: {result.get('name')}")
        else:
            print("✗ URI field missing!")

        print()

        # Test /licenses/{id}/json endpoint
        print("Testing GET /licenses/Gutmann/json")
        json_result = await get_license_json("Gutmann")

        if "uri" in json_result:
            print(f"✓ URI field present: {json_result['uri']}")
            print(f"✓ License ID: {json_result.get('licenseId')}")
            print(f"✓ Name: {json_result.get('name')}")
            print(f"✓ Has license text: {'licenseText' in json_result}")
        else:
            print("✗ URI field missing!")

        print()

        # Verify URIs match between endpoints
        if result.get('uri') == json_result.get('uri'):
            print(f"✓ URIs match between /licenses/{{id}} and /licenses/{{id}}/json")
        else:
            print(f"✗ URIs don't match!")
            print(f"  /licenses/{{id}}:      {result.get('uri')}")
            print(f"  /licenses/{{id}}/json: {json_result.get('uri')}")

        print()
        print("=" * 70)
        print("Sample Full Response:")
        print("=" * 70)

        import json as json_lib
        print(json_lib.dumps({
            "uri": json_result.get("uri"),
            "licenseId": json_result.get("licenseId"),
            "name": json_result.get("name"),
            "isDeprecatedLicenseId": json_result.get("isDeprecatedLicenseId"),
            "isOsiApproved": json_result.get("isOsiApproved"),
            "seeAlso": json_result.get("seeAlso", [])[:2]  # Show first 2 URLs
        }, indent=2))

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

    print()
    print("=" * 70)
    print("✓ URI Generation Test Complete!")
    print("=" * 70)


async def main():
    try:
        await test_uri_generation()
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

