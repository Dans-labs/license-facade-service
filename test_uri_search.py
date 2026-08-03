#!/usr/bin/env python3
"""
Test script for URI-based license lookup in get_license endpoint
"""
import asyncio
import sys
import os

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import get_license, generate_license_uri


async def test_uri_search():
    """Test searching by URI in get_license endpoint"""
    print("=" * 70)
    print("Testing URI-based License Search")
    print("=" * 70)
    print()

    # Test 1: Search by license ID (traditional)
    print("Test 1: Search by license ID (MIT)")
    print("-" * 70)
    try:
        result = await get_license("MIT")
        print(f"✓ Found by license ID")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")
        print(f"  URI: {result.get('uri')}")
        mit_uri = result.get('uri')
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 2: Search by URI (using the URI from Test 1)
    print("Test 2: Search by URI (using MIT's URI)")
    print("-" * 70)
    try:
        result = await get_license(mit_uri)
        print(f"✓ Found by URI")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")
        print(f"  URI: {result.get('uri')}")

        if result.get('licenseId') == 'MIT':
            print(f"✓ Correctly resolved URI to MIT license")
        else:
            print(f"✗ Wrong license returned: {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 3: Search by URI for another license
    print("Test 3: Search by URI for Apache-2.0")
    print("-" * 70)
    try:
        # First get Apache-2.0 by ID to get its URI
        apache_result = await get_license("Apache-2.0")
        apache_uri = apache_result.get('uri')
        print(f"  Apache-2.0 URI: {apache_uri}")

        # Now search by URI
        result = await get_license(apache_uri)
        print(f"✓ Found by URI")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")

        if result.get('licenseId') == 'Apache-2.0':
            print(f"✓ Correctly resolved URI to Apache-2.0 license")
        else:
            print(f"✗ Wrong license returned: {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 4: Invalid URI
    print("Test 4: Invalid URI (should fail)")
    print("-" * 70)
    try:
        result = await get_license("https://example.com/invalid-uri")
        print(f"✗ Should have failed but returned: {result.get('licenseId')}")
        return False
    except Exception as e:
        print(f"✓ Correctly raised exception: {str(e)[:60]}...")

    print()

    # Test 5: Invalid license ID
    print("Test 5: Invalid license ID (should fail)")
    print("-" * 70)
    try:
        result = await get_license("INVALID-LICENSE")
        print(f"✗ Should have failed but returned: {result.get('licenseId')}")
        return False
    except Exception as e:
        print(f"✓ Correctly raised exception: {str(e)[:60]}...")

    return True


async def main():
    success = await test_uri_search()

    print()
    print("=" * 70)
    if success:
        print("✓ All URI-based search tests PASSED!")
        print()
        print("Summary:")
        print("  - Can search by license ID (e.g., 'MIT')")
        print("  - Can search by full URI (e.g., 'https://lfs.../uuid')")
        print("  - Returns same license data for both methods")
        print("  - Properly handles invalid URIs and IDs")
    else:
        print("✗ Some tests FAILED!")
    print("=" * 70)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())

