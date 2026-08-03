#!/usr/bin/env python3
"""
Test script for UUID and URI-based license search
Tests searching by:
1. License ID (e.g., "MIT")
2. Full URI (e.g., "https://lfs.labs.dansdemo.nl/api/v1/licenses/d1b405f5-...")
3. UUID only (e.g., "d1b405f5-98e2-5acd-9f7b-531983fb5aad")
4. Partial UUID path (e.g., "d1b405f5-98e2-5acd-9f7b-531983fb5aad/something")
"""
import asyncio
import sys
import os

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import get_license


async def test_all_search_methods():
    """Test all search methods"""
    print("=" * 80)
    print("Testing All License Search Methods")
    print("=" * 80)
    print()

    # Test 1: Get a license by ID to extract its UUID
    print("Step 1: Get 0BSD license by ID to extract UUID")
    print("-" * 80)
    try:
        result = await get_license("0BSD")
        full_uri = result.get("uri")
        print(f"✓ Found by ID: 0BSD")
        print(f"  Full URI: {full_uri}")

        # Extract UUID
        uuid = full_uri.split("/")[-1]
        print(f"  UUID: {uuid}")
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 2: Search by full URI
    print("Test 2: Search by full URI")
    print("-" * 80)
    try:
        result = await get_license(full_uri)
        print(f"✓ Found by full URI")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")

        if result.get('licenseId') != '0BSD':
            print(f"✗ Wrong license! Expected 0BSD but got {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 3: Search by UUID only
    print("Test 3: Search by UUID only")
    print("-" * 80)
    try:
        result = await get_license(uuid)
        print(f"✓ Found by UUID: {uuid}")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")

        if result.get('licenseId') != '0BSD':
            print(f"✗ Wrong license! Expected 0BSD but got {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 4: Search by UUID with extra path
    print("Test 4: Search by UUID with path suffix")
    print("-" * 80)
    try:
        uuid_with_path = f"{uuid}/extra/path"
        result = await get_license(uuid_with_path)
        print(f"✓ Found by UUID path: {uuid_with_path}")
        print(f"  License ID: {result.get('licenseId')}")
        print(f"  Name: {result.get('name')}")

        if result.get('licenseId') != '0BSD':
            print(f"✗ Wrong license! Expected 0BSD but got {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 5: Search by License ID (traditional)
    print("Test 5: Search by License ID (traditional)")
    print("-" * 80)
    try:
        result = await get_license("0BSD")
        print(f"✓ Found by License ID: 0BSD")
        print(f"  Name: {result.get('name')}")

        if result.get('licenseId') != '0BSD':
            print(f"✗ Wrong license! Expected 0BSD but got {result.get('licenseId')}")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 6: Verify all methods return same data
    print("Test 6: Verify all methods return identical data")
    print("-" * 80)
    try:
        result_by_id = await get_license("0BSD")
        result_by_uri = await get_license(full_uri)
        result_by_uuid = await get_license(uuid)

        if result_by_id == result_by_uri == result_by_uuid:
            print(f"✓ All search methods return identical data")
        else:
            print(f"✗ Results differ between search methods!")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 7: Test with another license (MIT)
    print("Test 7: Test MIT license with all search methods")
    print("-" * 80)
    try:
        result = await get_license("MIT")
        mit_uri = result.get("uri")
        mit_uuid = mit_uri.split("/")[-1]

        result_by_id = await get_license("MIT")
        result_by_uri = await get_license(mit_uri)
        result_by_uuid = await get_license(mit_uuid)

        if result_by_id.get('licenseId') == result_by_uri.get('licenseId') == result_by_uuid.get('licenseId') == 'MIT':
            print(f"✓ MIT license found by all search methods")
            print(f"  ID: {result_by_id.get('licenseId')}")
            print(f"  URI: {mit_uri}")
            print(f"  UUID: {mit_uuid}")
        else:
            print(f"✗ Failed to find MIT by all methods")
            return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False

    print()

    # Test 8: Invalid UUID should fail
    print("Test 8: Invalid UUID should return 404")
    print("-" * 80)
    try:
        result = await get_license("00000000-0000-0000-0000-000000000000")
        print(f"✗ Should have failed but returned: {result.get('licenseId')}")
        return False
    except Exception as e:
        print(f"✓ Correctly raised exception: {str(e)[:60]}...")

    return True


async def main():
    success = await test_all_search_methods()

    print()
    print("=" * 80)
    if success:
        print("✓ All search method tests PASSED!")
        print()
        print("Summary of supported search methods:")
        print("  1. License ID:       GET /licenses/MIT")
        print("  2. Full URI:         GET /licenses/https://lfs.labs.dansdemo.nl/api/v1/licenses/uuid")
        print("  3. UUID only:        GET /licenses/d1b405f5-98e2-5acd-9f7b-531983fb5aad")
        print("  4. UUID with path:   GET /licenses/d1b405f5-98e2-5acd-9f7b-531983fb5aad/extra")
    else:
        print("✗ Some tests FAILED!")
    print("=" * 80)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())

