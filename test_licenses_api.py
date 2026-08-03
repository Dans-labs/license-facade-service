#!/usr/bin/env python3
"""
Test script for License Facade Service endpoints
Run this after starting the service to verify all endpoints work correctly
"""
import asyncio
import sys
sys.path.insert(0, 'src')

from license_facade_service.api.v1.licenses import (
    fetch_licenses_list,
    fetch_license_details
)


async def test_fetch_licenses():
    """Test fetching the complete license list"""
    print("=" * 60)
    print("Testing: Fetch all licenses")
    print("=" * 60)

    try:
        data = await fetch_licenses_list()
        version = data.get('licenseListVersion')
        licenses = data.get('licenses', [])

        print(f"✓ License List Version: {version}")
        print(f"✓ Total Licenses: {len(licenses)}")
        print(f"✓ First 5 licenses:")
        for lic in licenses[:5]:
            print(f"  - {lic.get('licenseId')}: {lic.get('name')}")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


async def test_fetch_license_details():
    """Test fetching details for specific licenses"""
    print("\n" + "=" * 60)
    print("Testing: Fetch license details")
    print("=" * 60)

    test_licenses = ['MIT', 'Apache-2.0', 'GPL-3.0-or-later', 'BSD-3-Clause']
    results = []

    for license_id in test_licenses:
        try:
            details = await fetch_license_details(license_id)
            name = details.get('name')
            is_osi = details.get('isOsiApproved', False)
            has_text = bool(details.get('licenseText'))

            print(f"✓ {license_id}:")
            print(f"  Name: {name}")
            print(f"  OSI Approved: {is_osi}")
            print(f"  Has License Text: {has_text}")
            results.append(True)
        except Exception as e:
            print(f"✗ {license_id}: Error - {e}")
            results.append(False)

    return all(results)


async def test_invalid_license():
    """Test error handling for invalid license"""
    print("\n" + "=" * 60)
    print("Testing: Invalid license handling")
    print("=" * 60)

    try:
        await fetch_license_details('INVALID-LICENSE-ID-12345')
        print("✗ Should have raised an exception")
        return False
    except Exception as e:
        print(f"✓ Correctly raised exception: {e}")
        return True


async def main():
    """Run all tests"""
    print("\n🧪 License Facade Service - API Tests\n")

    tests = [
        test_fetch_licenses(),
        test_fetch_license_details(),
        test_invalid_license()
    ]

    results = await asyncio.gather(*tests)

    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print("✗ Some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

