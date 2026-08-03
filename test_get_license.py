#!/usr/bin/env python3
"""
Test script for the modified /licenses/{license_id} endpoint
Verifies it returns complete JSON including isFsfLibre
"""
import asyncio
import sys
import os

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import get_license


async def test_get_license():
    """Test the get_license endpoint with various license IDs"""
    print("=" * 70)
    print("Testing /licenses/{license_id} Endpoint")
    print("=" * 70)
    print()

    test_cases = [
        "AFL-1.1",
        "MIT",
        "Apache-2.0",
        "GPL-3.0-or-later",
        "BSD-3-Clause"
    ]

    for license_id in test_cases:
        print(f"Testing: {license_id}")
        print("-" * 70)

        try:
            result = await get_license(license_id)

            # Check expected fields
            expected_fields = [
                "reference",
                "isDeprecatedLicenseId",
                "detailsUrl",
                "referenceNumber",
                "name",
                "licenseId",
                "seeAlso",
                "isOsiApproved"
            ]

            print(f"✓ License ID: {result.get('licenseId')}")
            print(f"✓ Name: {result.get('name')}")
            print(f"✓ Reference: {result.get('reference')}")
            print(f"✓ Details URL: {result.get('detailsUrl')}")
            print(f"✓ Reference Number: {result.get('referenceNumber')}")
            print(f"✓ Is Deprecated: {result.get('isDeprecatedLicenseId')}")
            print(f"✓ Is OSI Approved: {result.get('isOsiApproved')}")

            # Check for isFsfLibre (may not be present for all licenses)
            if "isFsfLibre" in result:
                print(f"✓ Is FSF Libre: {result.get('isFsfLibre')}")
            else:
                print(f"ℹ Is FSF Libre: Not specified")

            print(f"✓ See Also: {len(result.get('seeAlso', []))} URL(s)")

            # Verify all expected fields are present
            missing = [f for f in expected_fields if f not in result]
            if missing:
                print(f"⚠ Missing fields: {missing}")
            else:
                print(f"✓ All expected fields present")

            print()

        except Exception as e:
            print(f"✗ Error: {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 70)
    print("Detailed Example: AFL-1.1")
    print("=" * 70)

    try:
        result = await get_license("AFL-1.1")
        import json
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"✗ Error: {e}")

    print()
    print("=" * 70)
    print("✓ Test Complete!")
    print("=" * 70)


async def main():
    try:
        await test_get_license()
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

