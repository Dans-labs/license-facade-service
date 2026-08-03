#!/usr/bin/env python3
"""
Test script for enhanced /licenses endpoint
Verifies all requested fields are returned in the correct order
"""
import asyncio
import sys
import os
import json

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import licenses


async def test_licenses_endpoint():
    """Test the enhanced /licenses endpoint"""
    print("=" * 70)
    print("Testing Enhanced /licenses Endpoint")
    print("=" * 70)
    print()

    try:
        result = await licenses()

        print(f"✓ License List Version: {result.get('licenseListVersion')}")
        licenses_list = result.get('licenses', [])
        print(f"✓ Total Licenses: {len(licenses_list)}")
        print()

        if len(licenses_list) > 0:
            # Check the first license
            first_license = licenses_list[0]

            print("First License Structure:")
            print("-" * 70)

            # Expected fields in order
            expected_fields = [
                "uri",
                "referenceNumber",
                "licenseId",
                "name",
                "detailsUrl",
                "reference",
                "isDeprecatedLicenseId",
                "seeAlso",
                "isOsiApproved",
                "licenseText",
                "standardLicenseTemplate",
                "licenseTextHtml",
                "crossRef"
            ]

            # Check each field
            actual_fields = list(first_license.keys())

            print("Expected Fields vs Actual Fields:")
            all_present = True
            for idx, field in enumerate(expected_fields):
                if field in first_license:
                    actual_pos = actual_fields.index(field) if field in actual_fields else -1
                    order_match = "✓" if actual_pos == idx else f"⚠ (position {actual_pos})"
                    value_preview = str(first_license[field])[:50]
                    print(f"  {idx+1:2d}. {field:30s} {order_match} | {value_preview}...")
                else:
                    print(f"  {idx+1:2d}. {field:30s} ✗ MISSING")
                    all_present = False

            print()

            # Show sample license
            print("Sample License (first 3 licenses with key fields):")
            print("-" * 70)
            for license_data in licenses_list[:3]:
                sample = {
                    "uri": license_data.get("uri", "")[:60] + "...",
                    "licenseId": license_data.get("licenseId"),
                    "name": license_data.get("name"),
                    "hasLicenseText": bool(license_data.get("licenseText")),
                    "hasTemplate": bool(license_data.get("standardLicenseTemplate")),
                    "hasHtml": bool(license_data.get("licenseTextHtml")),
                    "crossRefCount": len(license_data.get("crossRef", []))
                }
                print(json.dumps(sample, indent=2))

            print()

            if all_present:
                print("✓ All expected fields are present!")
                return True
            else:
                print("✗ Some fields are missing!")
                return False
        else:
            print("✗ No licenses returned!")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    success = await test_licenses_endpoint()

    print()
    print("=" * 70)
    if success:
        print("✓ Enhanced /licenses endpoint test PASSED!")
    else:
        print("✗ Enhanced /licenses endpoint test FAILED!")
    print("=" * 70)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())

