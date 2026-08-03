#!/usr/bin/env python3
"""
Quick test to verify URI appears in JSON responses
"""
import asyncio
import sys
import os
import json

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import get_license_json


async def test_uri_in_response():
    """Test that URI appears in the JSON response"""
    print("=" * 70)
    print("Testing URI in /licenses/{id}/json Response")
    print("=" * 70)
    print()

    license_id = "0BSD"

    print(f"Fetching license: {license_id}")
    print("-" * 70)

    try:
        result = await get_license_json(license_id)

        print(f"Response type: {type(result)}")
        print(f"Response keys: {list(result.keys())[:10]}...")  # Show first 10 keys
        print()

        # Check if URI is present
        if "uri" in result:
            print(f"✓ URI field is present!")
            print(f"  URI: {result['uri']}")
        else:
            print(f"✗ URI field is MISSING!")
            print(f"  Keys in response: {list(result.keys())}")
            return False

        # Check if URI is first
        first_key = list(result.keys())[0]
        if first_key == "uri":
            print(f"✓ URI is the first field in response")
        else:
            print(f"ℹ URI is not first (first key: {first_key})")

        print()
        print("Sample response structure:")
        print("-" * 70)
        sample = {
            "uri": result.get("uri"),
            "licenseId": result.get("licenseId"),
            "name": result.get("name"),
            "isDeprecatedLicenseId": result.get("isDeprecatedLicenseId"),
            "isOsiApproved": result.get("isOsiApproved")
        }
        print(json.dumps(sample, indent=2))

        return True

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    success = await test_uri_in_response()

    print()
    print("=" * 70)
    if success:
        print("✓ URI is correctly appearing in JSON responses!")
    else:
        print("✗ URI is not appearing in JSON responses")
    print("=" * 70)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())

