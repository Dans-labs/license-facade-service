#!/usr/bin/env python3
"""
Test script for License Facade Service caching functionality
"""
import asyncio
import sys
import os
from pathlib import Path

sys.path.insert(0, 'src')
os.environ['BASE_DIR'] = os.getcwd()

from license_facade_service.api.v1.licenses import (
    check_for_updates,
    download_all_licenses,
    get_cached_version,
    get_cached_licenses_list,
    get_cached_license_details,
    CACHE_DIR
)


async def test_cache_system():
    """Test the caching system"""
    print("=" * 60)
    print("License Cache System Test")
    print("=" * 60)
    print(f"Cache directory: {CACHE_DIR}")
    print()

    # Check current cache status
    print("1. Checking current cache status...")
    version_info = get_cached_version()
    if version_info:
        print(f"   ✓ Cached version: {version_info.get('licenseListVersion')}")
        print(f"   ✓ License count: {version_info.get('licenseCount')}")
        print(f"   ✓ Last updated: {version_info.get('lastUpdated')}")
    else:
        print("   ℹ No cached version found")
    print()

    # Check for updates
    print("2. Checking for updates from SPDX repository...")
    needs_update = await check_for_updates()
    if needs_update:
        print("   ℹ Updates available or no cache exists")
    else:
        print("   ✓ Cache is up to date")
    print()

    # Download if needed
    if needs_update:
        print("3. Downloading all licenses...")
        print("   This may take a few minutes...")
        success = await download_all_licenses()
        if success:
            print("   ✓ Download complete!")

            # Show updated version
            version_info = get_cached_version()
            if version_info:
                print(f"   ✓ New version: {version_info.get('licenseListVersion')}")
                print(f"   ✓ Total licenses: {version_info.get('licenseCount')}")
        else:
            print("   ✗ Download failed")
            return False
    else:
        print("3. Skipping download (cache is current)")
    print()

    # Verify cache
    print("4. Verifying cached data...")

    # Check licenses list
    licenses_list = get_cached_licenses_list()
    if licenses_list:
        count = len(licenses_list.get('licenses', []))
        print(f"   ✓ Licenses list cached: {count} licenses")
    else:
        print("   ✗ No licenses list in cache")
        return False

    # Check some specific license details
    test_licenses = ['MIT', 'Apache-2.0', 'GPL-3.0-or-later', 'BSD-3-Clause']
    cached_count = 0
    for license_id in test_licenses:
        details = get_cached_license_details(license_id)
        if details:
            cached_count += 1

    print(f"   ✓ Sample licenses cached: {cached_count}/{len(test_licenses)}")

    # Count all cached files
    cached_files = list(CACHE_DIR.glob("*.json"))
    license_files = [f for f in cached_files if f.name not in ["version.json", "licenses_list.json"]]
    print(f"   ✓ Total license detail files: {len(license_files)}")
    print()

    print("=" * 60)
    print("✓ Cache system test complete!")
    print("=" * 60)
    return True


async def main():
    try:
        success = await test_cache_system()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

