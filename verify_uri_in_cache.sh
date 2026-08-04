#!/bin/bash
# Verification script to ensure URIs are being saved to cache

echo "=========================================="
echo "URI Cache Verification Script"
echo "=========================================="
echo ""

# Step 1: Clear old cache
echo "Step 1: Clearing old cache files..."
cd /Users/akmi/dev/work/eden/license-facade-service
rm -rf resources/data/licenses/*.json
echo "✓ Old cache cleared"
echo ""

# Step 2: Trigger cache download via Python test
echo "Step 2: Downloading licenses with URIs..."
export BASE_DIR=$(pwd)
python3 test_cache_system.py
echo ""

# Step 3: Verify URI in cached files
echo "Step 3: Verifying URIs in cached files..."
echo ""

# Check MIT license file
if [ -f "resources/data/licenses/MIT.json" ]; then
    echo "Checking MIT.json:"
    URI=$(cat resources/data/licenses/MIT.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('uri', 'NOT FOUND'))")
    if [ "$URI" != "NOT FOUND" ]; then
        echo "✓ URI found in MIT.json: $URI"
    else
        echo "✗ URI NOT found in MIT.json"
        exit 1
    fi
else
    echo "✗ MIT.json not found in cache"
    exit 1
fi
echo ""

# Check 0BSD license file
if [ -f "resources/data/licenses/0BSD.json" ]; then
    echo "Checking 0BSD.json:"
    URI=$(cat resources/data/licenses/0BSD.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('uri', 'NOT FOUND'))")
    if [ "$URI" != "NOT FOUND" ]; then
        echo "✓ URI found in 0BSD.json: $URI"
    else
        echo "✗ URI NOT found in 0BSD.json"
        exit 1
    fi
else
    echo "✗ 0BSD.json not found in cache"
    exit 1
fi
echo ""

# Check licenses_list.json
if [ -f "resources/data/licenses/licenses_list.json" ]; then
    echo "Checking licenses_list.json:"
    FIRST_LICENSE_URI=$(cat resources/data/licenses/licenses_list.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['licenses'][0].get('uri', 'NOT FOUND'))")
    if [ "$FIRST_LICENSE_URI" != "NOT FOUND" ]; then
        echo "✓ URI found in first license of list: $FIRST_LICENSE_URI"
    else
        echo "✗ URI NOT found in licenses list"
        exit 1
    fi
else
    echo "✗ licenses_list.json not found in cache"
    exit 1
fi
echo ""

echo "=========================================="
echo "✓ All verifications passed!"
echo "URIs are correctly saved in cache files"
echo "=========================================="

