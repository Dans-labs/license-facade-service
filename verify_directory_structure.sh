#!/bin/bash
# Final verification that directory structure is correct

echo "=========================================="
echo "Directory Structure Verification"
echo "=========================================="
echo ""

cd /Users/akmi/dev/work/eden/license-facade-service

echo "1. Checking source code directory..."
if [ -d "src/license_facade_service/resources" ]; then
    echo "✗ FAILED: Bundled resources directory still exists in source code"
    exit 1
else
    echo "✓ PASSED: No bundled resources in source code"
fi
echo ""

echo "2. Checking runtime cache directory..."
if [ -d "resources/data/licenses" ]; then
    echo "✓ PASSED: Runtime cache directory exists at project root"
else
    echo "✗ FAILED: Runtime cache directory missing"
    exit 1
fi
echo ""

echo "3. Listing source code structure..."
echo "src/license_facade_service/ contains:"
ls src/license_facade_service/
echo ""

echo "4. Listing cache directory structure..."
echo "resources/data/ contains:"
ls resources/data/
echo ""

echo "=========================================="
echo "✓ Directory structure is correct!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Removed: /src/license_facade_service/resources/"
echo "  - Using:   /resources/data/licenses/"
echo ""

