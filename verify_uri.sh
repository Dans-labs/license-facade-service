#!/bin/bash
# Quick verification script for URI generation feature

echo "========================================"
echo "URI Generation Feature Verification"
echo "========================================"
echo ""

# Check if service is running
echo "1. Checking if service is running..."
if curl -s http://localhost:12104/health > /dev/null 2>&1; then
    echo "   ✓ Service is running"
else
    echo "   ✗ Service is not running. Start with: docker compose up -d"
    exit 1
fi
echo ""

# Test URI in /licenses/{id} endpoint
echo "2. Testing /licenses/MIT endpoint..."
RESPONSE=$(curl -s http://localhost:12104/licenses/MIT)
URI=$(echo "$RESPONSE" | jq -r '.uri // empty')

if [ -n "$URI" ]; then
    echo "   ✓ URI field present: $URI"
else
    echo "   ✗ URI field missing!"
    exit 1
fi
echo ""

# Test URI in /licenses/{id}/json endpoint
echo "3. Testing /licenses/Gutmann/json endpoint..."
RESPONSE=$(curl -s http://localhost:12104/licenses/Gutmann/json)
URI_JSON=$(echo "$RESPONSE" | jq -r '.uri // empty')

if [ -n "$URI_JSON" ]; then
    echo "   ✓ URI field present: $URI_JSON"
else
    echo "   ✗ URI field missing!"
    exit 1
fi
echo ""

# Test determinism (same license should give same URI)
echo "4. Testing determinism (MIT license)..."
URI1=$(curl -s http://localhost:12104/licenses/MIT | jq -r '.uri')
URI2=$(curl -s http://localhost:12104/licenses/MIT | jq -r '.uri')

if [ "$URI1" = "$URI2" ]; then
    echo "   ✓ URIs match (deterministic)"
    echo "     URI: $URI1"
else
    echo "   ✗ URIs don't match!"
    echo "     First:  $URI1"
    echo "     Second: $URI2"
    exit 1
fi
echo ""

# Show sample response
echo "5. Sample response for Gutmann license:"
echo "----------------------------------------"
curl -s http://localhost:12104/licenses/Gutmann/json | jq '{
  uri,
  licenseId,
  name,
  isOsiApproved,
  seeAlso
}'
echo ""

echo "========================================"
echo "✓ All verifications passed!"
echo "========================================"
echo ""
echo "URI generation is working correctly!"

