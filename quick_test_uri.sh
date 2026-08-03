#!/bin/bash
# Quick test to verify URI appears in JSON response

echo "Testing URI in /licenses/{id}/json endpoint..."
echo ""

# Test with 0BSD license
echo "GET /licenses/0BSD/json"
echo "========================================"

RESPONSE=$(curl -s http://localhost:12104/licenses/0BSD/json)

# Check if URI exists
URI=$(echo "$RESPONSE" | jq -r '.uri // empty')

if [ -n "$URI" ]; then
    echo "✓ URI field is present"
    echo "  URI: $URI"
    echo ""

    # Check if it's the first field
    FIRST_KEY=$(echo "$RESPONSE" | jq -r 'keys[0]')
    if [ "$FIRST_KEY" = "uri" ]; then
        echo "✓ URI is the first field"
    else
        echo "ℹ First field is: $FIRST_KEY"
    fi
    echo ""

    # Show sample response
    echo "Sample response:"
    echo "$RESPONSE" | jq '{uri, licenseId, name, isOsiApproved, isDeprecatedLicenseId}' | head -10
    echo ""
    echo "✓ SUCCESS: URI is appearing in JSON response!"
else
    echo "✗ FAILED: URI field is missing!"
    echo ""
    echo "First 5 keys in response:"
    echo "$RESPONSE" | jq 'keys[:5]'
fi

