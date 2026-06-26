#!/bin/bash
# Test script for filter API

SOCK="/tmp/gvproxy-services.sock"
BASE_URL="http://localhost/services/filter"

echo "=== Testing Filter API ==="

echo -e "\n1. Get statistics:"
curl -s --unix-socket "$SOCK" "$BASE_URL/stats" | jq .

echo -e "\n2. Get all connections:"
curl -s --unix-socket "$SOCK" "$BASE_URL/connections" | jq .

echo -e "\n3. Get blocked connections:"
curl -s --unix-socket "$SOCK" "$BASE_URL/connections/blocked" | jq .

echo -e "\n4. Get DNS queries:"
curl -s --unix-socket "$SOCK" "$BASE_URL/dns/queries" | jq .

echo -e "\n5. Get allowlist:"
curl -s --unix-socket "$SOCK" "$BASE_URL/allowlist" | jq .

echo -e "\n6. Add domain to dynamic allowlist:"
curl -s --unix-socket "$SOCK" -X POST "$BASE_URL/allowlist" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | jq .

echo -e "\n7. Get updated allowlist:"
curl -s --unix-socket "$SOCK" "$BASE_URL/allowlist" | jq .

echo -e "\n8. Get blocklist:"
curl -s --unix-socket "$SOCK" "$BASE_URL/blocklist" | jq .

echo -e "\n9. Add to blocklist:"
curl -s --unix-socket "$SOCK" -X POST "$BASE_URL/blocklist" \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","ip":"10.0.0.5","port":443,"reason":"test block"}' | jq .

echo -e "\n10. Get updated blocklist:"
curl -s --unix-socket "$SOCK" "$BASE_URL/blocklist" | jq .

echo -e "\n11. Remove from allowlist:"
curl -s --unix-socket "$SOCK" -X DELETE "$BASE_URL/allowlist" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}' | jq .

echo -e "\n12. Remove from blocklist:"
curl -s --unix-socket "$SOCK" -X DELETE "$BASE_URL/blocklist" \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","ip":"10.0.0.5","port":443}' | jq .

echo -e "\n=== Test Complete ==="
