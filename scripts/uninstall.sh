#!/usr/bin/env bash
# Remove FoxESS local proxy UniFi NAT rules via API.
set -euo pipefail

UNIFI_URL="${UNIFI_URL:?Set UNIFI_URL}"
UNIFI_TOKEN="${UNIFI_TOKEN:?Set UNIFI_TOKEN}"
NAT_API="$UNIFI_URL/proxy/network/v2/api/site/default/nat"

echo "FoxESS local proxy — uninstall (UniFi API)"
echo ""

# Find and delete our rules
RULES=$(curl -sk "$NAT_API" -H "X-API-KEY: $UNIFI_TOKEN" 2>&1)
echo "$RULES" | python3 -c "
import json, sys
rules = json.load(sys.stdin)
foxess_rules = [r for r in rules if 'FoxESS' in r.get('description', '')]
if not foxess_rules:
    print('  No FoxESS NAT rules found.')
    sys.exit(0)
for r in foxess_rules:
    print(f'  {r[\"type\"]}: {r[\"description\"]} (id={r[\"_id\"]})')
" 2>/dev/null

# Delete each rule
for RULE_ID in $(echo "$RULES" | python3 -c "import json,sys; [print(r['_id']) for r in json.load(sys.stdin) if 'FoxESS' in r.get('description','')]" 2>/dev/null); do
  curl -sk -X DELETE "$NAT_API/$RULE_ID" \
    -H "X-API-KEY: $UNIFI_TOKEN" 2>&1 > /dev/null
  echo "  - Deleted $RULE_ID"
done

echo ""
echo "Done. Dongle will reconnect directly to FoxESS cloud."
